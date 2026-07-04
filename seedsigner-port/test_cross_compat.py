"""
Cross-compatibility test suite for Legacy Encryption Python ↔ JavaScript.

Verifies that:
  1. Python can round-trip encrypt/decrypt its own output
  2. Python can decrypt ciphertext produced by the Node.js reference
  3. Node.js can decrypt ciphertext produced by Python

Run:  python test_cross_compat.py          (needs Node.js on PATH for cross tests)
      python -m pytest test_cross_compat.py -v
"""

import json
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Bootstrap: ensure we can import the module under test
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.dirname(__file__))
import legacy_encryption as le  # noqa: E402

# Provide a minimal wordlist so tests don't need english.txt
le._BIP39_WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent",
    "absorb", "abstract", "absurd", "abuse", "access", "accident",
]

# Canonical all-zero-entropy mnemonic (checksum word "about") — a VALID BIP-39
# phrase, required now that encrypt enforces the checksum. Uses only words that
# exist in the minimal wordlist above (indices 0 and 3, matching real BIP-39).
SEED_12 = "abandon " * 11 + "about"
BK = "benefactor-test-key"
BYK = "beneficiary-test-key"


# ===========================================================================
# 1. Python self-consistency
# ===========================================================================

class TestPythonRoundTrip:
    """encrypt → decrypt within Python must always recover the plaintext."""

    def test_basic_roundtrip(self):
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        dec = le.decrypt_seed_phrase(enc, BK, BYK)
        assert dec == SEED_12

    def test_wrong_benefactor_key_fails(self):
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        try:
            le.decrypt_seed_phrase(enc, "wrong", BYK)
            assert False, "Should have raised"
        except Exception:
            pass  # expected — GCM auth tag mismatch

    def test_wrong_beneficiary_key_fails(self):
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        try:
            le.decrypt_seed_phrase(enc, BK, "wrong")
            assert False, "Should have raised"
        except Exception:
            pass

    def test_multiple_roundtrips_unique_ciphertext(self):
        """Each encryption should produce different output (random salt/IV)."""
        results = set()
        for _ in range(5):
            results.add(le.encrypt_seed_phrase(SEED_12, BK, BYK))
        assert len(results) == 5, "Ciphertexts should differ due to random salt/IV"

    def test_low_level_encrypt_decrypt(self):
        """Test encryptData/decryptData directly."""
        data = le.encrypt_data("hello world", "password123")
        plain = le.decrypt_data(data, "password123")
        assert plain == "hello world"

    def test_empty_keys(self):
        enc = le.encrypt_seed_phrase(SEED_12, "", "")
        dec = le.decrypt_seed_phrase(enc, "", "")
        assert dec == SEED_12

    def test_unicode_keys(self):
        enc = le.encrypt_seed_phrase(SEED_12, "p@$$wörd🔑", "clé🗝️")
        dec = le.decrypt_seed_phrase(enc, "p@$$wörd🔑", "clé🗝️")
        assert dec == SEED_12

    def test_long_keys(self):
        long_bk = "a" * 1000
        long_byk = "b" * 1000
        enc = le.encrypt_seed_phrase(SEED_12, long_bk, long_byk)
        dec = le.decrypt_seed_phrase(enc, long_bk, long_byk)
        assert dec == SEED_12

    def test_validate_seed_phrase(self):
        assert le.validate_seed_phrase(SEED_12) is True
        assert le.validate_seed_phrase("abandon ability able") is False  # too short
        assert le.validate_seed_phrase("abandon " * 11 + "zzzzz") is False  # bad word
        # Valid words + valid count but WRONG checksum is now rejected (v1 bug).
        assert le.validate_seed_phrase("abandon " * 11 + "abandon") is False

    def test_v1_backward_decrypt(self):
        """A legacy v1 payload (no LE2. prefix, no separator) still decrypts."""
        enc = le.encrypt_data(SEED_12, BK + BYK)        # v1: keys concatenated, no sep
        padding_str = str(enc["paddingLength"]).zfill(2)
        combined = f'{enc["salt"]}.{enc["iv"]}.{enc["ciphertext"]}.{padding_str}'
        v1_payload = le.base64.b64encode(combined.encode()).decode().rstrip("=")
        assert not v1_payload.startswith("LE2.")
        assert le.decrypt_seed_phrase(v1_payload, BK, BYK) == SEED_12

    def test_v2_format_and_separator(self):
        """Encrypt emits an LE2. payload; the 0x1F separator disambiguates keys."""
        enc = le.encrypt_seed_phrase(SEED_12, "ab", "c")
        assert enc.startswith("LE2.")
        assert le.decrypt_seed_phrase(enc, "ab", "c") == SEED_12
        # "a"+"bc" must NOT decrypt what "ab"+"c" encrypted (the v1 collision).
        try:
            le.decrypt_seed_phrase(enc, "a", "bc")
            assert False, "Ambiguous key split wrongly decrypted"
        except Exception:
            pass

    def test_forged_iteration_count_rejected(self):
        """A forged header with a huge iteration count must be rejected BEFORE
        key derivation runs — otherwise a malicious QR is a DoS (the header is
        only authenticated by the GCM tag, which is checked after PBKDF2)."""
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        body = bytearray(le._b64url_decode(enc[len(le.V2_PREFIX):]))
        body[2:6] = (0xFFFFFFFF).to_bytes(4, "big")
        forged = le.V2_PREFIX + le._b64url_encode(bytes(body))
        t0 = time.time()
        try:
            le.decrypt_seed_phrase(forged, BK, BYK)
            assert False, "Forged iteration count wrongly accepted"
        except ValueError as e:
            assert "iteration" in str(e).lower()
        # Must fail fast (no PBKDF2 with 4 billion iterations).
        assert time.time() - t0 < 1.0, "Rejection happened after key derivation"
        # Below the minimum bound must also be rejected (downgrade forgery).
        body[2:6] = (1).to_bytes(4, "big")
        forged = le.V2_PREFIX + le._b64url_encode(bytes(body))
        try:
            le.decrypt_seed_phrase(forged, BK, BYK)
            assert False, "Downgraded iteration count wrongly accepted"
        except ValueError as e:
            assert "iteration" in str(e).lower()

    def test_qr_helpers(self):
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        qr = le.encrypted_to_qr_data(enc)
        back = le.qr_data_to_encrypted(qr)
        dec = le.decrypt_seed_phrase(back, BK, BYK)
        assert dec == SEED_12


# ===========================================================================
# 2. Cross-compatibility: Python encrypts → Node decrypts
# ===========================================================================

# Node.js script that decrypts a Legacy payload (v2, with v1 fallback)
NODE_DECRYPT_SCRIPT = r"""
const crypto = require('crypto');
const { webcrypto } = require('crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const input = JSON.parse(process.argv[2]);
const encrypted = input.encrypted;
const bk = input.benefactorKey;
const byk = input.beneficiaryKey;
const SEP = "\u001f";

async function deriveKey(password, salt, iterations) {
    const enc = new TextEncoder();
    const km = await globalThis.crypto.subtle.importKey("raw", enc.encode(password), {name:"PBKDF2"}, false, ["deriveKey"]);
    return globalThis.crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations,hash:"SHA-256"}, km, {name:"AES-GCM",length:256}, true, ["encrypt","decrypt"]);
}
async function decryptV2(body, bk, byk) {
    const iterations = new DataView(body.buffer, body.byteOffset).getUint32(2, false);
    const padLen = body[6];
    const salt = body.slice(7,23), iv = body.slice(23,35), header = body.slice(0,35), ct = body.slice(35);
    const key = await deriveKey(bk + SEP + byk, salt, iterations);
    const dec = new Uint8Array(await globalThis.crypto.subtle.decrypt({name:"AES-GCM",iv,additionalData:header}, key, ct));
    const out = padLen > 0 ? dec.slice(0, dec.length - padLen) : dec;
    return new TextDecoder().decode(out);
}
async function decryptV1(payload, bk, byk) {
    const ck = bk + byk;
    let padded = payload;
    while (padded.length % 4 !== 0) padded += "=";
    const decoded = Buffer.from(padded, 'base64').toString();
    const parts = decoded.split(".");
    if (parts.length !== 4) throw new Error("bad format");
    const toU8 = s => new Uint8Array(Buffer.from(s, 'base64'));
    const salt = toU8(parts[0]), iv = toU8(parts[1]), ct = toU8(parts[2]), pl = parseInt(parts[3], 10);
    const key = await deriveKey(ck, salt, 600000);
    const dec = await globalThis.crypto.subtle.decrypt({name:"AES-GCM",iv}, key, ct);
    let text = new TextDecoder().decode(dec);
    if (pl > 0 && pl <= text.length) text = text.slice(0, -pl);
    return text;
}
async function decrypt(payload, bk, byk) {
    const m = payload.match(/^LE(\d+)\./);
    if (m) {
        const body = new Uint8Array(Buffer.from(payload.slice(m[0].length), 'base64url'));
        if (body[0] === 0x02) return decryptV2(body, bk, byk);
        throw new Error("unsupported version " + body[0]);
    }
    return decryptV1(payload, bk, byk);
}

decrypt(encrypted, bk, byk)
    .then(r => { console.log(JSON.stringify({ok: true, result: r})); })
    .catch(e => { console.log(JSON.stringify({ok: false, error: e.message})); process.exit(1); });
"""

# Node.js script that encrypts a seed phrase (Protocol v2)
NODE_ENCRYPT_SCRIPT = r"""
const crypto = require('crypto');
const { webcrypto } = require('crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const input = JSON.parse(process.argv[2]);
const seed = input.seedPhrase;
const bk = input.benefactorKey;
const byk = input.beneficiaryKey;
const SEP = "\u001f";

async function deriveKey(password, salt, iterations) {
    const enc = new TextEncoder();
    const km = await globalThis.crypto.subtle.importKey("raw", enc.encode(password), {name:"PBKDF2"}, false, ["deriveKey"]);
    return globalThis.crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations,hash:"SHA-256"}, km, {name:"AES-GCM",length:256}, true, ["encrypt","decrypt"]);
}
async function encryptSeedPhrase(seed, bk, byk) {
    const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const padLen = Math.floor(Math.random() * 5);
    const iterations = 600000;
    const header = new Uint8Array(35);
    header[0] = 0x02; header[1] = 0x01;
    new DataView(header.buffer).setUint32(2, iterations, false);
    header[6] = padLen; header.set(salt, 7); header.set(iv, 23);
    const seedBytes = new TextEncoder().encode(seed);
    const pt = new Uint8Array(seedBytes.length + padLen);
    pt.set(seedBytes, 0);
    if (padLen > 0) pt.set(globalThis.crypto.getRandomValues(new Uint8Array(padLen)), seedBytes.length);
    const key = await deriveKey(bk + SEP + byk, salt, iterations);
    const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:header}, key, pt));
    const body = new Uint8Array(35 + ct.length);
    body.set(header, 0); body.set(ct, 35);
    return "LE2." + Buffer.from(body).toString('base64url');
}

encryptSeedPhrase(seed, bk, byk)
    .then(r => { console.log(JSON.stringify({ok: true, result: r})); })
    .catch(e => { console.log(JSON.stringify({ok: false, error: e.message})); process.exit(1); });
"""


def _has_node() -> bool:
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _run_node(script: str, data: dict, timeout: int = 120) -> dict:
    """Run an inline Node.js script with JSON input, return parsed output."""
    # Write script to a temp file so process.argv[2] works correctly
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cjs", delete=False) as f:
        f.write(script)
        script_path = f.name
    try:
        result = subprocess.run(
            ["node", script_path, json.dumps(data)],
            capture_output=True, text=True, timeout=timeout,
        )
    finally:
        os.unlink(script_path)
    if result.returncode != 0:
        raise RuntimeError(f"Node failed: {result.stderr}")
    return json.loads(result.stdout.strip())


class TestPythonToNode:
    """Python encrypts, Node.js decrypts."""

    def test_python_encrypt_node_decrypt(self):
        if not _has_node():
            print("SKIP: node not found")
            return

        encrypted = le.encrypt_seed_phrase(SEED_12, BK, BYK)

        result = _run_node(NODE_DECRYPT_SCRIPT, {
            "encrypted": encrypted,
            "benefactorKey": BK,
            "beneficiaryKey": BYK,
        })

        assert result["ok"] is True, f"Node decryption failed: {result}"
        assert result["result"] == SEED_12


class TestNodeToPython:
    """Node.js encrypts, Python decrypts."""

    def test_node_encrypt_python_decrypt(self):
        if not _has_node():
            print("SKIP: node not found")
            return

        result = _run_node(NODE_ENCRYPT_SCRIPT, {
            "seedPhrase": SEED_12,
            "benefactorKey": BK,
            "beneficiaryKey": BYK,
        })
        assert result["ok"] is True, f"Node encryption failed: {result}"

        encrypted = result["result"]
        decrypted = le.decrypt_seed_phrase(encrypted, BK, BYK)
        assert decrypted == SEED_12


# ===========================================================================
# CLI runner
# ===========================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Legacy Encryption — Cross-Compatibility Tests")
    print("=" * 60)

    has_node = _has_node()
    if not has_node:
        print("⚠  Node.js not found — cross-compat tests will be skipped\n")

    passed = 0
    failed = 0
    skipped = 0

    for cls in [TestPythonRoundTrip, TestPythonToNode, TestNodeToPython]:
        print(f"\n--- {cls.__name__} ---")
        for name in sorted(dir(cls)):
            if not name.startswith("test_"):
                continue
            method = getattr(cls(), name)
            try:
                t0 = time.time()
                method()
                elapsed = time.time() - t0
                print(f"  ✓ {name} ({elapsed:.2f}s)")
                passed += 1
            except Exception as e:
                print(f"  ✗ {name}: {e}")
                failed += 1

    print(f"\n{'=' * 60}")
    print(f"Passed: {passed}  Failed: {failed}")
    if failed:
        sys.exit(1)
