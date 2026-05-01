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

SEED_12 = "abandon ability able about above absent absorb abstract absurd abuse access accident"
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
        assert le.validate_seed_phrase("abandon ability able about above absent absorb abstract absurd abuse access zzzzz") is False  # bad word

    def test_qr_helpers(self):
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        qr = le.encrypted_to_qr_data(enc)
        back = le.qr_data_to_encrypted(qr)
        dec = le.decrypt_seed_phrase(back, BK, BYK)
        assert dec == SEED_12


# ===========================================================================
# 2. Cross-compatibility: Python encrypts → Node decrypts
# ===========================================================================

# Node.js script that decrypts a Legacy-format ciphertext
NODE_DECRYPT_SCRIPT = r"""
const crypto = require('crypto');
const { webcrypto } = require('crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const input = JSON.parse(process.argv[2]);
const encrypted = input.encrypted;
const bk = input.benefactorKey;
const byk = input.beneficiaryKey;

class LE {
    static strToArrayBuffer(str) {
        const buf = new ArrayBuffer(str.length);
        const v = new Uint8Array(buf);
        for (let i = 0; i < str.length; i++) v[i] = str.charCodeAt(i);
        return buf;
    }
    static async deriveKey(password, salt) {
        const enc = new TextEncoder();
        const km = await globalThis.crypto.subtle.importKey("raw", enc.encode(password), {name:"PBKDF2"}, false, ["deriveKey"]);
        return globalThis.crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:600000,hash:"SHA-256"}, km, {name:"AES-GCM",length:256}, true, ["encrypt","decrypt"]);
    }
    static async decryptSeedPhrase(enc, bk, byk) {
        const ck = bk + byk;
        let padded = enc;
        while (padded.length % 4 !== 0) padded += "=";
        const decoded = Buffer.from(padded, 'base64').toString();
        const parts = decoded.split(".");
        if (parts.length !== 4) throw new Error("bad format");
        const salt = new Uint8Array(LE.strToArrayBuffer(Buffer.from(parts[0],'base64').toString('binary')));
        const iv   = new Uint8Array(LE.strToArrayBuffer(Buffer.from(parts[1],'base64').toString('binary')));
        const ct   = new Uint8Array(LE.strToArrayBuffer(Buffer.from(parts[2],'base64').toString('binary')));
        const pl   = parseInt(parts[3], 10);
        const key  = await LE.deriveKey(ck, salt);
        const dec  = await globalThis.crypto.subtle.decrypt({name:"AES-GCM",iv}, key, ct);
        let text = new TextDecoder().decode(dec);
        if (pl > 0 && pl <= text.length) text = text.slice(0, -pl);
        return text;
    }
}

LE.decryptSeedPhrase(encrypted, bk, byk)
    .then(r => { console.log(JSON.stringify({ok: true, result: r})); })
    .catch(e => { console.log(JSON.stringify({ok: false, error: e.message})); process.exit(1); });
"""

# Node.js script that encrypts a seed phrase
NODE_ENCRYPT_SCRIPT = r"""
const crypto = require('crypto');
const { webcrypto } = require('crypto');
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const input = JSON.parse(process.argv[2]);
const seed = input.seedPhrase;
const bk = input.benefactorKey;
const byk = input.beneficiaryKey;

class LE {
    static strToArrayBuffer(str) {
        const buf = new ArrayBuffer(str.length);
        const v = new Uint8Array(buf);
        for (let i = 0; i < str.length; i++) v[i] = str.charCodeAt(i);
        return buf;
    }
    static arrayBufferToStr(buf) {
        return String.fromCharCode.apply(null, new Uint8Array(buf));
    }
    static async deriveKey(password, salt) {
        const enc = new TextEncoder();
        const km = await globalThis.crypto.subtle.importKey("raw", enc.encode(password), {name:"PBKDF2"}, false, ["deriveKey"]);
        return globalThis.crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:600000,hash:"SHA-256"}, km, {name:"AES-GCM",length:256}, true, ["encrypt","decrypt"]);
    }
    static async encryptSeedPhrase(seed, bk, byk) {
        const ck = bk + byk;
        const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
        const key = await LE.deriveKey(ck, salt);
        const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
        const pl = Math.floor(Math.random() * 5);
        let padded = seed;
        for (let i = 0; i < pl; i++) padded += String.fromCharCode(Math.floor(Math.random()*256));
        const enc = new TextEncoder();
        const ct = await globalThis.crypto.subtle.encrypt({name:"AES-GCM",iv}, key, enc.encode(padded));
        const saltB64 = Buffer.from(LE.arrayBufferToStr(salt),'binary').toString('base64');
        const ivB64   = Buffer.from(LE.arrayBufferToStr(iv),'binary').toString('base64');
        const ctB64   = Buffer.from(LE.arrayBufferToStr(ct),'binary').toString('base64');
        const ps = String(pl).padStart(2,"0");
        const combined = saltB64+"."+ivB64+"."+ctB64+"."+ps;
        let b64 = Buffer.from(combined).toString('base64');
        b64 = b64.replace(/=+$/, "");
        return b64;
    }
}

LE.encryptSeedPhrase(seed, bk, byk)
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
