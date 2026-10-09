"""
Test suite for the Legacy Encryption Python port, and Python <-> JavaScript
cross-compatibility.

Verifies that:
  1. Python reproduces every published test vector (test-vectors.json)
     byte-for-byte, decrypts each one, and rejects every invalid vector with
     the expected error code.
  2. An independent, from-the-spec decryptor (no code shared with the port)
     decrypts the vectors — so the spec and the code agree.
  3. Python round-trips its own output, and canonicalizes keys and seeds the
     same way legacy-core.js does.
  4. Payloads cross between Python and the real legacy-core.js (the exact code
     embedded in Legacy-offline.html) in both directions.

Run:  python test_cross_compat.py          (needs Node.js on PATH for cross tests)
      python -m pytest test_cross_compat.py -v
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import legacy_encryption as le  # noqa: E402

# Use the real 2048-word list from the repo root (sha256-checked) so random
# mnemonics exercise the full wordlist.
_WORDLIST_PATH = os.path.join(ROOT, "english.txt")
with open(_WORDLIST_PATH, "rb") as _f:
    _raw = _f.read()
assert hashlib.sha256(_raw).hexdigest() == (
    "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
), "english.txt is not the official BIP-39 English wordlist"
le._BIP39_WORDLIST = [w.strip() for w in _raw.decode().splitlines() if w.strip()]

with open(os.path.join(ROOT, "test-vectors.json")) as _f:
    VECTORS = json.load(_f)

CORE_JS = os.path.join(ROOT, "legacy-core.js")

SEED_12 = "abandon " * 11 + "about"
BK = "benefactor-test-key"
BYK = "beneficiary-test-key"


def _random_mnemonic(words: int) -> str:
    """A random valid BIP-39 mnemonic (test helper)."""
    ent_bits = words * 11 * 32 // 33
    entropy = os.urandom(ent_bits // 8)
    cs = hashlib.sha256(entropy).digest()
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(ent_bits)
    bits += bin(int.from_bytes(cs, "big"))[2:].zfill(256)[: ent_bits // 32]
    wl = le.get_wordlist()
    return " ".join(wl[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def _expect_code(code, fn, *args):
    try:
        fn(*args)
    except le.LegacyError as e:
        assert e.code == code, f"expected {code}, got {e.code}: {e}"
        return
    raise AssertionError(f"expected LegacyError({code}), nothing raised")


# ===========================================================================
# 1. Published test vectors
# ===========================================================================

class TestVectors:

    def test_reproduce_valid_vectors(self):
        for v in VECTORS["valid"]:
            payload = le.encrypt_with_params(
                v["seed"], v["benefactorKey"], v["beneficiaryKey"],
                salt=bytes.fromhex(v["salt"]),
                iv=bytes.fromhex(v["iv"]),
                pad_bytes=bytes.fromhex(v["padBytes"]),
            )
            assert payload == v["payload"], f'{v["name"]}: payload mismatch'

    def test_decrypt_valid_vectors(self):
        for v in VECTORS["valid"]:
            got = le.decrypt_seed_phrase(v["payload"], v["benefactorKey"], v["beneficiaryKey"])
            assert got == v["canonicalSeed"], v["name"]
            if "canonicalBenefactorKey" in v:
                assert le.canonicalize_key(v["benefactorKey"]) == v["canonicalBenefactorKey"]
                assert le.canonicalize_key(v["beneficiaryKey"]) == v["canonicalBeneficiaryKey"]
                got = le.decrypt_seed_phrase(
                    v["payload"], v["canonicalBenefactorKey"], v["canonicalBeneficiaryKey"])
                assert got == v["canonicalSeed"], v["name"]

    def test_reject_invalid_vectors(self):
        for v in VECTORS["invalid"]:
            t0 = time.time()
            try:
                le.decrypt_seed_phrase(v["payload"], v["benefactorKey"], v["beneficiaryKey"])
            except le.LegacyError as e:
                assert e.code == v["code"], f'{v["name"]}: expected {v["code"]}, got {e.code}'
            else:
                raise AssertionError(f'{v["name"]}: was accepted')
            if v["code"] in ("BAD_PAYLOAD", "BAD_KEY"):
                # Rejected before PBKDF2 (no 600k-iteration delay).
                assert time.time() - t0 < 0.1, f'{v["name"]}: rejected only after key derivation'


# ===========================================================================
# 2. Independent decryptor written from PROTOCOL-SPEC.md alone
# ===========================================================================

def _spec_decrypt(payload: str, benefactor: str, beneficiary: str) -> str:
    """Deliberately shares no code with legacy_encryption.py. Inputs must
    already be canonical (the vectors' canonical keys)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    body = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    salt, iv, ct = body[:16], body[16:28], body[28:]
    password = benefactor.encode() + b"\x1f" + beneficiary.encode()
    key = hashlib.pbkdf2_hmac("sha256", password, salt, 600_000, 32)
    plain = AESGCM(key).decrypt(iv, ct, None)
    return plain[1:len(plain) - plain[0]].decode()


class TestSpecConformance:

    def test_independent_decryptor_reads_vectors(self):
        for v in VECTORS["valid"]:
            bk = v.get("canonicalBenefactorKey", v["benefactorKey"])
            byk = v.get("canonicalBeneficiaryKey", v["beneficiaryKey"])
            assert _spec_decrypt(v["payload"], bk, byk) == v["canonicalSeed"], v["name"]


# ===========================================================================
# 3. Python behaviour
# ===========================================================================

class TestPython:

    def test_basic_roundtrip(self):
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        assert le.decrypt_seed_phrase(enc, BK, BYK) == SEED_12

    def test_random_mnemonics_roundtrip(self):
        for words in (12, 24, 12, 24):
            seed = _random_mnemonic(words)
            enc = le.encrypt_seed_phrase(seed, BK, BYK)
            assert le.decrypt_seed_phrase(enc, BK, BYK) == seed

    def test_wrong_keys_fail(self):
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        _expect_code("WRONG_KEYS", le.decrypt_seed_phrase, enc, "wrong", BYK)
        _expect_code("WRONG_KEYS", le.decrypt_seed_phrase, enc, BK, "wrong")
        _expect_code("WRONG_KEYS", le.decrypt_seed_phrase, enc, BYK, BK)

    def test_key_boundary_is_unambiguous(self):
        enc = le.encrypt_seed_phrase(SEED_12, "ab", "c")
        assert le.decrypt_seed_phrase(enc, "ab", "c") == SEED_12
        _expect_code("WRONG_KEYS", le.decrypt_seed_phrase, enc, "a", "bc")

    def test_unique_ciphertexts(self):
        results = {le.encrypt_seed_phrase(SEED_12, BK, BYK) for _ in range(4)}
        assert len(results) == 4, "random salt/iv must make every payload unique"
        assert len({r[:4] for r in results}) == 4, "payloads must not share a recognizable start"

    def test_key_canonicalization(self):
        c = le.canonicalize_key
        assert c("  a   b  ") == "a b"
        assert c("a\tb\nc\r\nd") == "a b c d"
        assert c("a\u00a0b") == "a b"
        assert c("\u2018x\u2019 \u201cy\u201d") == "'x' \"y\""
        assert c("CaSe") == "CaSe"
        printable = "".join(chr(i) for i in range(0x21, 0x7F))
        assert c(printable) == printable
        for bad in ("", "   ", "\n\t", "caf\u00e9", "key\U0001F511", "a\x1fb", "a\x00b", "a\x7fb", "\u2014"):
            _expect_code("BAD_KEY", c, bad)

    def test_canonicalized_keys_decrypt(self):
        enc = le.encrypt_seed_phrase(SEED_12, " It\u2019s  mine ", "pass\u00a0word\n")
        assert le.decrypt_seed_phrase(enc, "It's mine", "pass word") == SEED_12

    def test_seed_normalization_and_validation(self):
        messy = "  ABANDON abandon\tabandon abandon abandon abandon\nabandon abandon abandon abandon abandon About  "
        assert le.normalize_seed_phrase(messy) == SEED_12
        enc = le.encrypt_seed_phrase(messy, BK, BYK)
        assert le.decrypt_seed_phrase(enc, BK, BYK) == SEED_12
        assert le.validate_seed_phrase(SEED_12)
        assert not le.validate_seed_phrase("abandon ability able")
        assert not le.validate_seed_phrase("abandon " * 11 + "zzzzz")
        assert not le.validate_seed_phrase("abandon " * 11 + "abandon")   # bad checksum
        assert not le.validate_seed_phrase(" ".join(["abandon"] * 17 + ["agent"]))  # 18 words
        _expect_code("BAD_SEED", le.encrypt_seed_phrase, "abandon " * 11 + "abandon", BK, BYK)

    def test_rejects_empty_keys_on_encrypt(self):
        _expect_code("BAD_KEY", le.encrypt_seed_phrase, SEED_12, "", BYK)
        _expect_code("BAD_KEY", le.encrypt_seed_phrase, SEED_12, BK, "  ")

    def test_qr_helpers(self):
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        back = le.qr_data_to_encrypted("  " + le.encrypted_to_qr_data(enc) + "\n")
        assert le.decrypt_seed_phrase(back, BK, BYK) == SEED_12


# ===========================================================================
# 4. Cross-compatibility with the real legacy-core.js
# ===========================================================================

NODE_DRIVER = r"""
const C = require(process.argv[2]);
const req = JSON.parse(process.argv[3]);
(async () => {
    try {
        let result;
        if (req.op === "encrypt") result = await C.encryptSeedPhrase(req.seed, req.bk, req.byk);
        else if (req.op === "decrypt") result = await C.decryptSeedPhrase(req.payload, req.bk, req.byk);
        else if (req.op === "estimate") result = req.keys.map((k) => C.estimateKeyBits(k));
        console.log(JSON.stringify({ ok: true, result }));
    } catch (e) {
        console.log(JSON.stringify({ ok: false, code: e.code || null, error: e.message }));
    }
})();
"""


def _has_node() -> bool:
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _node(req: dict) -> dict:
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".cjs", delete=False) as f:
        f.write(NODE_DRIVER)
        path = f.name
    try:
        out = subprocess.run(["node", path, CORE_JS, json.dumps(req)],
                             capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(path)
    if out.returncode != 0:
        raise RuntimeError(f"node failed: {out.stderr}")
    return json.loads(out.stdout.strip())


class TestCrossCompat:

    def test_python_encrypt_js_decrypt(self):
        if not _has_node():
            print("SKIP: node not found")
            return
        for seed in (SEED_12, _random_mnemonic(24)):
            enc = le.encrypt_seed_phrase(seed, " It\u2019s  mine ", BYK)
            r = _node({"op": "decrypt", "payload": enc, "bk": "It's mine", "byk": BYK})
            assert r["ok"], r
            assert r["result"] == seed

    def test_js_encrypt_python_decrypt(self):
        if not _has_node():
            print("SKIP: node not found")
            return
        for seed in (SEED_12, _random_mnemonic(24)):
            r = _node({"op": "encrypt", "seed": seed, "bk": BK, "byk": "pass\u00a0word"})
            assert r["ok"], r
            assert le.decrypt_seed_phrase(r["result"], BK, "pass word") == seed

    def test_same_errors_for_bad_input(self):
        if not _has_node():
            print("SKIP: node not found")
            return
        enc = le.encrypt_seed_phrase(SEED_12, BK, BYK)
        r = _node({"op": "decrypt", "payload": enc, "bk": BYK, "byk": BK})
        assert not r["ok"] and r["code"] == "WRONG_KEYS"
        r = _node({"op": "encrypt", "seed": SEED_12, "bk": "caf\u00e9", "byk": BYK})
        assert not r["ok"] and r["code"] == "BAD_KEY"

    def test_key_strength_matches_js(self):
        keys = ["cat", "12345678", "aardvark", "password", "!@#$%^&*",
                "rusty-hollow-lantern", "correct horse battery staple",
                "aaaaaaaa", "Tr0ub4dor&3", "a", "AB cd-12"]
        # Python's own expectations (threshold 40).
        for k in keys:
            assert le.key_is_weak(k) == (le.estimate_key_bits(k) < le.WEAK_KEY_BITS)
        if not _has_node():
            print("SKIP: node not found")
            return
        r = _node({"op": "estimate", "keys": keys})
        assert r["ok"], r
        for k, js_bits in zip(keys, r["result"]):
            py_bits = le.estimate_key_bits(k)
            assert abs(py_bits - js_bits) < 1e-9, f"{k}: py {py_bits} vs js {js_bits}"
            # and the weak decision agrees
            assert (py_bits < le.WEAK_KEY_BITS) == (js_bits < le.WEAK_KEY_BITS), k


# ===========================================================================
# CLI runner
# ===========================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Legacy Encryption — Python port & cross-compatibility tests")
    print("=" * 60)

    if not _has_node():
        print("⚠  Node.js not found — cross-compat tests will be skipped\n")

    passed = failed = 0
    for cls in [TestVectors, TestSpecConformance, TestPython, TestCrossCompat]:
        print(f"\n--- {cls.__name__} ---")
        for name in sorted(dir(cls)):
            if not name.startswith("test_"):
                continue
            method = getattr(cls(), name)
            try:
                t0 = time.time()
                method()
                print(f"  \u2713 {name} ({time.time() - t0:.2f}s)")
                passed += 1
            except Exception as e:
                print(f"  \u2717 {name}: {e!r}")
                failed += 1

    print(f"\n{'=' * 60}")
    print(f"Passed: {passed}  Failed: {failed}")
    if failed:
        sys.exit(1)
