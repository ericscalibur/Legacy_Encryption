# Legacy Encryption — Tests

Two suites, one contract. The browser core (`legacy-core.js`, embedded verbatim
in `Legacy-offline.html`, `encrypt.html`, `decrypt.html`) and the SeedSigner
port (`seedsigner-port/legacy_encryption.py`) must both reproduce the published
vectors in `test-vectors.json` byte-for-byte.

```bash
npm test                 # JS suite (~320 checks, ~1 min)
npm run test:quick       # JS suite with 40 random round-trips
npm run test:all         # JS suite + Python suite
node test-legacy-encryption.js --iterations 2000   # more random round-trips
python3 seedsigner-port/test_cross_compat.py       # Python suite (needs `cryptography`)
```

## What the JS suite checks (`test-legacy-encryption.js`)

- The three HTML pages embed `legacy-core.js` byte-for-byte (`tools/sync-core.js --check`).
- `test-vectors.json` matches what the core produces (`tools/generate-vectors.js --check`).
- The embedded wordlist is the official BIP-39 English list (sha256-pinned).
- Every valid vector is reproduced exactly and decrypts; every invalid vector
  is rejected with the right error code, and malformed payloads are rejected
  before PBKDF2 runs.
- An independent decode of the vectors with Node's own `crypto` module.
- Key canonicalization, seed normalization, BIP-39 checksum enforcement,
  padding lengths 0–4, wrong/swapped/re-split keys, non-mnemonic plaintext.
- Random round-trips with random 12/24-word mnemonics and random printable-ASCII keys.

## What the Python suite checks (`seedsigner-port/test_cross_compat.py`)

- The same vectors (reproduce, decrypt, reject with matching codes).
- A from-the-spec decryptor that shares no code with the port.
- Python ↔ `legacy-core.js` in both directions, including matching error codes.

The on-device UI (`seedsigner-port/views/legacy_views.py`) is not covered by
these suites; rehearse encrypt → decrypt on hardware after every rebuild.
