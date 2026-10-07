# Legacy Encryption — Protocol Specification

**Status:** FINAL. This is the one and only Legacy Encryption format. It
replaces the earlier "v1" and "v2" (`LE2.`-prefixed) drafts, neither of which
was ever used for real funds; implementations no longer accept either.

This document is complete: an engineer with any standard cryptography library
can decrypt a Legacy payload from this page alone, without any Legacy code.
The published test vectors (`test-vectors.json`) prove an implementation is
byte-for-byte correct.

**Implementations** (all must pass `test-vectors.json`):

| Where | File |
|---|---|
| Browser (canonical) | `legacy-core.js`, embedded verbatim in `Legacy-offline.html`, `encrypt.html`, `decrypt.html` (`node tools/sync-core.js` copies it; the test suite fails on drift) |
| SeedSigner device | `seedsigner-port/legacy_encryption.py` |

---

## 1. Overview

```
password   = canon(benefactorKey) || 0x1F || canon(beneficiaryKey)
key        = PBKDF2-HMAC-SHA256(password, salt, 600000 iterations, dkLen = 32)
plaintext  = padLen(1) || seed || padBytes(padLen)                    padLen 0..4
ciphertext = AES-256-GCM-Encrypt(key, iv, plaintext), no AAD          (includes 16-byte tag)
payload    = base64url(salt(16) || iv(12) || ciphertext)              (no '=' padding)
```

Both keys are required, in order. This is **one password split into two
parts**, not threshold cryptography or secret sharing.

**No marker, by design.** Every visible byte of a payload is random (salt,
IV, ciphertext). There is no prefix, version number or fixed header, so a
payload found on its own cannot be identified as Legacy-generated. The
holder must be told what it is. The consequence is that all parameters are
fixed by this specification: none are stored, and none can change without
creating a different, incompatible format.

## 2. Inputs

### 2.1 Seed phrase

A BIP-39 mnemonic of **12 or 24** English words with a valid BIP-39 checksum.
Encryptors normalize the input before validating: split on ASCII whitespace
(space, tab, CR, LF), drop empty items, lowercase ASCII letters, and join with
single spaces (0x20). The **canonical seed** — the exact bytes encrypted — is
that ASCII string, with no leading or trailing whitespace. Encryptors MUST
refuse anything else (wrong word count, unknown word, bad checksum).

### 2.2 Key canonicalization — `canon()`

Applied identically to each key on **both** encrypt and decrypt. The aim is
that an heir typing the key years later, on a different device, from a paper
copy, gets the same bytes.

1. Replace U+2018 and U+2019 (curly single quotes) with `'` (0x27); U+201C
   and U+201D (curly double quotes) with `"` (0x22); U+00A0 (no-break
   space), U+0009 (tab), U+000A (LF) and U+000D (CR) with a space (0x20).
2. Replace every run of spaces with a single space; remove a leading and a
   trailing space.
3. The result MUST be non-empty and consist only of printable ASCII,
   0x20–0x7E. Otherwise the key is **rejected** (never silently altered
   further). This is exactly the set a standard US keyboard, and the
   SeedSigner on-screen keyboard, can type.

Keys are case-sensitive. Because a canonical key never contains 0x1F, the
separator between the two keys is unambiguous: `"ab" + "c"` and `"a" + "bc"`
derive different keys.

## 3. Binary layout

```
offset  size  field
0       16    salt        (random)
16      12    iv          (random GCM nonce)
28      ..    ciphertext  (plaintext length + 16-byte GCM tag at the end)
```

Plaintext (encrypted, so authenticated by the tag):

```
offset  size     field
0       1        padLen    = 0..4
1       ..       seed      (canonical mnemonic, ASCII, 47..215 bytes)
..      padLen   padBytes  (random)
```

Encryptors draw salt, IV, `padLen` (uniform 0–4) and `padBytes` from a
cryptographically secure RNG.

The decoded payload is therefore 92 to 264 bytes: 16 + 12 + 16 + 1, plus
47 bytes (12 three-letter words) up to 215 + 4 bytes (24 eight-letter words
plus maximum padding).

## 4. Payload string

```
payload = base64url(salt || iv || ciphertext)
```

base64url per RFC 4648 §5 (`-` and `_` instead of `+` and `/`), with `=`
padding removed.

## 5. Decryption (normative)

Before running PBKDF2, a decryptor MUST reject anything that cannot be a
payload:

1. Trim surrounding ASCII whitespace. The remainder must be non-empty, use
   only `A–Z a–z 0–9 - _`, and its length mod 4 must not be 1.
2. The decoded body must be 92 to 264 bytes.

(With no marker, these checks catch garbage, truncation and things like
SeedQRs early; any other string of plausible length is only rejected after
PBKDF2, by the tag.)

Then: canonicalize both keys (§2.2), derive the key, and AES-256-GCM decrypt
with no AAD. A tag failure means a wrong key, wrong key order, a damaged
payload, or something that is not a Legacy payload; it never yields garbage.
Read `padLen` from the first plaintext byte (must be ≤ 4), and drop that byte
and the last `padLen` bytes. The result MUST decode as UTF-8 and MUST be a
canonical, checksum-valid 12- or 24-word mnemonic (§2.1); otherwise report
corruption.

Encryptors MUST self-check: parse their own output with the decryption rules
above and decrypt it with the derived key, and only release the payload if it
yields exactly the canonical seed.

## 6. Error codes

Both implementations report the same codes, which the test vectors check:

| Code | Meaning |
|---|---|
| `BAD_KEY` | A key is empty or contains a character outside printable ASCII |
| `BAD_SEED` | Not a valid 12/24-word BIP-39 mnemonic (encrypt only) |
| `BAD_PAYLOAD` | Cannot be a payload (alphabet, length) |
| `WRONG_KEYS` | GCM authentication failed: wrong/swapped key, damaged payload, or not a Legacy payload |
| `CORRUPT` | Authenticated, but padLen > 4 or the plaintext is not a canonical valid mnemonic |
| `VERIFY_FAILED` | Encrypt self-check failed; nothing was produced |

## 7. Test vectors

`test-vectors.json` holds deterministic vectors (fixed salt, IV and padding)
covering 12 and 24 words, several padding lengths, all ASCII punctuation, and
key canonicalization (messy input keys that
must produce the same payload as clean ones), plus 26 invalid payloads with
their required error codes. Regenerate with `node tools/generate-vectors.js`;
both test suites fail if the file and the code disagree.

Vector 1, for a quick manual check:

```
seed           abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
benefactorKey  correct horse battery staple
beneficiaryKey trombone yellow lantern quiet
salt           000102030405060708090a0b0c0d0e0f
iv             101112131415161718191a1b
padBytes       (none)
payload        AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaG3paH38t9XEn69wGB8wrYlEQuyfO-yW3xZCmoFhUHNcEbEaMi5CgeyDP9Fq9MSka6bbovt4u0C6s2HhcDofpAWnpf9Pltr2O0K23Hw0CwZCjF554ouezMCJ6dqxV7F04Z2I0q7lTf6S2Mrke3VqF
```

## 8. Minimal reference decryptor (Python, `cryptography` package)

```python
import base64, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def legacy_decrypt(payload, benefactor_key, beneficiary_key):
    # keys must already be canonical (section 2.2)
    b64 = payload.strip()
    body = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    salt, iv, ct = body[:16], body[16:28], body[28:]
    password = benefactor_key.encode() + b"\x1f" + beneficiary_key.encode()
    key = hashlib.pbkdf2_hmac("sha256", password, salt, 600_000, 32)
    plain = AESGCM(key).decrypt(iv, ct, None)
    pad_len = plain[0]
    return plain[1:len(plain) - pad_len].decode()
```

## 9. Design decisions

- **PBKDF2-HMAC-SHA256, 600,000 iterations** (OWASP guidance). Argon2 is not
  in Web Crypto, which would break the zero-dependency offline page, and its
  memory-hardness risks OOM on the 512 MB Pi Zero. Fixed rather than stored,
  so payloads stay unmarked.
- **Padding (0–4 bytes)** is retained as part of the design; it costs nothing.
- **base64url** keeps a saved or handed-down payload from being mangled in
  URLs and filenames.
- **Printable-ASCII keys** guarantee a key made in any browser can be typed on
  the SeedSigner, and remove every Unicode-normalization pitfall (composed vs.
  decomposed accents, smart punctuation, invisible characters) that could lock
  an heir out.
- **No prefix, version or header.** An earlier draft started every payload
  with `LE2.` plus a fixed header, which made any payload recognizable as
  Legacy at a glance. This final format trades that self-description for
  payloads indistinguishable from random data. Only the length (which hints
  at 12 vs. 24 words) is visible.
