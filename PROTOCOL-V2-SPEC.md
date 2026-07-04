# Legacy Encryption — Protocol v2 Spec (design draft)

**Status:** DESIGN ONLY — do not implement until after the 2026-06-18 podcast demo.
The current demo card runs **v1** and must stay untouched. This document defines v2 so it can be executed cleanly afterward.

**Author goals for v2:**
1. **Never trap a user again** — the format becomes self-describing (versioned + parameterized), so future changes don't break existing encrypted seeds.
2. **Outlive the project** — any standards-based crypto library can decrypt a Legacy QR decades from now, from a published spec + test vectors, without our code.
3. **Fix the key-boundary ambiguity** — unambiguous separation of the two keys.
4. **Stay compact** — equal or smaller QR than v1 (better scannability on a Pi Zero).
5. **v1 stays decryptable forever.**

---

## 1. v1 format (the immutable baseline — document, never remove decrypt support)

**Crypto:**
- Combined password = `benefactorKey + beneficiaryKey` (UTF-8, **no separator** ← the ambiguity)
- KDF: PBKDF2-HMAC-**SHA256**, **600,000** iterations, **16-byte** random salt → **256-bit** key
- Cipher: **AES-256-GCM**, **12-byte** random IV, 16-byte auth tag appended to ciphertext
- Obfuscation: **0–4** random bytes appended to the plaintext seed before encryption; count stored

**Serialization:**
```
inner  = b64(salt) "." b64(iv) "." b64(ciphertext) "." paddingLen(2-digit, zero-padded)
payload = b64(inner)   with trailing '=' stripped
```
- `ciphertext` already includes the 16-byte GCM tag.
- **v1 has no version marker** — that's how we detect it (see §4).

**Implementations:** `Legacy-offline.html` (`encryptSeedPhrase`/`decryptSeedPhrase`), `seedsigner-port/legacy_encryption.py`.

---

## 2. v2 changes (what's different and why)

| Change | v1 | v2 | Why |
|---|---|---|---|
| **Version marker** | none | `LE2.` prefix + internal version byte | Self-describing; future changes never trap users |
| **Key separator** | `bene + benef` (none) | `benefactor` + `0x1F` + `beneficiary` | `0x1F` (Unit Separator) is **untypeable**, so it can never collide with key text — removes boundary ambiguity entirely |
| **KDF params** | hard-coded 600k | **stored in header** (kdf id + iteration count) | Bump iterations or swap KDF later with **no new envelope version** |
| **Encoding** | double-base64 + dot-joined strings | single **base64url** of a packed binary blob | ~25–30% smaller → likely drops QR below Version 10 → easier scan |
| **Padding** | 0–4 bytes, count in payload | optional, count in header `padLen` | Kept for parity; low value (GCM/IV already randomize), see §6 |

### Combined password (v2)
```
kdf_input = utf8(benefactorKey) || 0x1F || utf8(beneficiaryKey)
```
Order still matters; the `0x1F` makes the boundary unambiguous and rules out empty-key edge cases.

---

## 3. v2 binary layout

All multi-byte integers big-endian. Encrypt produces the **body**, then wraps it:

```
BODY (binary):
  offset  size  field
  0       1     version        = 0x02
  1       1     kdf_id         = 0x01  (PBKDF2-HMAC-SHA256)
  2       4     iterations     = 600000 (uint32)  ← stored, so it can change without a v3
  6       1     padLen         = 0..4
  7       16    salt
  23      12    iv (GCM nonce)
  35      ..    ciphertext     (includes trailing 16-byte GCM auth tag)

PAYLOAD (string, goes into the QR):
  "LE2." + base64url(BODY)        trailing '=' stripped
```

- Header is **35 bytes** fixed + ciphertext. Salt/iv are positional — no delimiters needed.
- `kdf_id` + `iterations` in the header are the durability hooks: raising iterations to, say, 1,000,000 later is a *parameter* change, not a format break — decryptors already read both from the header.
- **Decryptors MUST reject `iterations` outside [100,000 … 10,000,000] before deriving the key.** The header is only authenticated by the GCM tag, which can't be checked until *after* PBKDF2 runs — so without this bound a forged payload with `iterations = 0xFFFFFFFF` stalls the decryptor for days (DoS), and an absurdly low count flags a downgrade forgery early. The bound is a decrypt-side sanity check, not a format field; widening it later is a parameter change, not a version bump.
- The `LE2.` prefix is human-glanceable and uses `.` (outside the base64url alphabet) so it can't be confused with body bytes; the authoritative version is still the internal `version` byte (defense in depth).

### GCM associated data (AAD)
Bind the header to the ciphertext: pass `BODY[0..35]` (everything before the ciphertext) as GCM **AAD**. This makes the version/params tamper-evident — flipping the stored iteration count or version invalidates the auth tag. (v1 used no AAD; v2 should.)

---

## 4. Version detection (decryptor algorithm)

```
def decrypt(payload, benefactorKey, beneficiaryKey):
    if re.match(r'^LE(\d+)\.', payload):       # versioned (v2+)
        ver_prefix = parsed number
        body = base64url_decode(strip_prefix(payload))
        assert body[0] == ver_prefix's expected byte
        dispatch on body[0]:
            0x02 -> decrypt_v2(body, keys)
            # future: 0x03 -> decrypt_v3(...)
    else:                                       # no marker = legacy v1
        return decrypt_v1(payload, keys)
```

**Rule:** decryptors MUST keep `decrypt_v1` forever. Encryptors emit **v2 only** once shipped.

---

## 5. Test vectors (publish these — durability guarantee)

Random salt/iv make output non-deterministic, so test vectors fix them via a **test-only deterministic mode** (inject salt+iv instead of `urandom`). Publish in `test-legacy-encryption.js` and the spec:

For **each** of v1 and v2, publish a record:
```
seed:          "abandon abandon ... about"   (12-word canonical)
benefactorKey: "correct-horse-battery-staple"
beneficiaryKey:"trombone-yellow-lantern-quiet"
salt (hex):    <fixed 16 bytes>
iv (hex):      <fixed 12 bytes>
padLen:        0
iterations:    600000
=> payload:    <exact expected string>
```
Plus one 24-word vector and one `padLen=4` vector. These let *any* future implementation prove byte-for-byte compatibility without our code — the real "no third party" guarantee for an heir.

---

## 6. Decisions (RESOLVED 2026-06-17)

1. **Padding — KEEP.** Retain the 0–4 random-byte padding with `padLen` in the header. Treated as part of the design ("secret sauce"); costs nothing on the Pi Zero.
2. **KDF — PBKDF2-HMAC-SHA256.** Stay on PBKDF2: Argon2id isn't in Web Crypto (would break the zero-dependency offline HTML) and its memory-hardness risks OOM on the 512 MB single-core Pi Zero. The stored `kdf_id` leaves the door open for Argon2 (`kdf_id=0x02`) in a future build if ever warranted.
3. **Encoding — base64url.** Swaps `+`→`-`, `/`→`_`, drops `=`. Same size/speed (pure char substitution → zero Pi Zero cost), but URL- and filename-safe so a saved/handed-down blob can't be silently mangled.
4. **Iterations — 600,000.** Matches OWASP guidance; already tolerated on the Pi Zero (~tens of seconds). Header stores the count, so it's bumpable later with no format break.

**Pi Zero note:** v2 adds ~0 compute over v1 — padding is a few bytes, base64url is free, KDF/iterations unchanged. Expect identical runtime to the proven v1 build.

---

## 7. Implementation checklist (post-podcast)

- [ ] `Legacy-offline.html`: add v2 encrypt + v1/v2 decrypt dispatch (canonical impl)
- [ ] `seedsigner-port/legacy_encryption.py`: mirror v2 encrypt + dispatch; keep `decrypt_v1`
- [ ] `test-legacy-encryption.js`: deterministic-mode test vectors for v1 **and** v2; round-trip + cross-impl tests
- [ ] `protocol.html`: document v2 envelope, header fields, version detection, test vectors
- [ ] `CLAUDE.md`: update Cryptographic Design section for v2
- [ ] Rebuild image, re-flash, **re-rehearse full round trip** before any public release
- [ ] Tag a release; keep v1-capable builds downloadable forever

---

## 8. One-line summary
v2 = **same proven crypto (AES-256-GCM + PBKDF2-600k)** wrapped in a **versioned, self-describing, parameter-carrying envelope**, with an **untypeable key separator** and **published test vectors** — so the protocol can evolve forever without ever stranding a user's encrypted seed.
