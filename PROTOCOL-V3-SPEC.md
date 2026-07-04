# Legacy Encryption — Protocol v3 Spec (design draft, for review)

**Status:** DESIGN ONLY — not implemented. Drafted 2026-06-23 to circulate for feedback
before deciding whether to build. v1 and v2 stay decryptable forever regardless.

**What this adds:** **k-of-n recovery** (e.g. 2-of-3) so the scheme no longer fails if a
single party loses their key. Today's v2 is strict **2-of-2**: two people each hold one
half of a single password, and **either one failing loses the seed forever**. For an
inheritance tool that's a serious reliability flaw — two single points of failure. v3
fixes exactly that, while keeping the thing that makes Legacy worth using: each party
holds **one memorable password**, no shares, no infrastructure, fully offline.

---

## 0. Context for a first-time reader

Legacy encrypts a BIP-39 seed phrase so the ciphertext (a QR) can be stored openly/redundantly
and is useless to anyone who finds it. Recovery requires passwords held by separate people.

**Be honest about what this is:** it is *password-based encryption applied more than once* —
**not** Shamir Secret Sharing and **not** threshold cryptography in the information-theoretic
sense. With Shamir, k-1 shares reveal *nothing*. Here, k-1 passwords reveal nothing *usable*,
but the security is **computational**: an attacker with k-1 passwords still "only" has to
brute-force the missing one(s). With high-entropy passwords (4–5 random words each) that's a
strong wall — but it's a different guarantee, and reviewers should hold that distinction.

v3 deliberately uses **zero new cryptographic primitives**. It is the audited v2 encryption
(AES-256-GCM + PBKDF2-HMAC-SHA256, 600k iters) applied once per authorized group. That keeps
it cross-implementation-safe (the exact property we spent v2 hardening) and easy to audit.

---

## 1. The idea in one paragraph

To make a 2-of-3 among parties **A, B, C**, encrypt the seed **three times** — once for each
allowed pair: `{A,B}`, `{A,C}`, `{B,C}`. Each pair's encryption key comes from **both of that
pair's passwords combined**. Store all three ciphertexts in one envelope. Any two parties
combine their two passwords and open the matching ciphertext (GCM's auth tag tells them which
one). Any single party alone can open nothing. Any one party can be lost and the other two
still recover. Generalises to k-of-n by encrypting once per k-subset (`C(n,k)` ciphertexts).

---

## 2. Combining passwords (order-independent)

For a group, the combined password is the group's passwords **sorted by UTF-8 byte value**,
joined by the untypeable `0x1F` separator (same separator as v2):

```
combined = 0x1F.join( sort_by_bytes( [password_i for i in group] ) )
key      = PBKDF2-HMAC-SHA256(combined, salt, iterations, dkLen=32)
```

**Why sort:** so recovery needs *no* knowledge of "who is party 1 vs party 2" or what order to
type — any k holders just enter their k passwords in any order. (Passwords must be distinct;
identical passwords across parties is a misuse and should be rejected at encrypt time.)

---

## 3. v3 binary layout

All multi-byte integers big-endian. Encrypt builds the ENVELOPE, then wraps it.

```
PAYLOAD (the QR string):
  "LE3." + base64url(ENVELOPE)        trailing '=' stripped

ENVELOPE (binary):
  off  size  field
  0    1     version      = 0x03
  1    1     kdf_id       = 0x01  (PBKDF2-HMAC-SHA256)
  2    4     iterations   = 600000 (uint32)
  6    1     k            = threshold        (e.g. 2)
  7    1     n            = total parties     (e.g. 3)
  8    1     rec_count    = number of records = C(n,k)   (e.g. 3)
  9    ..    records[rec_count]

RECORD (binary, variable length):
  off    size  field
  0      k     subset      = k party indices, ascending, 1 byte each (routing label only)
  k      1     padLen      = 0..4
  k+1    16    salt
  k+17   12    iv (GCM nonce)
  k+29   2     ct_len      = ciphertext length (uint16)
  k+31   ..    ciphertext  = AES-256-GCM(seed ‖ padLen random bytes), includes 16-byte tag
```

- **`iterations` bounds (inherited from v2):** decryptors MUST reject `iterations` outside
  [100,000 … 10,000,000] *before* deriving any key. The envelope is only authenticated by the
  per-record GCM tags, which can't be checked until after PBKDF2 runs — without this bound a
  forged payload with `iterations = 0xFFFFFFFF` is a denial-of-service. (Matters even more in
  v3: the try-all decrypt path runs PBKDF2 up to `C(n,k)` times per attempt.)
- **`subset`** is non-secret routing metadata (lets the UI jump straight to the right record
  for a single PBKDF2, and label it "Alice & Carol"). The access structure is already implied
  by `k`/`n`/`rec_count`, so this leaks nothing new.
- **GCM AAD** for each record = the 9-byte ENVELOPE header **plus** that record's header bytes
  (`subset ‖ padLen ‖ salt ‖ iv ‖ ct_len`) — everything except the ciphertext. Tampering with
  version/params/structure fails the auth tag (same discipline as v2).
- **Padding** is per-record 0–4 random *bytes* appended to the seed bytes before encryption
  (kept for parity with v2; count in `padLen`).

---

## 4. Encrypt algorithm

```
encrypt(seed, passwords[0..n-1], k):
    assert all passwords distinct and non-empty
    records = []
    for each subset S of {0..n-1} with |S| == k, in ascending order:
        combined = 0x1F.join(sort_by_bytes([passwords[i] for i in S]))
        salt = random(16); iv = random(12); padLen = random(0..4)
        rec_header = bytes(S) ‖ padLen ‖ salt ‖ iv ‖ ct_len_placeholder
        key = PBKDF2(combined, salt, iterations)
        ct  = AES_GCM_encrypt(key, iv, seed_utf8 ‖ random(padLen),
                              aad = envelope_header ‖ rec_header_without_ct_len_then_with)
        records.append(record(S, padLen, salt, iv, ct))
    return "LE3." + base64url(envelope_header ‖ concat(records))
```

(The AAD must be computed over the final header bytes including `ct_len`; in practice you fix
`ct_len = len(ct)` — GCM ciphertext length equals plaintext length — before sealing.)

## 5. Decrypt algorithm

```
decrypt(payload, present_passwords[0..k-1], [optional: which slots they hold]):
    body = base64url_decode(strip "LE3.")
    read version=0x03, kdf_id, iterations, k, n, rec_count
    combined = 0x1F.join(sort_by_bytes(present_passwords))

    if slots known:                      # fast path — 1 PBKDF2
        rec = record whose subset == sorted(slots)
        return try_record(rec, combined)
    else:                                # try-all — up to C(n,k) PBKDF2
        for rec in records:
            try: return try_record(rec, combined)
            except auth-tag-failure: continue
        raise "wrong passwords or wrong number of holders"

try_record(rec, combined):
    key = PBKDF2(combined, rec.salt, iterations)
    pt  = AES_GCM_decrypt(key, rec.iv, rec.ciphertext, aad=...)   # raises on tag mismatch
    return strip(pt, rec.padLen).utf8()
```

---

## 6. Worked example — 2-of-3 (A, B, C)

```
rec_count = C(3,2) = 3
record 0: subset {A,B}  ct = AESGCM(seed)  key = PBKDF2(sort(pwA,pwB) joined 0x1F)
record 1: subset {A,C}  ct = AESGCM(seed)  key = PBKDF2(sort(pwA,pwC) joined 0x1F)
record 2: subset {B,C}  ct = AESGCM(seed)  key = PBKDF2(sort(pwB,pwC) joined 0x1F)
```

- A lost? → B + C open record 2.
- B lost? → A + C open record 1.
- C lost? → A + B open record 0.
- Any one password alone → opens nothing.

---

## 7. Honest security analysis

| Property | v3 result |
|---|---|
| Confidentiality | Each record = AES-256-GCM under a PBKDF2-600k key from a ≥k-password secret. k-1 passwords can't form any record's full combination → nothing decrypts. |
| Recovery reliability | **Any k of n recover; up to n-k holders can fail.** This is the whole point — fixes v2's 2-of-2 AND-gate. |
| Nature of the guarantee | **Computational, not information-theoretic.** Unlike Shamir, k-1 passwords + brute-forcing the missing one(s) is the attack. Strength = entropy of the missing password(s). |
| Partial-compromise surface | With one party compromised (k=2), the attacker must brute-force one more password — and the multiple records give them **several targets**, so they attack the weakest remaining password. Wider target set than v2. **Mitigation: high-entropy passwords (4–5 random words).** |
| Metadata leakage | Envelope reveals `k`, `n`, and abstract subset structure — never passwords or seed. |
| Tamper-evidence | Per-record GCM AAD binds all params + structure. |
| New primitives | **None.** Same audited AES-GCM + PBKDF2 as v1/v2 → cross-implementation-safe by construction. |

---

## 8. Costs and downsides (read these before deciding)

1. **Encrypt time blows up on the Pi Zero.** Encryption runs `C(n,k)` sequential PBKDF2-600k
   derivations on a single core. 2-of-3 = **3 × ~25s ≈ 75s**. v2 was one ~25s pass. Bigger
   configs are worse. (Decrypt is 1 PBKDF2 with the fast path, or up to `C(n,k)` with try-all.)
2. **QR gets denser.** ~`C(n,k)×` the ciphertext. 2-of-3 of a 12-word seed ≈ **~3×** v2's size
   (roughly QR Version ~16 vs ~10). 24-word or bigger configs get denser still — and dense QRs
   on the Pi Zero camera are *exactly* the thing that caused the historical scan-freeze issues.
3. **Combinatorial blowup caps `n`.** Fine for 2-of-3 (3 records) or 2-of-4 (6). 3-of-5 (10) and
   up get unwieldy in both size and encrypt time. v3 should refuse large configs.
4. **More secret-state in the UI.** Encrypt now collects `n` passwords; both front-ends thread
   more secrets through view state. (Sloppy secret-handling-in-views was a fair criticism of the
   original port — more keys makes that discipline matter more.)
5. **Forward-only.** A v3 blob needs v3-capable Legacy to open. Old builds can't read it. Keep
   every version's offline HTML + image downloadable forever.
6. **Doesn't fix the human layer.** k-of-n protects against *losing* a key, not against an heir
   who never understood they held a critical secret. Education/communication is still on you.

---

## 9. The alternative we're NOT proposing (and why)

The "proper" cryptographic way to get k-of-n with one key is **Shamir-split the data key, then
password-encrypt each share** (one PBKDF2 + one ciphertext regardless of n → small QR, fast
encrypt). We're **not** speccing that here because it requires implementing **GF(256) Shamir
byte-identically in JavaScript and Python** and keeping them in lockstep forever — bespoke
cross-language crypto, the exact risk class v2 worked to eliminate. **Rule of thumb:** if you
find yourself *needing* Shamir (large n, or QR too dense for the Pi Zero camera), that's the
signal you've outgrown Legacy's niche and should adopt **SLIP-39 or Bitcoin multisig** instead
of hand-rolling threshold crypto. v3-combinatorial is the right tool *only* for small k-of-n.

---

## 10. Versioning & test vectors

- **Dispatch:** `LE3.` → v3, `LE2.` → v2, no prefix → legacy v1. Decryptors keep all three
  forever; encryptors emit the newest once shipped.
- **`kdf_id` + `iterations`** are in the header (as in v2), so params can change without a v4.
- **Publish deterministic test vectors** (fixed salts/ivs) for a canonical 2-of-3 example so any
  future implementation can prove byte-for-byte compatibility from the spec alone — the real
  "no third party needed" guarantee for an heir.

---

## 11. Open questions for reviewers (please weigh in)

1. **Strategic:** does 2-of-3 keep Legacy in its simplicity niche, or has it become "a worse,
   unaudited multisig"? Where's the line where you'd just tell someone to use multisig / SLIP-39?
2. **Encrypt time:** is ~75s to encrypt a 2-of-3 on the Pi Zero acceptable? If not, is the answer
   (a) accept it, (b) lower iterations for multi-record, or (c) switch to Shamir (§9) to keep it
   to one PBKDF2 — accepting the bespoke-crypto risk?
3. **QR density** (~3× for 2-of-3) vs the Pi Zero camera: acceptable, or a dealbreaker that
   pushes toward Shamir's smaller blob?
4. **Partial-compromise brute-force surface** (multiple records = multiple targets for an
   attacker who has one password): acceptable given high-entropy key guidance?
5. **Config limits:** cap at 2-of-3 only? 2-of-N? Some small max `rec_count`?
6. **Order-independent password sorting** (§2) — agree it's the right UX call vs. requiring
   parties to know their slot/order?
7. **Bigger picture:** is this worth building at all, or does the honest answer remain "for real
   inheritance, use Bitcoin-native multisig + timelocks; Legacy is a simple offline convenience
   for a narrow case"?

---

## 12. One-line summary

v3 = **the audited v2 encryption, applied once per authorized k-subset**, so any *k of n*
holders recover and no single lost password is fatal — buying real inheritance reliability with
**no new crypto**, at the cost of a denser QR and a slower multi-pass encrypt on the Pi Zero.
