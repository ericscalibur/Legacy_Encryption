# Independent Review Brief

Legacy Encryption has had no independent security review. This brief is for a
reviewer who is willing to change that. Findings will be published in full,
with your name if you want it, including anything unflattering.

## What it is

Legacy encrypts a 12 or 24-word BIP-39 seed under two keys, so it can be stored
or sent digitally and recovered only by someone holding both. It runs offline
in a browser or on a SeedSigner. People may trust it with real bitcoin for
decades, and their heirs may need to use it with no one to help.

## What to review

Start with the first three. They are the core of the project.

1. **Format and cryptography:** [PROTOCOL-SPEC.md](PROTOCOL-SPEC.md). PBKDF2-HMAC-SHA256
   at 600,000 iterations, AES-256-GCM, and two keys joined into one password.
2. **Browser implementation:** [legacy-core.js](legacy-core.js), embedded in
   [Legacy-offline.html](Legacy-offline.html).
3. **Device implementation:** [seedsigner-port/legacy_encryption.py](seedsigner-port/legacy_encryption.py)
   and its flow in `seedsigner-port/views/legacy_views.py`.
4. **Offline guarantee:** whether the Content-Security-Policy in
   `Legacy-offline.html` really prevents all network access.
5. **Release integrity:** the SeedSigner image build in `seedsigner-port/build.sh`
   and how `sign-release.sh` signs releases.

## Questions we want answered

- Is PBKDF2 at 600,000 iterations still the right choice, given that it is cheap
  to attack on GPUs? Should the format move to a memory-hard function?
- Are the strength meter's ratings honest? It estimates from length and variety,
  warns below 60 bits, and only knows a few common passwords. Should Legacy also
  offer generated keys?
- Do the `0x1F` key separator, key canonicalization or padding create any weakness?
- Does removing all headers and markers cost anything important, such as the
  ability to upgrade the format later?
- Do the JavaScript and Python versions behave differently on any input?
- Can a heir recover funds from the published spec alone, with no working Legacy
  software?

## What's out of scope

- Keys chosen weakly by users, except as they bear on the warning above
- Social engineering, and attacks on anyone's accounts or devices
- The online demo in `try-it.html`, which warns against real seeds
- The informational web pages

## How to run it

```bash
npm install
npm run test:all
```

`npm run test:all` needs Python with the `cryptography` package. Published
vectors are in [test-vectors.json](test-vectors.json).

## Known limits

- Two-of-two by design: losing either key loses the funds.
- Security rests on the strength of user-chosen keys.
- No key rotation: changing keys means encrypting again.
- Browsers can't guarantee that memory is wiped.

## Reporting

Please report anything serious privately first, so people can be warned before
details are public. Contact: [the contact details on the About page](about.html#contact).

We can't promise a fee in advance of talking, but we will discuss paying for
your time, and the [Legacy Challenge](challenge.html) remains open to anyone who
breaks the ciphertext.
