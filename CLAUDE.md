# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Legacy Encryption is a P2P Bitcoin inheritance solution — a client-side web application for encrypting and decrypting BIP39 seed phrases using a dual-key (benefactor + beneficiary) system. It requires no backend and works entirely offline via the browser's Web Crypto API.

## Commands

```bash
# Run tests
npm test                          # Standard test run (~1,010 tests)
npm run test:verbose              # With detailed output
npm run test:quick                # Quick subset

# Advanced test runner
node run-tests.js --quick --verbose
node run-tests.js --iterations 2000
node run-tests.js --extensive --parallel
```

## Architecture

### Core Application
The primary deliverable is **`Legacy-offline.html`** — a single self-contained HTML file with no external dependencies. It embeds:
- Full BIP39 English wordlist (2,048 words)
- AES-256-GCM encryption/decryption implementation using the browser Web Crypto API
- Both the encrypt and decrypt UIs in one file

**`encrypt.html`** and **`decrypt.html`** are online demo versions with a warning not to use real seed phrases there.

**`index.html`** is the marketing landing page; the other HTML files (`mission.html`, `how-it-works.html`, `benefits.html`, `FAQ.html`, `protocol.html`, `contact.html`) are informational pages.

### Cryptographic Design
- **Key derivation:** PBKDF2 (SHA-256, 10,000 iterations, 16-byte random salt)
- **Encryption:** AES-256-GCM with a 12-byte random IV
- **Dual-key scheme:** Seed phrase is encrypted first with the benefactor key, then with the beneficiary key — decryption requires both keys in the correct order
- **Obfuscation:** 0–4 bytes of random padding added to plaintext before encryption

### Test Suite (`test-legacy-encryption.js`)
Node.js test suite that reimplements the encryption logic using the Node `crypto` module to mirror the browser Web Crypto API behavior. The `LegacyEncryption` class in this file is the reference implementation for testing purposes only — the canonical implementation lives in `Legacy-offline.html`.

### Styling
`styles.css` is shared across the informational/demo HTML pages (dark theme, Bitcoin orange `#f7931a` accent, Courier New body font). `Legacy-offline.html` has its own embedded styles.
