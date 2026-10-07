#!/usr/bin/env node
// Regenerates test-vectors.json from legacy-core.js. The committed file is
// the published contract: every implementation must reproduce each payload
// byte-for-byte, and the test suites fail if this script's output changes.
//
//   node tools/generate-vectors.js           rewrite test-vectors.json
//   node tools/generate-vectors.js --check   exit 1 if it would change

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const C = require("../legacy-core.js");

const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const range = (start, n) => Buffer.from(Array.from({ length: n }, (_, i) => (start + i) & 0xff)).toString("hex");

const VECTORS = [
    {
        name: "12 words, no padding",
        seed: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        benefactorKey: "correct horse battery staple",
        beneficiaryKey: "trombone yellow lantern quiet",
        salt: range(0x00, 16),
        iv: range(0x10, 12),
        padBytes: "",
    },
    {
        name: "24 words, 4 padding bytes",
        seed: "abandon ".repeat(23) + "art",
        benefactorKey: "Benefactor-Key!2026",
        beneficiaryKey: "Beneficiary Key #2",
        salt: range(0xf0, 16),
        iv: range(0xa0, 12),
        padBytes: "deadbeef",
    },
    {
        name: "12 words, 2 padding bytes, all ASCII punctuation",
        seed: "legal winner thank year wave sausage worth useful legal winner thank yellow",
        benefactorKey: "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
        beneficiaryKey: "a b",
        salt: range(0x40, 16),
        iv: range(0x80, 12),
        padBytes: "0080",
    },
    {
        name: "key canonicalization: same payload as vector 1",
        seed: "  Abandon abandon abandon abandon abandon abandon\nabandon abandon abandon abandon abandon ABOUT ",
        benefactorKey: "  correct   horse battery\tstaple\n",
        beneficiaryKey: "trombone\u00a0yellow lantern quiet ",
        canonicalBenefactorKey: "correct horse battery staple",
        canonicalBeneficiaryKey: "trombone yellow lantern quiet",
        salt: range(0x00, 16),
        iv: range(0x10, 12),
        padBytes: "",
    },
    {
        name: "key canonicalization: curly quotes become straight quotes",
        seed: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        benefactorKey: "It\u2019s \u201cours\u201d",
        beneficiaryKey: "don\u2018t forget",
        canonicalBenefactorKey: "It's \"ours\"",
        canonicalBeneficiaryKey: "don't forget",
        salt: range(0x20, 16),
        iv: range(0x30, 12),
        padBytes: "01",
    },
];

// Payloads every decryptor must reject, with the error code it must report.
// Built from vector 1 so the only defect is the one named.
function negatives(good) {
    const body = Buffer.from(good, "base64url");
    const mutate = (f) => {
        const b = Buffer.from(body);
        f(b);
        return b.toString("base64url");
    };
    const k = { benefactorKey: "correct horse battery staple", beneficiaryKey: "trombone yellow lantern quiet" };
    // A correctly authenticated payload (under vector 1's keys) whose
    // plaintext breaks a rule only visible after decryption.
    const sealed = (plaintext) => {
        const salt = Buffer.alloc(16, 0x55), iv = Buffer.alloc(12, 0x66);
        const key = crypto.pbkdf2Sync(Buffer.from(k.benefactorKey + "\x1f" + k.beneficiaryKey, "ascii"), salt, 600000, 32, "sha256");
        const c = crypto.createCipheriv("aes-256-gcm", key, iv);
        const ct = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
        return Buffer.concat([salt, iv, ct]).toString("base64url");
    };
    const seed = Buffer.from("abandon ".repeat(11) + "about", "ascii");
    const filler = (n) => Buffer.alloc(n, 0x41).toString("base64url");
    return [
        { name: "wrong benefactor key", payload: good, benefactorKey: "correct horse battery stapler", beneficiaryKey: k.beneficiaryKey, code: "WRONG_KEYS" },
        { name: "keys swapped", payload: good, benefactorKey: k.beneficiaryKey, beneficiaryKey: k.benefactorKey, code: "WRONG_KEYS" },
        { name: "key boundary moved", payload: good, benefactorKey: "correct horse battery stapl", beneficiaryKey: "etrombone yellow lantern quiet", code: "WRONG_KEYS" },
        { name: "key case changed", payload: good, benefactorKey: "Correct horse battery staple", beneficiaryKey: k.beneficiaryKey, code: "WRONG_KEYS" },
        { name: "empty key", payload: good, benefactorKey: "   ", beneficiaryKey: k.beneficiaryKey, code: "BAD_KEY" },
        { name: "non-ASCII key", payload: good, benefactorKey: "corréct horse battery staple", beneficiaryKey: k.beneficiaryKey, code: "BAD_KEY" },
        { name: "control character in key", payload: good, benefactorKey: "correct\u001fhorse", beneficiaryKey: k.beneficiaryKey, code: "BAD_KEY" },
        { name: "salt bit flipped", payload: mutate((b) => { b[0] ^= 1; }), ...k, code: "WRONG_KEYS" },
        { name: "iv bit flipped", payload: mutate((b) => { b[20] ^= 1; }), ...k, code: "WRONG_KEYS" },
        { name: "ciphertext bit flipped", payload: mutate((b) => { b[40] ^= 1; }), ...k, code: "WRONG_KEYS" },
        { name: "tag bit flipped", payload: mutate((b) => { b[b.length - 1] ^= 0x80; }), ...k, code: "WRONG_KEYS" },
        { name: "truncated by one byte", payload: body.subarray(0, body.length - 1).toString("base64url"), ...k, code: "WRONG_KEYS" },
        { name: "random bytes of a plausible length", payload: crypto.createHash("sha512").update("x").digest().toString("base64url") + crypto.createHash("sha512").update("y").digest().toString("base64url"), ...k, code: "WRONG_KEYS" },
        { name: "authenticated, padLen byte above 4", payload: sealed(Buffer.concat([Buffer.from([5]), seed, Buffer.alloc(5)])), ...k, code: "CORRUPT" },
        { name: "authenticated, plaintext not a mnemonic", payload: sealed(Buffer.concat([Buffer.from([0]), Buffer.from("this is not a seed phrase, but it is long enough to pass the length check", "ascii")])), ...k, code: "CORRUPT" },
        { name: "authenticated, mnemonic not canonical (uppercase)", payload: sealed(Buffer.concat([Buffer.from([0]), Buffer.from("ABANDON " + "abandon ".repeat(10) + "about", "ascii")])), ...k, code: "CORRUPT" },
        { name: "old draft format with LE2. prefix", payload: "LE2." + good, ...k, code: "BAD_PAYLOAD" },
        { name: "standard-base64 character", payload: good.slice(0, 20) + "+" + good.slice(21), ...k, code: "BAD_PAYLOAD" },
        { name: "embedded space", payload: good.slice(0, 20) + " " + good.slice(20), ...k, code: "BAD_PAYLOAD" },
        { name: "impossible base64 length", payload: good + "A", ...k, code: "BAD_PAYLOAD" },
        { name: "too short (91 bytes)", payload: filler(91), ...k, code: "BAD_PAYLOAD" },
        { name: "too long (265 bytes)", payload: filler(265), ...k, code: "BAD_PAYLOAD" },
        { name: "a standard 12-word SeedQR (digits)", payload: "000000000000000000000000000000000000000000000003", ...k, code: "BAD_PAYLOAD" },
        { name: "a standard 24-word SeedQR (digits)", payload: "0".repeat(92) + "0102", ...k, code: "BAD_PAYLOAD" },
        { name: "empty", payload: "", ...k, code: "BAD_PAYLOAD" },
        { name: "whitespace only", payload: " \n ", ...k, code: "BAD_PAYLOAD" },
    ];
}

async function build() {
    const out = [];
    for (const v of VECTORS) {
        const payload = await C.encryptWithParams(v.seed, v.benefactorKey, v.beneficiaryKey, {
            salt: hex(v.salt),
            iv: hex(v.iv),
            padBytes: hex(v.padBytes),
        });
        out.push({ ...v, canonicalSeed: C.normalizeSeedPhrase(v.seed), payload });
    }
    if (out[3].payload !== out[0].payload) throw new Error("canonicalization vector diverged from vector 1");
    return {
        description:
            "Legacy Encryption test vectors. Every implementation must produce each `payload` exactly from the listed inputs " +
            "(salt, iv, padBytes in hex), must decrypt each payload back to `canonicalSeed`, " +
            "and must reject every entry in `invalid` with the listed error code. See PROTOCOL-SPEC.md.",
        format: "base64url(salt || iv || AES-256-GCM(PBKDF2-SHA256-600000(canon(k1) 0x1F canon(k2)), padLen || seed || padBytes))",
        valid: out,
        invalid: negatives(out[0].payload),
    };
}

build().then((data) => {
    const file = path.join(__dirname, "..", "test-vectors.json");
    const text = JSON.stringify(data, null, 2) + "\n";
    if (process.argv.includes("--check")) {
        const current = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
        if (current !== text) {
            console.error("test-vectors.json does not match legacy-core.js output");
            process.exit(1);
        }
        console.log("test-vectors.json is up to date");
    } else {
        fs.writeFileSync(file, text);
        console.log(`wrote ${data.valid.length} valid and ${data.invalid.length} invalid vectors`);
    }
}).catch((e) => { console.error(e); process.exit(1); });
