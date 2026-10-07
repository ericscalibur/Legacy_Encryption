/**
 * Test suite for Legacy Encryption.
 *
 * Tests the real shipped code: legacy-core.js is the exact block embedded in
 * Legacy-offline.html, encrypt.html and decrypt.html, and the first test
 * fails if any embedded copy differs from it by a single byte.
 *
 *   node test-legacy-encryption.js                  standard run
 *   node test-legacy-encryption.js --quick          fewer random round-trips
 *   node test-legacy-encryption.js --extensive      many more
 *   node test-legacy-encryption.js --iterations N   exactly N
 *   node test-legacy-encryption.js --verbose        print every round-trip
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const C = require("./legacy-core.js");

const ROOT = __dirname;
const VECTORS = JSON.parse(fs.readFileSync(path.join(ROOT, "test-vectors.json"), "utf8"));
const SEED_12 = "abandon ".repeat(11) + "about";

function parseArgs(argv) {
    const opts = { roundTrips: 300, verbose: false };
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === "--quick") opts.roundTrips = 40;
        else if (argv[i] === "--extensive") opts.roundTrips = 2000;
        else if (argv[i] === "--iterations") opts.roundTrips = parseInt(argv[++i], 10);
        else if (argv[i] === "--verbose") opts.verbose = true;
    }
    return opts;
}

// Random valid BIP-39 mnemonic (test helper, uses the core's wordlist).
function randomMnemonic(words) {
    const entBits = (words * 11 * 32) / 33;
    const entropy = crypto.randomBytes(entBits / 8);
    const cs = crypto.createHash("sha256").update(entropy).digest();
    let bits = [...entropy].map((b) => b.toString(2).padStart(8, "0")).join("");
    bits += [...cs].map((b) => b.toString(2).padStart(8, "0")).join("").slice(0, entBits / 32);
    const out = [];
    for (let i = 0; i < bits.length; i += 11) out.push(C.WORDLIST[parseInt(bits.slice(i, i + 11), 2)]);
    return out.join(" ");
}

// Random key made of printable ASCII, never empty after canonicalization.
function randomKey(maxLen = 40) {
    const len = 1 + crypto.randomInt(maxLen);
    let s = "";
    for (let i = 0; i < len; i++) s += String.fromCharCode(0x20 + crypto.randomInt(95));
    return /[^ ]/.test(s) ? s : s + "x";
}

async function expectCode(code, fn) {
    try {
        await fn();
    } catch (e) {
        if (e.code !== code) throw new Error(`expected ${code}, got ${e.code || e.name}: ${e.message}`);
        return;
    }
    throw new Error(`expected ${code}, nothing was thrown`);
}

function assertEqual(actual, expected, what) {
    if (actual !== expected) {
        throw new Error(`${what}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    }
}

class TestSuite {
    constructor(opts) {
        this.opts = opts;
        this.passed = 0;
        this.failed = [];
    }

    async run(name, fn, quiet = false) {
        const t0 = Date.now();
        try {
            await fn();
            this.passed++;
            if (!quiet) console.log(`\u2713 ${name} (${Date.now() - t0}ms)`);
        } catch (e) {
            this.failed.push({ name, error: e.message });
            console.log(`\u2717 ${name}: ${e.message}`);
        }
    }

    async runAll() {
        console.log("\u{1f510} Legacy Encryption test suite\n");

        // --- The shipped code is the tested code -----------------------
        await this.run("HTML pages embed legacy-core.js byte-for-byte", () => {
            execFileSync(process.execPath, [path.join(ROOT, "tools", "sync-core.js"), "--check"], { stdio: "pipe" });
        });
        await this.run("test-vectors.json matches legacy-core.js output", () => {
            execFileSync(process.execPath, [path.join(ROOT, "tools", "generate-vectors.js"), "--check"], { stdio: "pipe" });
        });
        await this.run("Embedded wordlist is the official BIP-39 English list", () => {
            const txt = fs.readFileSync(path.join(ROOT, "english.txt"));
            assertEqual(
                crypto.createHash("sha256").update(txt).digest("hex"),
                "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda",
                "english.txt sha256",
            );
            assertEqual(C.WORDLIST.join("\n") + "\n", txt.toString(), "embedded wordlist");
        });

        // --- Published vectors -----------------------------------------
        await this.run("Reproduce every valid test vector", async () => {
            for (const v of VECTORS.valid) {
                const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
                const p = await C.encryptWithParams(v.seed, v.benefactorKey, v.beneficiaryKey, {
                    salt: hex(v.salt), iv: hex(v.iv), padBytes: hex(v.padBytes),
                });
                assertEqual(p, v.payload, v.name);
            }
        });
        await this.run("Decrypt every valid test vector", async () => {
            for (const v of VECTORS.valid) {
                assertEqual(await C.decryptSeedPhrase(v.payload, v.benefactorKey, v.beneficiaryKey), v.canonicalSeed, v.name);
            }
        });
        await this.run("Reject every invalid test vector with the right code", async () => {
            for (const v of VECTORS.invalid) {
                const t0 = Date.now();
                await expectCode(v.code, () => C.decryptSeedPhrase(v.payload, v.benefactorKey, v.beneficiaryKey))
                    .catch((e) => { throw new Error(`${v.name}: ${e.message}`); });
                if (["BAD_PAYLOAD", "BAD_KEY"].includes(v.code) && Date.now() - t0 > 100) {
                    throw new Error(`${v.name}: rejected only after key derivation`);
                }
            }
        });
        await this.run("Payload decodes per the spec with Node's own crypto (independent check)", () => {
            for (const v of VECTORS.valid) {
                const body = Buffer.from(v.payload, "base64url");
                const password = Buffer.concat([
                    Buffer.from(v.canonicalBenefactorKey || v.benefactorKey, "ascii"),
                    Buffer.from([0x1f]),
                    Buffer.from(v.canonicalBeneficiaryKey || v.beneficiaryKey, "ascii"),
                ]);
                const key = crypto.pbkdf2Sync(password, body.subarray(0, 16), 600000, 32, "sha256");
                const d = crypto.createDecipheriv("aes-256-gcm", key, body.subarray(16, 28));
                d.setAuthTag(body.subarray(body.length - 16));
                const plain = Buffer.concat([d.update(body.subarray(28, body.length - 16)), d.final()]);
                assertEqual(plain.subarray(1, plain.length - plain[0]).toString(), v.canonicalSeed, v.name);
            }
        });
        await this.run("No payload starts with a recognizable marker", async () => {
            const starts = new Set();
            for (let i = 0; i < 8; i++) starts.add((await C.encryptSeedPhrase(SEED_12, "k1", "k2")).slice(0, 4));
            if (starts.size < 7) throw new Error(`payload prefixes repeat: ${[...starts]}`);
        });

        // --- Behaviour --------------------------------------------------
        await this.run("Round-trip 12- and 24-word mnemonics", async () => {
            for (const words of [12, 24]) {
                const seed = randomMnemonic(words);
                const p = await C.encryptSeedPhrase(seed, "benefactor key", "beneficiary key");
                assertEqual(await C.decryptSeedPhrase(p, "benefactor key", "beneficiary key"), seed, `${words} words`);
            }
        });
        await this.run("Every payload is unique (random salt and IV)", async () => {
            const seen = new Set();
            for (let i = 0; i < 5; i++) seen.add(await C.encryptSeedPhrase(SEED_12, "a", "b"));
            assertEqual(seen.size, 5, "distinct payloads");
        });
        await this.run("Padding length is random over 0..4", async () => {
            // Same seed, so payload length differs only by padding.
            const lengths = new Set();
            for (let i = 0; i < 60 && lengths.size < 5; i++) {
                lengths.add(Buffer.from(await C.encryptSeedPhrase(SEED_12, "k1", "k2"), "base64url").length);
            }
            assertEqual(lengths.size, 5, "distinct padded lengths");
        });
        await this.run("Wrong, swapped or re-split keys fail", async () => {
            const p = await C.encryptSeedPhrase(SEED_12, "ab", "c");
            assertEqual(await C.decryptSeedPhrase(p, "ab", "c"), SEED_12, "correct keys");
            await expectCode("WRONG_KEYS", () => C.decryptSeedPhrase(p, "a", "bc"));
            await expectCode("WRONG_KEYS", () => C.decryptSeedPhrase(p, "c", "ab"));
            await expectCode("WRONG_KEYS", () => C.decryptSeedPhrase(p, "AB", "c"));
        });
        await this.run("Key canonicalization", async () => {
            const c = C.canonicalizeKey;
            assertEqual(c("  a   b  "), "a b", "spaces");
            assertEqual(c("a\tb\nc\r\nd"), "a b c d", "tab/newline");
            assertEqual(c("a\u00a0b"), "a b", "no-break space");
            assertEqual(c("\u2018x\u2019 \u201cy\u201d"), "'x' \"y\"", "curly quotes");
            assertEqual(c("CaSe"), "CaSe", "case preserved");
            let printable = "";
            for (let i = 0x21; i < 0x7f; i++) printable += String.fromCharCode(i);
            assertEqual(c(printable), printable, "all printable ASCII");
            for (const bad of ["", "   ", "\n\t", "caf\u00e9", "key\u{1F511}", "a\u001fb", "a\u0000b", "a\u007fb", "\u2014", undefined]) {
                await expectCode("BAD_KEY", () => c(bad));
            }
        });
        await this.run("Keys typed differently but canonically equal still decrypt", async () => {
            const p = await C.encryptSeedPhrase(SEED_12, " It\u2019s  mine ", "pass\u00a0word\n");
            assertEqual(await C.decryptSeedPhrase(p, "It's mine", "pass word"), SEED_12, "canonical keys");
        });
        await this.run("Empty or non-ASCII keys are refused at encrypt time", async () => {
            await expectCode("BAD_KEY", () => C.encryptSeedPhrase(SEED_12, "", "b"));
            await expectCode("BAD_KEY", () => C.encryptSeedPhrase(SEED_12, "a", "  \n"));
            await expectCode("BAD_KEY", () => C.encryptSeedPhrase(SEED_12, "contrase\u00f1a", "b"));
        });
        await this.run("Seed normalization and BIP-39 validation", async () => {
            const messy = "  ABANDON abandon\tabandon abandon abandon abandon\nabandon abandon abandon abandon abandon About  ";
            assertEqual(C.normalizeSeedPhrase(messy), SEED_12, "normalized");
            const p = await C.encryptSeedPhrase(messy, "a", "b");
            assertEqual(await C.decryptSeedPhrase(p, "a", "b"), SEED_12, "stored canonical");
            assertEqual(await C.seedPhraseError(SEED_12), null, "valid seed");
            for (const bad of [
                "abandon ability able",
                "abandon ".repeat(11) + "zzzzz",
                "abandon ".repeat(11) + "abandon",                        // bad checksum
                "abandon ".repeat(17) + "agent",                          // valid 18-word, unsupported
                "",
            ]) {
                if ((await C.seedPhraseError(bad)) === null) throw new Error(`accepted: ${bad}`);
                await expectCode("BAD_SEED", () => C.encryptSeedPhrase(bad, "a", "b"));
            }
        });
        await this.run("Surrounding whitespace on the payload is ignored", async () => {
            const p = await C.encryptSeedPhrase(SEED_12, "a", "b");
            assertEqual(await C.decryptSeedPhrase(`\n  ${p} \r\n`, "a", "b"), SEED_12, "trimmed payload");
        });

        // --- Random round-trips -----------------------------------------
        const n = this.opts.roundTrips;
        console.log(`\n\u{1f504} ${n} random round-trips (random 12/24-word mnemonics, random printable-ASCII keys)...`);
        const t0 = Date.now();
        for (let i = 0; i < n; i++) {
            await this.run(`Round-trip ${i + 1}`, async () => {
                const seed = randomMnemonic(Math.random() < 0.5 ? 12 : 24);
                const bk = randomKey(), byk = randomKey();
                const p = await C.encryptSeedPhrase(seed, bk, byk);
                assertEqual(await C.decryptSeedPhrase(p, bk, byk), seed, "round-trip");
            }, !this.opts.verbose);
        }
        console.log(`   done in ${((Date.now() - t0) / 1000).toFixed(1)}s`);

        this.summary();
    }

    summary() {
        const total = this.passed + this.failed.length;
        console.log("\n" + "=".repeat(60));
        console.log(`Total: ${total}   \u2713 Passed: ${this.passed}   \u2717 Failed: ${this.failed.length}`);
        for (const f of this.failed) console.log(`   \u2717 ${f.name}: ${f.error}`);
        console.log("=".repeat(60));
    }
}

async function main(argv = process.argv.slice(2)) {
    const suite = new TestSuite(parseArgs(argv));
    await suite.runAll();
    return suite;
}

if (require.main === module) {
    process.on("unhandledRejection", (reason) => {
        console.error("Unhandled rejection:", reason);
        process.exit(1);
    });
    main().then((s) => process.exit(s.failed.length ? 1 : 0));
}

module.exports = { main, randomMnemonic };
