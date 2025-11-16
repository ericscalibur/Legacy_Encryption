/**
 * Comprehensive Test Script for Legacy Encryption System
 * Tests encryption/decryption functionality over thousands of iterations
 */

const crypto = require('crypto');
const { webcrypto } = require('crypto');

// Polyfill for browser crypto API in Node.js
if (!globalThis.crypto) {
    globalThis.crypto = webcrypto;
}

// BIP39 English wordlist (first 100 words for testing - full list would be 2048 words)
const BIP39_WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artist"
];

// Core encryption functions extracted from the HTML file
class LegacyEncryption {
    static strToArrayBuffer(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
        for (let i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }

    static arrayBufferToStr(buf) {
        return String.fromCharCode.apply(null, new Uint8Array(buf));
    }

    static generateSalt() {
        return globalThis.crypto.getRandomValues(new Uint8Array(16));
    }

    static async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await globalThis.crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        const key = await globalThis.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 10000,
                hash: "SHA-256"
            },
            keyMaterial,
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
        return key;
    }

    static async encryptData(plaintext, password) {
        const salt = this.generateSalt();
        const key = await this.deriveKey(password, salt);
        const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();

        // Add random padding to the plaintext
        const randomPaddingLength = Math.floor(Math.random() * 5); // Add 0-4 random bytes
        let paddedPlaintext = plaintext;
        for (let i = 0; i < randomPaddingLength; i++) {
            paddedPlaintext += String.fromCharCode(Math.floor(Math.random() * 256));
        }

        const encoded = encoder.encode(paddedPlaintext);

        const ciphertext = await globalThis.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            encoded
        );

        // Convert to Base64
        const ivString = this.arrayBufferToStr(iv);
        const ciphertextString = this.arrayBufferToStr(ciphertext);
        const saltString = this.arrayBufferToStr(salt);

        const ivBase64 = Buffer.from(ivString, 'binary').toString('base64');
        const ciphertextBase64 = Buffer.from(ciphertextString, 'binary').toString('base64');
        const saltBase64 = Buffer.from(saltString, 'binary').toString('base64');

        return {
            salt: saltBase64,
            iv: ivBase64,
            ciphertext: ciphertextBase64,
            paddingLength: randomPaddingLength
        };
    }

    static async decryptData(data, password) {
        try {
            const salt = new Uint8Array(this.strToArrayBuffer(Buffer.from(data.salt, 'base64').toString('binary')));
            const key = await this.deriveKey(password, salt);

            const iv = new Uint8Array(this.strToArrayBuffer(Buffer.from(data.iv, 'base64').toString('binary')));
            const ciphertext = new Uint8Array(this.strToArrayBuffer(Buffer.from(data.ciphertext, 'base64').toString('binary')));

            const decrypted = await globalThis.crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: iv
                },
                key,
                ciphertext
            );

            const decoder = new TextDecoder();
            let decryptedText = decoder.decode(decrypted);

            // Remove random padding
            const paddingLength = data.paddingLength;
            if (paddingLength > 0 && paddingLength <= decryptedText.length) {
                decryptedText = decryptedText.slice(0, -paddingLength);
            }

            return decryptedText;
        } catch (error) {
            if (error.name === "OperationError") {
                throw new Error("Decryption failed due to authentication tag mismatch. This may indicate an incorrect key or corrupted data.");
            } else {
                throw new Error(`Decryption error: ${error.message}`);
            }
        }
    }

    static generateSeedPhrase(wordCount = 12) {
        if (wordCount !== 12 && wordCount !== 24) {
            throw new Error("Seed phrase must be 12 or 24 words");
        }

        const seedPhraseWords = [];
        for (let i = 0; i < wordCount; i++) {
            const randomIndex = Math.floor(Math.random() * BIP39_WORDLIST.length);
            seedPhraseWords.push(BIP39_WORDLIST[randomIndex]);
        }
        return seedPhraseWords.join(" ");
    }

    static validateSeedPhrase(seedPhrase) {
        const words = seedPhrase.split(" ");
        if (words.length !== 12 && words.length !== 24) {
            return false;
        }
        return words.every(word => BIP39_WORDLIST.includes(word));
    }

    static async encryptSeedPhrase(seedPhrase, benefactorKey, beneficiaryKey) {
        if (!this.validateSeedPhrase(seedPhrase)) {
            throw new Error("Invalid seed phrase");
        }

        const combinedKey = benefactorKey + beneficiaryKey;
        const encryptedData = await this.encryptData(seedPhrase, combinedKey);
        const paddingStr = String(encryptedData.paddingLength).padStart(2, "0");
        const combinedString = encryptedData.salt + "." + encryptedData.iv + "." + encryptedData.ciphertext + "." + paddingStr;

        let base64Encoded = Buffer.from(combinedString).toString('base64');
        base64Encoded = base64Encoded.replace(/=+$/, "");

        return base64Encoded;
    }

    static async decryptSeedPhrase(encryptedSeedPhrase, benefactorKey, beneficiaryKey) {
        const combinedKey = benefactorKey + beneficiaryKey;
        const base64Decoded = Buffer.from(encryptedSeedPhrase, 'base64').toString();
        const components = base64Decoded.split(".");

        if (components.length !== 4) {
            throw new Error("Invalid encrypted seed phrase format.");
        }

        const data = {
            salt: components[0],
            iv: components[1],
            ciphertext: components[2],
            paddingLength: parseInt(components[3], 10)
        };

        return await this.decryptData(data, combinedKey);
    }
}

// Test Suite
class TestSuite {
    constructor() {
        this.totalTests = 0;
        this.passedTests = 0;
        this.failedTests = 0;
        this.results = [];
    }

    async runTest(testName, testFunction) {
        this.totalTests++;
        try {
            const startTime = Date.now();
            await testFunction();
            const endTime = Date.now();
            this.passedTests++;
            this.results.push({
                name: testName,
                status: 'PASS',
                time: endTime - startTime,
                error: null
            });
            console.log(`✓ ${testName} (${endTime - startTime}ms)`);
        } catch (error) {
            this.failedTests++;
            this.results.push({
                name: testName,
                status: 'FAIL',
                time: 0,
                error: error.message
            });
            console.log(`✗ ${testName}: ${error.message}`);
        }
    }

    generateRandomString(length = 10) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }

    // Basic encryption/decryption round-trip test
    async testBasicEncryptionDecryption() {
        const plaintext = "Hello, World!";
        const password = "testpassword123";

        const encrypted = await LegacyEncryption.encryptData(plaintext, password);
        const decrypted = await LegacyEncryption.decryptData(encrypted, password);

        if (decrypted !== plaintext) {
            throw new Error(`Expected "${plaintext}", got "${decrypted}"`);
        }
    }

    // Test seed phrase generation and validation
    async testSeedPhraseGeneration() {
        // Test 12-word seed phrase
        const seedPhrase12 = LegacyEncryption.generateSeedPhrase(12);
        if (!LegacyEncryption.validateSeedPhrase(seedPhrase12)) {
            throw new Error("Generated 12-word seed phrase is invalid");
        }

        // Test 24-word seed phrase
        const seedPhrase24 = LegacyEncryption.generateSeedPhrase(24);
        if (!LegacyEncryption.validateSeedPhrase(seedPhrase24)) {
            throw new Error("Generated 24-word seed phrase is invalid");
        }

        // Test invalid lengths
        try {
            LegacyEncryption.generateSeedPhrase(13);
            throw new Error("Should have thrown error for invalid word count");
        } catch (error) {
            if (!error.message.includes("12 or 24 words")) {
                throw error;
            }
        }
    }

    // Test full seed phrase encryption/decryption cycle
    async testSeedPhraseEncryptionDecryption() {
        const seedPhrase = LegacyEncryption.generateSeedPhrase(12);
        const benefactorKey = this.generateRandomString(15);
        const beneficiaryKey = this.generateRandomString(15);

        const encrypted = await LegacyEncryption.encryptSeedPhrase(seedPhrase, benefactorKey, beneficiaryKey);
        const decrypted = await LegacyEncryption.decryptSeedPhrase(encrypted, benefactorKey, beneficiaryKey);

        if (decrypted !== seedPhrase) {
            throw new Error(`Expected "${seedPhrase}", got "${decrypted}"`);
        }
    }

    // Test salt uniqueness
    async testSaltUniqueness() {
        const salts = new Set();
        for (let i = 0; i < 1000; i++) {
            const salt = LegacyEncryption.generateSalt();
            const saltString = Array.from(salt).join(',');
            if (salts.has(saltString)) {
                throw new Error("Duplicate salt generated");
            }
            salts.add(saltString);
        }
    }

    // Test wrong password handling
    async testWrongPassword() {
        const plaintext = "secret message";
        const correctPassword = "correct123";
        const wrongPassword = "wrong456";

        const encrypted = await LegacyEncryption.encryptData(plaintext, correctPassword);

        try {
            await LegacyEncryption.decryptData(encrypted, wrongPassword);
            throw new Error("Should have failed with wrong password");
        } catch (error) {
            if (!error.message.includes("authentication tag mismatch")) {
                throw new Error("Expected authentication tag mismatch error");
            }
        }
    }

    // Test with various character sets
    async testVariousCharacterSets() {
        const testCases = [
            "Simple ASCII text",
            "Unicode: 🔐 🗝️ 💰 ₿",
            "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?",
            "Numbers: 0123456789",
            "Mixed: Hello123!@# 世界 🌍",
            "", // Empty string
            "a", // Single character
            "A".repeat(10000) // Long string
        ];

        for (const testCase of testCases) {
            const password = this.generateRandomString(12);
            const encrypted = await LegacyEncryption.encryptData(testCase, password);
            const decrypted = await LegacyEncryption.decryptData(encrypted, password);

            if (decrypted !== testCase) {
                throw new Error(`Failed for test case: "${testCase}"`);
            }
        }
    }

    // Test corrupted data handling
    async testCorruptedData() {
        const plaintext = "test message";
        const password = "testpass";
        const encrypted = await LegacyEncryption.encryptData(plaintext, password);

        // Corrupt the ciphertext
        const corruptedData = {
            ...encrypted,
            ciphertext: encrypted.ciphertext.slice(0, -5) + "XXXXX"
        };

        try {
            await LegacyEncryption.decryptData(corruptedData, password);
            throw new Error("Should have failed with corrupted data");
        } catch (error) {
            if (!error.message.includes("authentication tag mismatch")) {
                throw new Error("Expected authentication tag mismatch error");
            }
        }
    }

    // Stress test with random data
    async testRandomDataStress() {
        const iterations = 100;
        for (let i = 0; i < iterations; i++) {
            const plaintext = this.generateRandomString(Math.floor(Math.random() * 1000) + 1);
            const password = this.generateRandomString(Math.floor(Math.random() * 50) + 1);

            const encrypted = await LegacyEncryption.encryptData(plaintext, password);
            const decrypted = await LegacyEncryption.decryptData(encrypted, password);

            if (decrypted !== plaintext) {
                throw new Error(`Iteration ${i}: Failed for plaintext length ${plaintext.length}`);
            }
        }
    }

    // Test concurrent operations
    async testConcurrentOperations() {
        const operations = [];
        for (let i = 0; i < 50; i++) {
            operations.push(async () => {
                const plaintext = `Message ${i}`;
                const password = `password${i}`;
                const encrypted = await LegacyEncryption.encryptData(plaintext, password);
                const decrypted = await LegacyEncryption.decryptData(encrypted, password);
                if (decrypted !== plaintext) {
                    throw new Error(`Concurrent operation ${i} failed`);
                }
            });
        }

        await Promise.all(operations.map(op => op()));
    }

    // Performance test
    async testPerformance() {
        const iterations = 100;
        const plaintext = "Performance test message with some reasonable length to test encryption speed";
        const password = "performanceTestPassword123";

        const startTime = Date.now();

        for (let i = 0; i < iterations; i++) {
            const encrypted = await LegacyEncryption.encryptData(plaintext, password);
            const decrypted = await LegacyEncryption.decryptData(encrypted, password);

            if (decrypted !== plaintext) {
                throw new Error(`Performance test iteration ${i} failed`);
            }
        }

        const endTime = Date.now();
        const totalTime = endTime - startTime;
        const avgTime = totalTime / iterations;

        console.log(`Performance: ${iterations} round-trips in ${totalTime}ms (avg: ${avgTime.toFixed(2)}ms per round-trip)`);
    }

    async runAllTests() {
        console.log("🔐 Starting Legacy Encryption Test Suite\n");

        // Basic functionality tests
        await this.runTest("Basic Encryption/Decryption", () => this.testBasicEncryptionDecryption());
        await this.runTest("Seed Phrase Generation", () => this.testSeedPhraseGeneration());
        await this.runTest("Seed Phrase Encryption/Decryption", () => this.testSeedPhraseEncryptionDecryption());

        // Security tests
        await this.runTest("Salt Uniqueness", () => this.testSaltUniqueness());
        await this.runTest("Wrong Password Handling", () => this.testWrongPassword());
        await this.runTest("Corrupted Data Handling", () => this.testCorruptedData());

        // Robustness tests
        await this.runTest("Various Character Sets", () => this.testVariousCharacterSets());
        await this.runTest("Random Data Stress Test", () => this.testRandomDataStress());
        await this.runTest("Concurrent Operations", () => this.testConcurrentOperations());

        // Performance test
        await this.runTest("Performance Test", () => this.testPerformance());

        // Extensive round-trip tests
        console.log("\n🔄 Running extensive round-trip tests...");
        for (let i = 0; i < 1000; i++) {
            await this.runTest(`Round-trip Test ${i + 1}`, async () => {
                const seedPhrase = LegacyEncryption.generateSeedPhrase(Math.random() > 0.5 ? 12 : 24);
                const benefactorKey = this.generateRandomString(Math.floor(Math.random() * 30) + 5);
                const beneficiaryKey = this.generateRandomString(Math.floor(Math.random() * 30) + 5);

                const encrypted = await LegacyEncryption.encryptSeedPhrase(seedPhrase, benefactorKey, beneficiaryKey);
                const decrypted = await LegacyEncryption.decryptSeedPhrase(encrypted, benefactorKey, beneficiaryKey);

                if (decrypted !== seedPhrase) {
                    throw new Error(`Round-trip failed: expected "${seedPhrase}", got "${decrypted}"`);
                }
            });
        }

        this.printSummary();
    }

    printSummary() {
        console.log("\n" + "=".repeat(60));
        console.log("📊 TEST SUMMARY");
        console.log("=".repeat(60));
        console.log(`Total Tests: ${this.totalTests}`);
        console.log(`✓ Passed: ${this.passedTests}`);
        console.log(`✗ Failed: ${this.failedTests}`);
        console.log(`Success Rate: ${((this.passedTests / this.totalTests) * 100).toFixed(2)}%`);

        if (this.failedTests > 0) {
            console.log("\n❌ FAILED TESTS:");
            this.results
                .filter(result => result.status === 'FAIL')
                .forEach(result => {
                    console.log(`   ${result.name}: ${result.error}`);
                });
        }

        const avgTime = this.results
            .filter(result => result.status === 'PASS' && result.time > 0)
            .reduce((sum, result) => sum + result.time, 0) / this.passedTests;

        console.log(`\n⏱️  Average test time: ${avgTime.toFixed(2)}ms`);
        console.log("=".repeat(60));
    }
}

// Run the tests
async function main() {
    const testSuite = new TestSuite();
    await testSuite.runAllTests();

    if (testSuite.failedTests === 0) {
        console.log("\n🎉 All tests passed! The Legacy Encryption system is working correctly.");
        process.exit(0);
    } else {
        console.log("\n⚠️  Some tests failed. Please review the failures above.");
        process.exit(1);
    }
}

// Handle unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

main().catch(console.error);
