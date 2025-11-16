# Legacy Encryption Test Suite

A comprehensive testing framework for the Legacy Encryption system that validates encryption/decryption functionality across thousands of test iterations.

## Overview

This test suite thoroughly validates the Legacy Encryption HTML application by testing:

- **Core Encryption/Decryption**: AES-GCM encryption with PBKDF2 key derivation
- **Seed Phrase Operations**: BIP39 seed phrase generation, validation, and encryption
- **Security Features**: Salt uniqueness, wrong password handling, data corruption detection
- **Edge Cases**: Various character sets, empty inputs, large data, concurrent operations
- **Performance**: Encryption/decryption speed benchmarking

## Files

- `test-legacy-encryption.js` - Main test suite with comprehensive test cases
- `run-tests.js` - Advanced test runner with configurable options
- `package.json` - Node.js dependencies and scripts
- `TEST_README.md` - This documentation

## Prerequisites

- **Node.js 16.0.0 or higher** (for Web Crypto API support)
- No additional dependencies required (uses built-in Node.js modules)

## Quick Start

1. **Run Basic Tests**:
   ```bash
   node test-legacy-encryption.js
   ```

2. **Run with NPM**:
   ```bash
   npm test
   ```

3. **Quick Test (100 iterations)**:
   ```bash
   node run-tests.js --quick
   ```

## Test Categories

### 1. Basic Functionality Tests
- Basic encryption/decryption round-trips
- Seed phrase generation (12 and 24 words)
- Seed phrase validation
- Full encryption/decryption cycle

### 2. Security Tests
- Salt uniqueness verification (1000 salts)
- Wrong password rejection
- Data corruption detection
- Authentication tag verification

### 3. Robustness Tests
- Various character sets (ASCII, Unicode, special chars)
- Edge cases (empty strings, single chars, long strings)
- Random data stress testing
- Concurrent operation handling

### 4. Performance Tests
- Encryption/decryption speed benchmarking
- Memory usage validation
- Large data handling

### 5. Extensive Round-Trip Tests
- 1000+ iterations with random inputs
- Random seed phrase lengths (12/24 words)
- Random key combinations
- Various data sizes

## Advanced Usage

### Custom Test Runs

```bash
# Run with custom iteration count
node run-tests.js --iterations 5000

# Extensive test suite (5000 iterations)
node run-tests.js --extensive

# Verbose output
node run-tests.js --verbose

# Custom timeout (60 seconds)
node run-tests.js --timeout 60
```

### Test Runner Options

- `--quick` - Fast test run (100 iterations)
- `--extensive` - Comprehensive test run (5000 iterations)  
- `--verbose` - Detailed output for all tests
- `--parallel` - Run tests in parallel (experimental)
- `--iterations <n>` - Custom iteration count
- `--timeout <seconds>` - Test timeout in seconds
- `--help` - Show help message

## Test Results

### Success Output
```
✓ Basic Encryption/Decryption (15ms)
✓ Seed Phrase Generation (8ms)
✓ Seed Phrase Encryption/Decryption (25ms)
...
✓ Round-trip Test 1000 (18ms)

📊 TEST SUMMARY
Total Tests: 1010
✓ Passed: 1010
✗ Failed: 0
Success Rate: 100.00%
⏱️  Average test time: 16.50ms
```

### Failure Output
```
✗ Wrong Password Handling: Expected authentication tag mismatch error
✗ Corrupted Data Handling: Should have failed with corrupted data

❌ FAILED TESTS:
   Wrong Password Handling: Expected authentication tag mismatch error
   Corrupted Data Handling: Should have failed with corrupted data
```

## What Gets Tested

### Core Encryption Functions
- `strToArrayBuffer()` - String to ArrayBuffer conversion
- `arrayBufferToStr()` - ArrayBuffer to string conversion  
- `generateSalt()` - Cryptographic salt generation
- `deriveKey()` - PBKDF2 key derivation (10,000 iterations)
- `encryptData()` - AES-GCM encryption with random padding
- `decryptData()` - AES-GCM decryption with padding removal

### Seed Phrase Functions  
- `generateSeedPhrase()` - BIP39 seed phrase generation
- `validateSeedPhrase()` - BIP39 wordlist validation
- `encryptSeedPhrase()` - Full seed phrase encryption workflow
- `decryptSeedPhrase()` - Full seed phrase decryption workflow

### Security Validations
- **Salt Uniqueness**: Ensures no duplicate salts in 1000 generations
- **Key Derivation**: Consistent key generation from same password/salt
- **Authentication**: AES-GCM authentication tag verification
- **Padding**: Random padding addition/removal integrity

### Error Conditions
- Invalid seed phrase formats (wrong word count, invalid BIP39 words)
- Wrong password authentication failures
- Corrupted ciphertext detection
- Malformed encrypted data handling

## Test Data

### BIP39 Wordlist
Tests use a subset of the BIP39 English wordlist (100 words) for seed phrase generation and validation. The full HTML file contains the complete 2048-word list.

### Test Cases Include
- **Character Sets**: ASCII, Unicode (🔐 🗝️ 💰 ₿), special characters, numbers
- **Data Sizes**: Empty strings, single characters, normal text, large data (10KB+)
- **Key Lengths**: 1-80 character passwords
- **Seed Phrases**: Valid 12/24 word combinations from BIP39 wordlist

## Performance Benchmarks

Expected performance on modern hardware:
- **Encryption**: ~15-25ms per operation
- **Decryption**: ~10-20ms per operation  
- **Key Derivation**: ~8-15ms (10,000 PBKDF2 iterations)
- **Round-trip**: ~25-45ms total

## Troubleshooting

### Common Issues

1. **Node.js Version**: Requires Node.js 16+ for Web Crypto API
   ```bash
   node --version  # Should be 16.0.0 or higher
   ```

2. **Test Timeouts**: Increase timeout for slow systems
   ```bash
   node run-tests.js --timeout 60
   ```

3. **Memory Issues**: Reduce iterations for limited memory
   ```bash
   node run-tests.js --iterations 100
   ```

### Debug Mode
```bash
# Run with verbose output and Node.js debugging
NODE_DEBUG=* node test-legacy-encryption.js --verbose
```

## Integration with Original HTML

The test suite extracts and validates the core JavaScript functions from `Legacy-offline.html`:

- Functions are adapted for Node.js environment
- Web Crypto API polyfilled via Node.js `crypto` module
- Base64 encoding uses Node.js `Buffer` instead of browser `btoa`/`atob`
- BIP39 wordlist subset used for testing

## Continuous Integration

For CI/CD pipelines:

```bash
# Exit with error code on test failure
npm test || exit 1

# Quick tests for fast feedback
node run-tests.js --quick || exit 1
```

## Security Notes

- Tests validate cryptographic security properties
- Salt uniqueness prevents rainbow table attacks
- Authentication tag verification prevents tampering
- Key derivation uses industry-standard PBKDF2 with 10,000 iterations
- AES-GCM provides both confidentiality and authenticity

## Contributing

When adding new tests:

1. Follow existing test patterns in `LegacyEncryption` class
2. Add tests to appropriate category in `TestSuite`
3. Include both positive and negative test cases
4. Validate error messages and types
5. Test edge cases and boundary conditions

## License

This test suite is provided as-is for validating the Legacy Encryption system functionality.