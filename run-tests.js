#!/usr/bin/env node

/**
 * Advanced Test Runner for Legacy Encryption System
 * Provides configurable test execution with detailed reporting
 */

const fs = require('fs');
const path = require('path');

// Configuration options
const CONFIG = {
    iterations: {
        quick: 100,
        normal: 1000,
        extensive: 5000
    },
    timeout: 30000, // 30 seconds per test
    verbose: false,
    parallel: false
};

// Parse command line arguments
function parseArgs() {
    const args = process.argv.slice(2);
    const config = { ...CONFIG };

    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--quick':
                config.mode = 'quick';
                break;
            case '--extensive':
                config.mode = 'extensive';
                break;
            case '--verbose':
                config.verbose = true;
                break;
            case '--parallel':
                config.parallel = true;
                break;
            case '--iterations':
                config.customIterations = parseInt(args[++i]);
                break;
            case '--timeout':
                config.timeout = parseInt(args[++i]) * 1000;
                break;
            case '--help':
                printHelp();
                process.exit(0);
                break;
        }
    }

    return config;
}

function printHelp() {
    console.log(`
Legacy Encryption Test Runner

Usage: node run-tests.js [options]

Options:
  --quick              Run quick test suite (100 iterations)
  --extensive          Run extensive test suite (5000 iterations)
  --verbose            Enable verbose output
  --parallel           Run tests in parallel (experimental)
  --iterations <n>     Custom number of iterations
  --timeout <seconds>  Test timeout in seconds (default: 30)
  --help               Show this help message

Examples:
  node run-tests.js --quick --verbose
  node run-tests.js --iterations 2000
  node run-tests.js --extensive --parallel
    `);
}

// Test result formatter
class TestResultFormatter {
    constructor(verbose = false) {
        this.verbose = verbose;
        this.startTime = Date.now();
    }

    formatDuration(ms) {
        if (ms < 1000) return `${ms}ms`;
        if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
        return `${(ms / 60000).toFixed(2)}m`;
    }

    printHeader() {
        console.log('🔐 Legacy Encryption Test Suite');
        console.log('='.repeat(50));
        console.log(`Started at: ${new Date().toLocaleString()}`);
        console.log('='.repeat(50));
    }

    printTestResult(testName, status, duration, error = null) {
        const icon = status === 'PASS' ? '✅' : '❌';
        const timeStr = this.formatDuration(duration);

        if (this.verbose || status === 'FAIL') {
            console.log(`${icon} ${testName} (${timeStr})`);
            if (error && (this.verbose || status === 'FAIL')) {
                console.log(`   Error: ${error}`);
            }
        } else {
            process.stdout.write(status === 'PASS' ? '.' : 'F');
        }
    }

    printSummary(results) {
        if (!this.verbose) console.log('\n');

        const totalTime = Date.now() - this.startTime;
        const passed = results.filter(r => r.status === 'PASS').length;
        const failed = results.filter(r => r.status === 'FAIL').length;
        const total = results.length;

        console.log('\n' + '='.repeat(50));
        console.log('📊 TEST SUMMARY');
        console.log('='.repeat(50));
        console.log(`Total Tests: ${total}`);
        console.log(`✅ Passed: ${passed}`);
        console.log(`❌ Failed: ${failed}`);
        console.log(`Success Rate: ${((passed / total) * 100).toFixed(2)}%`);
        console.log(`Total Time: ${this.formatDuration(totalTime)}`);

        if (failed > 0) {
            console.log('\n❌ FAILED TESTS:');
            results
                .filter(r => r.status === 'FAIL')
                .forEach(r => console.log(`   ${r.name}: ${r.error}`));
        }

        const avgTime = results
            .filter(r => r.status === 'PASS')
            .reduce((sum, r) => sum + r.duration, 0) / passed;

        console.log(`\n⏱️  Average test time: ${this.formatDuration(avgTime)}`);
        console.log('='.repeat(50));
    }

    generateReport(results, config) {
        const report = {
            timestamp: new Date().toISOString(),
            config: config,
            summary: {
                total: results.length,
                passed: results.filter(r => r.status === 'PASS').length,
                failed: results.filter(r => r.status === 'FAIL').length,
                duration: Date.now() - this.startTime
            },
            results: results
        };

        const reportPath = path.join(__dirname, `test-report-${Date.now()}.json`);
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
        console.log(`\n📄 Detailed report saved to: ${reportPath}`);

        return report;
    }
}

// Test categories configuration
const TEST_CATEGORIES = {
    basic: [
        'Basic Encryption/Decryption',
        'Seed Phrase Generation',
        'Seed Phrase Encryption/Decryption'
    ],
    security: [
        'Salt Uniqueness',
        'Wrong Password Handling',
        'Corrupted Data Handling',
        'Key Derivation Consistency'
    ],
    robustness: [
        'Various Character Sets',
        'Edge Cases',
        'Large Data Handling',
        'Concurrent Operations'
    ],
    stress: [
        'Random Data Stress Test',
        'Performance Test',
        'Memory Usage Test'
    ]
};

async function runTestSuite(config) {
    const formatter = new TestResultFormatter(config.verbose);
    formatter.printHeader();

    // Import the test module
    const testModule = require('./test-legacy-encryption.js');

    // Determine number of iterations
    let iterations = config.customIterations ||
                    CONFIG.iterations[config.mode] ||
                    CONFIG.iterations.normal;

    console.log(`Configuration:`);
    console.log(`- Mode: ${config.mode || 'normal'}`);
    console.log(`- Iterations: ${iterations}`);
    console.log(`- Verbose: ${config.verbose}`);
    console.log(`- Parallel: ${config.parallel}`);
    console.log(`- Timeout: ${config.timeout}ms`);
    console.log('');

    // This would integrate with the actual test suite
    // For now, we'll simulate running the tests
    console.log('Note: This runner would integrate with the main test suite.');
    console.log('Run the main test with: node test-legacy-encryption.js');

    return [];
}

async function main() {
    try {
        const config = parseArgs();
        const results = await runTestSuite(config);

        if (results.length > 0) {
            const formatter = new TestResultFormatter(config.verbose);
            formatter.printSummary(results);
            formatter.generateReport(results, config);

            const failed = results.filter(r => r.status === 'FAIL').length;
            process.exit(failed > 0 ? 1 : 0);
        }

    } catch (error) {
        console.error('❌ Test runner failed:', error.message);
        if (CONFIG.verbose) {
            console.error(error.stack);
        }
        process.exit(1);
    }
}

// Handle process signals
process.on('SIGINT', () => {
    console.log('\n\n⏹️  Test execution interrupted by user');
    process.exit(130);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error.message);
    process.exit(1);
});

if (require.main === module) {
    main();
}

module.exports = {
    runTestSuite,
    TestResultFormatter,
    TEST_CATEGORIES
};
