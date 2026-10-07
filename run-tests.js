#!/usr/bin/env node
// Convenience wrapper: forwards flags to the real suite in
// test-legacy-encryption.js (--quick, --extensive, --iterations N, --verbose).
// Also runs the Python port's tests when python3 and `cryptography` are
// available, since the device and the browser must agree byte-for-byte.

const { spawnSync } = require("child_process");
const path = require("path");

const args = process.argv.slice(2).filter((a) => a !== "--parallel");
if (args.includes("--help")) {
    console.log("Usage: node run-tests.js [--quick | --extensive | --iterations N] [--verbose] [--no-python]");
    process.exit(0);
}

const js = spawnSync(process.execPath, [path.join(__dirname, "test-legacy-encryption.js"), ...args.filter((a) => a !== "--no-python")], { stdio: "inherit" });
let status = js.status;

if (!args.includes("--no-python")) {
    const py = spawnSync("python3", [path.join(__dirname, "seedsigner-port", "test_cross_compat.py")], { stdio: "inherit" });
    if (py.error) console.log("\n⚠  python3 not found — skipped the Python port tests");
    else if (py.status !== 0) status = status || py.status;
}
process.exit(status);
