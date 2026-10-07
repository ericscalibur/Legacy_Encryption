#!/usr/bin/env node
// Copies legacy-core.js verbatim into every HTML page that embeds it,
// replacing everything between the BEGIN/END LEGACY CORE marker lines.
//
//   node tools/sync-core.js           rewrite the pages
//   node tools/sync-core.js --check   exit 1 if any page is out of date

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const PAGES = ["Legacy-offline.html", "encrypt.html", "decrypt.html"];
const BEGIN = "// ==== BEGIN LEGACY CORE ====";
const END = "// ==== END LEGACY CORE ====";

const core = fs.readFileSync(path.join(ROOT, "legacy-core.js"), "utf8").trimEnd();
if (!core.startsWith(BEGIN) || !core.endsWith(END)) {
    console.error("legacy-core.js must start and end with the core markers");
    process.exit(1);
}

function embedded(html, page) {
    const start = html.indexOf(BEGIN);
    const end = html.indexOf(END);
    if (start === -1 || end === -1 || end < start || html.indexOf(BEGIN, start + 1) !== -1) {
        throw new Error(`${page}: expected exactly one BEGIN/END LEGACY CORE block`);
    }
    return { start, end: end + END.length };
}

const check = process.argv.includes("--check");
let stale = 0;
for (const page of PAGES) {
    const file = path.join(ROOT, page);
    const html = fs.readFileSync(file, "utf8");
    const { start, end } = embedded(html, page);
    if (html.slice(start, end) === core) {
        console.log(`ok       ${page}`);
        continue;
    }
    if (check) {
        console.log(`STALE    ${page}`);
        stale++;
    } else {
        fs.writeFileSync(file, html.slice(0, start) + core + html.slice(end));
        console.log(`updated  ${page}`);
    }
}
if (stale) {
    console.error("Run: node tools/sync-core.js");
    process.exit(1);
}
