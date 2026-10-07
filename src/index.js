#!/usr/bin/env node
// ciguard — point it at your workflows, find out if your CI is a liability.

const fs = require("fs");
const { analyze, worstBand } = require("./analyzer");
const { printReport } = require("./reporter");

const BANDS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

function usage() {
  console.log(`
ciguard <path> [options]

  path            workflow .yml file, or a directory to walk

options:
  --json               machine-readable output
  --fail-on <band>     exit 1 if the worst file hits band or worse (for CI)
  --out <file>         write the report (json) to a file
  -h, --help           this
`.trim());
}

function main() {
  const args = process.argv.slice(2);
  if (!args.length || args.includes("-h") || args.includes("--help")) {
    usage();
    process.exit(args.length ? 0 : 1);
  }

  let input = null, json = false, failOn = null, out = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--json") json = true;
    else if (a === "--fail-on") failOn = (args[++i] || "").toUpperCase();
    else if (a === "--out") out = args[++i];
    else if (!input) input = a;
    else { console.error(`unexpected arg: ${a}`); process.exit(1); }
  }
  if (failOn && !BANDS.includes(failOn)) {
    console.error(`--fail-on must be one of ${BANDS.join("|")}`);
    process.exit(1);
  }
  if (!fs.existsSync(input)) {
    console.error(`not found: ${input}`);
    process.exit(1);
  }

  let results;
  try {
    results = analyze(input);
  } catch (e) {
    console.error(`analysis failed: ${e.message}`);
    process.exit(1);
  }

  if (out) {
    fs.writeFileSync(out, JSON.stringify(results, null, 2));
    console.error(`wrote ${out}`);
  }
  printReport(results, { json });

  const worst = worstBand(results);
  if (failOn && BANDS.indexOf(worst) >= BANDS.indexOf(failOn)) process.exit(1);
}

main();
