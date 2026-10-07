// quick sanity check — one clean workflow, one nasty one.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { analyze } = require("../src/analyzer");

function makeRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ciguard-test-"));
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(dir, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

const clean = `
name: ci
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: npm test
`;

const nasty = `
name: pr-build
on:
  pull_request_target:
    types: [opened]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: github.event.pull_request.head.sha
      - uses: some-random/action@v1
      - name: greet
        run: echo "hello \${{ github.event.issue.title }}"
`;

const dir = makeRepo({
  ".github/workflows/clean.yml": clean,
  ".github/workflows/nasty.yml": nasty,
});

let failed = 0;
function check(label, cond) {
  console.log(`${cond ? "PASS" : "FAIL"} — ${label}`);
  if (!cond) failed++;
}

const results = analyze(dir);
const byFile = Object.fromEntries(results.map((r) => [r.file, r]));

check("found both workflows", results.length === 2);
check(`clean scores LOW (got ${byFile["clean.yml"].band} ${byFile["clean.yml"].score})`,
  byFile["clean.yml"].band === "LOW");
check(`nasty scores HIGH+ (got ${byFile["nasty.yml"].band} ${byFile["nasty.yml"].score})`,
  ["HIGH", "CRITICAL"].includes(byFile["nasty.yml"].band));
check("script injection flagged",
  byFile["nasty.yml"].findings.some((f) => f.code === "SCRIPT_INJECTION"));
check("pr_target flagged",
  byFile["nasty.yml"].findings.some((f) => f.code === "TRIGGER_PR_TARGET"));
check("unpinned third-party action flagged",
  byFile["nasty.yml"].findings.some((f) => f.code === "ACTION_UNPINNED" && f.detail.includes("some-random")));
check("write-all flagged",
  byFile["nasty.yml"].findings.some((f) => f.code === "PERM_WRITE_ALL"));

fs.rmSync(dir, { recursive: true, force: true });
process.exit(failed ? 1 : 0);
