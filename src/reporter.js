// pretty output. colors are manual ansi, no dep needed for that.

const COLORS = { CRITICAL: "\x1b[31m", HIGH: "\x1b[33m", MEDIUM: "\x1b[93m", LOW: "\x1b[32m" };
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";

function bar(score) {
  const filled = Math.round(score / 5); // 20 blocks total
  return "█".repeat(filled) + "░".repeat(20 - filled);
}

function printReport(results, { json = false } = {}) {
  if (json) {
    console.log(JSON.stringify(results, null, 2));
    return;
  }

  for (const r of results) {
    console.log(`\n${BOLD}${r.file}${RESET}`);
    if (r.error) {
      console.log(`  skipped — ${r.error}\n`);
      continue;
    }
    const color = COLORS[r.band] || "";
    console.log(`${color}${BOLD}[${r.band}]${RESET} risk score: ${BOLD}${r.score}/100${RESET} ${color}${bar(r.score)}${RESET}\n`);
    if (!r.findings.length) {
      console.log("  clean — nothing flagged. either it's spotless or we're not looking hard enough.\n");
      continue;
    }
    for (const f of r.findings) {
      console.log(`  ${color}▸${RESET} ${BOLD}+${f.score}${RESET}  ${f.code}`);
      console.log(`     ${f.detail}`);
    }
    console.log("");
  }
}

module.exports = { printReport };
