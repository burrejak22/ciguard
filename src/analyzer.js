const fs = require("fs");
const path = require("path");
const yaml = require("js-yaml");
const checks = require("./checks");

function findWorkflows(input) {
  // single file, or walk a dir for anything that looks like a workflow
  if (fs.statSync(input).isFile()) return [input];
  const files = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) { walk(full); continue; }
      if (/\.(ya?ml)$/i.test(e.name)) files.push(full);
    }
  };
  walk(input);
  return files;
}

function analyze(input) {
  const files = findWorkflows(input);
  if (!files.length) throw new Error("no workflow files found — point it at a .yml file or a repo dir");

  return files.map((f) => {
    let workflow;
    try {
      workflow = yaml.load(fs.readFileSync(f, "utf8"));
    } catch (e) {
      return { file: path.basename(f), error: `couldn't parse: ${e.message}` };
    }
    // js-yaml reads `on:` as boolean true (yaml 1.1 things). fix it up.
    if (workflow && workflow.on === undefined && workflow[true] !== undefined) {
      workflow.on = workflow[true];
    }
    if (!workflow || typeof workflow !== "object" || !workflow.jobs) {
      return { file: path.basename(f), error: "doesn't look like a workflow (no jobs)" };
    }

    const findings = [
      ...checks.checkScriptInjection(workflow),
      ...checks.checkUnpinnedActions(workflow),
      ...checks.checkDangerousTriggers(workflow),
      ...checks.checkPermissions(workflow),
    ];
    findings.sort((a, b) => b.score - a.score);
    const score = Math.min(100, findings.reduce((s, x) => s + x.score, 0));

    return { file: path.basename(f), score, band: checks.bandFor(score), findings };
  });
}

function worstBand(results) {
  const order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  let worst = 0;
  for (const r of results) {
    if (!r.band) continue;
    worst = Math.max(worst, order.indexOf(r.band));
  }
  return order[worst];
}

module.exports = { analyze, worstBand };
