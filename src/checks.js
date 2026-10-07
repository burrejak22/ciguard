// what makes a workflow sketchy, and how much we care

// contexts an attacker can influence via PRs, issues, comments...
const DANGEROUS_CONTEXTS = [
  "github.event.issue.title",
  "github.event.issue.body",
  "github.event.pull_request.title",
  "github.event.pull_request.body",
  "github.event.comment.body",
  "github.event.review.body",
  "github.head_ref",
  "github.base_ref",
];

function triggersOf(workflow) {
  const on = workflow.on;
  if (!on) return [];
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.map(String);
  return Object.keys(on);
}

function eachStep(workflow) {
  const out = [];
  const jobs = workflow.jobs || {};
  for (const [jobId, job] of Object.entries(jobs)) {
    const steps = (job && job.steps) || [];
    steps.forEach((step, index) => out.push({ jobId, step: step || {}, index }));
  }
  return out;
}

function checkScriptInjection(workflow) {
  // ${{ }} inside run: blocks — attacker-controlled text becomes shell code
  const out = [];
  const prTarget = triggersOf(workflow).includes("pull_request_target");
  for (const { jobId, step, index } of eachStep(workflow)) {
    const script = step.run;
    if (typeof script !== "string" || !script.includes("${{")) continue;
    const where = `job ${jobId}, step ${index + 1}`;
    if (DANGEROUS_CONTEXTS.some((c) => script.includes(c))) {
      out.push({
        code: "SCRIPT_INJECTION",
        score: prTarget ? 45 : 35,
        detail: `script injection: attacker-controlled context interpolated into run: (${where})`,
      });
    } else if (script.includes("github.event")) {
      out.push({
        code: "SCRIPT_INJECTION_MAYBE",
        score: 20,
        detail: `possible script injection: github.event data inside run: (${where}) — verify it's not attacker-controlled`,
      });
    } else {
      out.push({
        code: "SCRIPT_EXPRESSION",
        score: 8,
        detail: `expression inside run: (${where}) — usually fine, worth a glance`,
      });
    }
  }
  return out;
}

const TRUSTED_ORGS = ["actions/", "github/"];

function checkUnpinnedActions(workflow) {
  const out = [];
  const seen = new Set(); // don't nag about the same action twice
  for (const { jobId, step } of eachStep(workflow)) {
    const uses = step.uses;
    if (typeof uses !== "string" || !uses.includes("@")) continue;
    const at = uses.lastIndexOf("@");
    const action = uses.slice(0, at);
    const ref = uses.slice(at + 1);
    if (seen.has(uses)) continue;
    seen.add(uses);
    if (/^[0-9a-f]{40}$/.test(ref)) continue; // pinned to a sha, that's the dream
    // docker:// images are their own thing, skip
    if (uses.startsWith("docker://")) continue;
    const trusted = TRUSTED_ORGS.some((o) => action.startsWith(o));
    if (/^(main|master|latest)$/.test(ref)) {
      out.push({
        code: "ACTION_FLOATING",
        score: trusted ? 15 : 30,
        detail: `${uses} floats on ${ref} — a compromised upstream ships straight to you (job ${jobId})`,
      });
    } else {
      out.push({
        code: "ACTION_UNPINNED",
        score: trusted ? 8 : 20,
        detail: `${uses} uses a mutable tag — pin to a sha for supply-chain safety (job ${jobId})`,
      });
    }
  }
  return out;
}

function checkDangerousTriggers(workflow) {
  const out = [];
  if (!triggersOf(workflow).includes("pull_request_target")) return out;
  const steps = eachStep(workflow);
  const checksOutPR = steps.some(
    ({ step }) =>
      typeof step.uses === "string" &&
      step.uses.startsWith("actions/checkout") &&
      JSON.stringify(step.with || {}).includes("github.event.pull_request")
  );
  const runsCode = steps.some(({ step }) => typeof step.run === "string");
  out.push({
    code: "TRIGGER_PR_TARGET",
    score: checksOutPR && runsCode ? 40 : 25,
    detail:
      "pull_request_target runs in a privileged context" +
      (checksOutPR && runsCode
        ? " and checks out + runs PR code — classic pwn-request setup"
        : " — make sure it never touches untrusted code"),
  });
  return out;
}

function checkPermissions(workflow) {
  const out = [];
  const flag = (perms, where, base) => {
    if (!perms) return;
    if (perms === "write-all") {
      out.push({ code: "PERM_WRITE_ALL", score: base, detail: `${where}: write-all — every permission wide open` });
    } else if (typeof perms === "object") {
      for (const [scope, level] of Object.entries(perms)) {
        if (level === "write" && ["contents", "packages", "actions", "id-token"].includes(scope)) {
          out.push({ code: "PERM_BROAD_WRITE", score: 10, detail: `${where}: ${scope}: write — broader than most jobs need` });
        }
      }
    }
  };
  flag(workflow.permissions, "workflow", 30);
  for (const [jobId, job] of Object.entries(workflow.jobs || {})) {
    flag(job && job.permissions, `job ${jobId}`, 20);
  }
  return out;
}

function checkSecretExfil(workflow) {
  const out = [];
  const seen = new Set(); // one of each, don't spam per step
  for (const { jobId, step, index } of eachStep(workflow)) {
    const script = step.run;
    if (typeof script !== "string" || !script.includes("secrets.")) continue;
    const where = `job ${jobId}, step ${index + 1}`;
    if (!seen.has("log") && /echo\s+[^|\n]*\$\{\{\s*secrets\./.test(script)) {
      seen.add("log");
      out.push({
        code: "SECRET_IN_LOG",
        score: 25,
        detail: `secret interpolated into echo output (${where}) — ends up in plain-text logs`,
      });
    }
    if (!seen.has("net") && /curl[\s\S]*?\$\{\{\s*secrets\./.test(script)) {
      seen.add("net");
      out.push({
        code: "SECRET_TO_NETWORK",
        score: 30,
        detail: `secret passed to curl (${where}) — verify the destination is supposed to have it`,
      });
    }
  }
  return out;
}

function checkCachePoisoning(workflow) {
  // actions/cache keyed on attacker-controlled data + PR trigger = poisoned cache for main
  const out = [];
  const untrusted = triggersOf(workflow).some((t) => t.startsWith("pull_request"));
  if (!untrusted) return out;
  for (const { jobId, step, index } of eachStep(workflow)) {
    const uses = step.uses || "";
    if (!uses.startsWith("actions/cache")) continue;
    const key = JSON.stringify(step.with || {});
    if (DANGEROUS_CONTEXTS.some((c) => key.includes(c)) || key.includes("github.head_ref")) {
      out.push({
        code: "CACHE_POISONING",
        score: 30,
        detail: `cache key includes attacker-controlled data (job ${jobId}, step ${index + 1}) — a PR author can poison the cache for main-branch builds`,
      });
    }
  }
  return out;
}

function checkPersistCredentials(workflow) {
  // checkout keeps the token in git config by default; untrusted code running after it can steal it
  const out = [];
  const untrusted = triggersOf(workflow).some((t) => t === "pull_request" || t === "pull_request_target");
  if (!untrusted) return out;
  const runsCode = eachStep(workflow).some(({ step }) => typeof step.run === "string");
  if (!runsCode) return out;
  for (const { jobId, step, index } of eachStep(workflow)) {
    if (typeof step.uses !== "string" || !step.uses.startsWith("actions/checkout")) continue;
    const withBlock = step.with || {};
    if (withBlock["persist-credentials"] === false || withBlock["persist-credentials"] === "false") continue;
    out.push({
      code: "PERSIST_CREDENTIALS",
      score: 20,
      detail: `actions/checkout keeps credentials persisted (job ${jobId}, step ${index + 1}) while PR code runs — token theft vector, set persist-credentials: false`,
    });
    break; // one is enough, don't nag per checkout
  }
  return out;
}

function bandFor(score) {
  if (score >= 70) return "CRITICAL";
  if (score >= 45) return "HIGH";
  if (score >= 20) return "MEDIUM";
  return "LOW";
}

module.exports = {
  checkScriptInjection,
  checkUnpinnedActions,
  checkDangerousTriggers,
  checkPermissions,
  checkSecretExfil,
  checkCachePoisoning,
  checkPersistCredentials,
  triggersOf,
  eachStep,
  bandFor,
};
