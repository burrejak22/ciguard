# ciguard

Security auditor for GitHub Actions workflows. Point it at a workflow file or
a repo and get a risk report: script injection, unpinned third-party actions,
`pull_request_target` footguns, and overly broad permissions.

## Why

CI pipelines are production infrastructure with the keys to the kingdom, and
most workflow files were written by copying Stack Overflow. Supply-chain
attacks through CI are some of the highest-leverage attacks out there, and
reviewing every workflow by hand doesn't scale. ciguard automates the first
pass so security teams can focus on the actually suspicious stuff.

## Install

```bash
npm install -g ciguard
```

Or run from source:

```bash
git clone https://github.com/burrejak22/ciguard
cd ciguard
npm install
```

## Usage

```bash
# single workflow file
ciguard .github/workflows/ci.yml

# whole repo (walks for *.yml / *.yaml)
ciguard ./my-repo

# machine-readable output
ciguard ./my-repo --json
```

### CI usage

Fail the build when risk hits a threshold:

```bash
ciguard .github/workflows --fail-on HIGH
```

Exit code is 1 when the worst finding across all scanned files is the given
band or worse (`LOW` < `MEDIUM` < `HIGH` < `CRITICAL`).

## Example output

```
ci.yml
[HIGH] risk score: 60/100 ████████████░░░░░░░░

  ▸ +40  TRIGGER_PR_TARGET
     pull_request_target runs in a privileged context and checks out + runs PR code — classic pwn-request setup
  ▸ +35  SCRIPT_INJECTION
     script injection: attacker-controlled context interpolated into run: (job build, step 2)
  ▸ +20  ACTION_UNPINNED
     some-random/action@v1 uses a mutable tag — pin to a sha for supply-chain safety (job build)
```

## What gets checked

- **Script injection** — `${{ }}` expressions inside `run:` scripts, weighted
  by whether the context is attacker-controlled (`github.event.issue.title`,
  `github.head_ref`, ...). Worse under `pull_request_target`.
- **Unpinned actions** — `uses:` refs on mutable tags or floating branches
  instead of a commit sha. Third-party actions score higher than `actions/*`.
- **Dangerous triggers** — `pull_request_target` combined with checking out
  and running PR code (the pwn-request pattern).
- **Permissions** — `write-all` at the workflow or job level.

## Scoring

Same philosophy as the rest of the family: weights are opinionated triage
heuristics, not a certification. Totals capped at 100.

| Band     | Score  | Meaning                           |
|----------|--------|-----------------------------------|
| LOW      | 0–19   | boring in a good way              |
| MEDIUM   | 20–44  | worth a look                      |
| HIGH     | 45–69  | needs justification               |
| CRITICAL | 70–100 | fix before this runs again        |

## Limitations

- Static analysis only. It reads the YAML, it doesn't execute your pipeline.
- Expression analysis is heuristic — complex nested contexts may be missed,
  and safe patterns can occasionally get flagged. A HIGH score means "a human
  should look", not "you've been pwned".

## Contributing

Issues and PRs welcome. Keep it dependency-light and keep the CLI fast.
