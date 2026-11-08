# ciguard

Security auditor for GitHub Actions workflows. Point it at a workflow file or a whole repo. Get a risk report. Script injection, unpinned actions, `pull_request_target` footguns, loose permissions.

## Why

Your CI pipeline is production infrastructure with the keys to everything, and most workflow files were written by someone copy-pasting from Stack Overflow. CI supply-chain attacks are among the highest-leverage attacks going, and the exploitable patterns are the same ones that keep showing up across repos. ciguard automates the first pass so the review time goes to the genuinely weird stuff.

## Install

```bash
npm install -g ciguard
```

From source:

```bash
git clone https://github.com/burrejak22/ciguard
cd ciguard
npm install
```

## Use

```bash
ciguard .github/workflows/ci.yml          # one file
ciguard ./my-repo                          # whole repo, walks for *.yml / *.yaml
ciguard ./my-repo --json
```

### CI

```bash
ciguard .github/workflows --fail-on HIGH
```

Exit 1 when the worst finding across all scanned files is the given band or worse (`LOW` < `MEDIUM` < `HIGH` < `CRITICAL`).

## Example output

```
ci.yml
[HIGH] risk score: 60/100 ████████████░░░░░░░░

  ▸ +40  TRIGGER_PR_TARGET
     pull_request_target runs in a privileged context AND checks out / runs PR code. classic pwn-request setup
  ▸ +35  SCRIPT_INJECTION
     attacker-controlled context interpolated into run: (job build, step 2)
  ▸ +20  ACTION_UNPINNED
     some-random/action@v1 uses a mutable tag. pin to a sha
```

## What gets checked

- **Script injection**. `${{ }}` expressions inside `run:` scripts, weighted by whether the context is attacker-controlled (`github.event.issue.title`, `github.head_ref`, etc). Worse under `pull_request_target`.
- **Unpinned actions**. `uses:` refs on mutable tags or floating branches instead of a commit sha. Third-party actions score higher than `actions/*`.
- **Dangerous triggers**. `pull_request_target` combined with checking out and running PR code, the pwn-request pattern.
- **Permissions**. `write-all` at the workflow or job level.
- **Secret exfiltration**. Secrets echoed into logs or shipped to external URLs via curl.
- **Cache poisoning**. `actions/cache` keys built from attacker-controlled data on PR triggers.
- **Credential persistence**. `actions/checkout` keeping the token around while untrusted PR code runs.

## Scoring

Same philosophy as the other tools. Weights are opinionated triage heuristics, not a certification. Totals cap at 100.

| Band     | Score  | Meaning                           |
|----------|--------|-----------------------------------|
| LOW      | 0 to 19   | boring in a good way              |
| MEDIUM   | 20 to 44  | worth a look                      |
| HIGH     | 45 to 69  | needs justification               |
| CRITICAL | 70 to 100 | fix before this runs again        |

## Limitations

Static analysis only. It reads the YAML, it doesn't execute your pipeline. Expression analysis is heuristic. Complex nested contexts may be missed and safe patterns can occasionally get flagged. HIGH means "a human should look", not "you've been pwned".

## Contributing

Issues and PRs welcome. Keep it dependency-light and keep the CLI fast.
