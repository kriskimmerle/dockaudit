# dockaudit

**Pure Python Dockerfile linter & security auditor. Zero dependencies.**

Lint your Dockerfiles for security issues, best practice violations, and common mistakes — without installing Haskell, Go, or Node.js.

```bash
$ dockaudit Dockerfile
dockaudit v1.0.0
============================================================
File: Dockerfile

🔴 ERRORS (2)
------------------------------------------------------------
  [DA002] FROM uses :latest tag
  Line 1: Image 'ubuntu:latest' uses :latest which is mutable and unpredictable

  [DA004] Potential API key in ENV
  Line 5: ENV may contain a API key. Secrets should not be baked into images.

🟡 WARNINGS (3)
------------------------------------------------------------
  [DA003] No USER instruction — container runs as root
  ...

============================================================
Grade: D (60/100)
Issues: 2 errors, 3 warnings, 0 info
```

## Why?

- **hadolint** is great but written in Haskell — requires prebuilt binaries or GHC
- **dockadvisor** is written in Go — requires Go toolchain
- **dockerlint** (Python) — abandoned since 2019, minimal checks

**dockaudit** is a single Python file with zero dependencies. If you have Python 3.10+, you can lint Dockerfiles. Period.

## Installation

```bash
# Just download it
curl -O https://raw.githubusercontent.com/kriskimmerle/dockaudit/main/dockaudit.py
chmod +x dockaudit.py

# Or clone and run
git clone https://github.com/kriskimmerle/dockaudit.git
cd dockaudit
python3 dockaudit.py Dockerfile
```

## Usage

```bash
# Lint a Dockerfile
dockaudit Dockerfile

# Lint with fix suggestions
dockaudit --verbose Dockerfile

# JSON output
dockaudit --format json Dockerfile

# CI mode: exit 1 if grade below B
dockaudit --check B Dockerfile

# Show only errors (skip warnings and info)
dockaudit --severity error Dockerfile

# Ignore specific rules
dockaudit --ignore DA003,DA005 Dockerfile

# Lint from stdin
cat Dockerfile | dockaudit -

# Lint multiple files
dockaudit Dockerfile Dockerfile.dev Dockerfile.prod

# List all rules
dockaudit --list-rules
```

## Rules (27)

| Rule | Severity | Description |
|------|----------|-------------|
| DA001 | ERROR | Invalid or unknown instruction |
| DA002 | ERROR | FROM uses `:latest` tag (or no tag) |
| DA003 | WARNING | No USER instruction — container runs as root |
| DA004 | ERROR | Secrets in ENV or ARG (API keys, passwords, tokens) |
| DA005 | WARNING | Missing HEALTHCHECK instruction |
| DA006 | ERROR | curl/wget piped to shell (`curl \| bash`) |
| DA007 | WARNING | Consecutive RUN instructions (excess layers) |
| DA008 | WARNING | Use COPY instead of ADD for local files |
| DA009 | INFO | Deprecated MAINTAINER instruction |
| DA010 | WARNING | apt-get install without `--no-install-recommends` |
| DA011 | WARNING | apt-get install without cache cleanup |
| DA012 | WARNING | apk add without `--no-cache` |
| DA013 | WARNING | pip install without `--no-cache-dir` |
| DA014 | WARNING | Using sudo in RUN instruction |
| DA015 | INFO | Exposing SSH port 22 |
| DA016 | WARNING | WORKDIR with relative path |
| DA017 | WARNING | CMD/ENTRYPOINT in shell form (signal handling) |
| DA018 | WARNING | COPY/ADD copies entire build context (`.`) |
| DA019 | INFO | Duplicate ENV key declarations |
| DA020 | INFO | Instruction not uppercase |
| DA021 | WARNING | Missing or misplaced FROM instruction |
| DA022 | ERROR | apt-get update without install in same RUN |
| DA023 | WARNING | apt-get install without `-y` flag |
| DA024 | WARNING | COPY --from references undefined stage |
| DA025 | ERROR | apt-get install with unpinned package versions |
| DA026 | INFO | Multiple CMD/ENTRYPOINT instructions |
| DA027 | WARNING | EXPOSE with invalid port number |

## Grading

| Grade | Score | Description |
|-------|-------|-------------|
| A | 90-100 | Excellent — follows best practices |
| B | 80-89 | Good — minor improvements suggested |
| C | 70-79 | Fair — some important issues |
| D | 60-69 | Poor — multiple issues |
| F | <60 | Failing — major security/practice problems |

Scoring: ERROR = -15 points, WARNING = -5 points, INFO = -2 points (from a base of 100).

## CI Integration

```yaml
# .github/workflows/lint.yml
name: Lint Dockerfile
on: [push, pull_request]
jobs:
  dockaudit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: |
          curl -sO https://raw.githubusercontent.com/kriskimmerle/dockaudit/main/dockaudit.py
          python3 dockaudit.py --check B Dockerfile
```

## JSON Output

```bash
$ dockaudit --format json Dockerfile
```

```json
{
  "version": "1.0.0",
  "file": "Dockerfile",
  "grade": "A",
  "score": 100,
  "parser_errors": [],
  "findings": [],
  "summary": {
    "total": 0,
    "errors": 0,
    "warnings": 0,
    "info": 0
  }
}
```

## Security Checks

dockaudit detects **12 secret patterns** in ENV/ARG instructions:

- GitHub PATs (`ghp_...`, `github_pat_...`)
- OpenAI keys (`sk-...`, `sk-proj-...`)
- AWS access keys (`AKIA...`)
- Slack tokens (`xox...`)
- Stripe keys (`sk_live_...`)
- Generic API keys, passwords, tokens, secrets

## Comparison

| Feature | dockaudit | hadolint | dockadvisor |
|---------|-----------|----------|-------------|
| Language | Python | Haskell | Go |
| Dependencies | Zero | GHC/binary | Go toolchain |
| Install | `curl` or `pip` | Download binary | `go install` |
| Rules | 27 | ~90 | 60+ |
| Security checks | Yes (secrets) | Basic | Yes |
| Grading | A-F | No | 0-100 |
| CI mode | `--check` | Exit codes | CLI |
| Shell analysis | No | shellcheck | No |
| JSON output | Yes | Yes (SARIF) | Yes |
| Single file | Yes | No | No |

dockaudit trades rule count for **zero-friction installation**. If you need deep shell analysis inside RUN commands, use hadolint. If you want a quick security and best-practices check with nothing to install, use dockaudit.

## Requirements

- Python 3.10+
- No dependencies

## License

MIT
