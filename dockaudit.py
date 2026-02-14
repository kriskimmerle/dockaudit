#!/usr/bin/env python3
"""dockaudit - Pure Python Dockerfile Linter & Security Auditor.

Lint Dockerfiles for security issues, best practice violations, and common
mistakes. Zero dependencies — stdlib only.

Usage:
    dockaudit [OPTIONS] [DOCKERFILE...]

Examples:
    dockaudit Dockerfile
    dockaudit --format json Dockerfile
    dockaudit --check B Dockerfile
    dockaudit --severity error Dockerfile
    dockaudit --ignore DA003,DA007 Dockerfile
    dockaudit --list-rules
"""

from __future__ import annotations

__version__ = "1.0.0"

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class Severity(Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


SEVERITY_WEIGHT = {
    Severity.ERROR: 15,
    Severity.WARNING: 5,
    Severity.INFO: 2,
}

# Secret patterns (same approach as gitaudit/dotguard)
SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*=\s*['\"][^'\"]{8,}", "API key"),
    (r"(?i)(secret[_-]?key|secretkey)\s*=\s*['\"][^'\"]{8,}", "Secret key"),
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}", "Password"),
    (r"(?i)(token|auth[_-]?token)\s*=\s*['\"][^'\"]{8,}", "Token"),
    (r"(?i)(access[_-]?key)\s*=\s*['\"][^'\"]{8,}", "Access key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub PAT"),
    (r"github_pat_[a-zA-Z0-9_]{22,}", "GitHub PAT (fine-grained)"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API key"),
    (r"sk-proj-[a-zA-Z0-9_-]+", "OpenAI project key"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"xox[bpors]-[a-zA-Z0-9-]+", "Slack token"),
    (r"sk_live_[a-zA-Z0-9]+", "Stripe secret key"),
]

# Package managers and their clean-up patterns
APT_INSTALL_RE = re.compile(r"\bapt-get\s+install\b", re.IGNORECASE)
APT_CLEAN_RE = re.compile(
    r"(apt-get\s+clean|rm\s+-rf\s+/var/lib/apt/lists)", re.IGNORECASE
)
APT_NO_RECOMMENDS_RE = re.compile(r"--no-install-recommends", re.IGNORECASE)
APK_ADD_RE = re.compile(r"\bapk\s+add\b", re.IGNORECASE)
APK_NO_CACHE_RE = re.compile(r"--no-cache", re.IGNORECASE)
PIP_INSTALL_RE = re.compile(r"\bpip3?\s+install\b", re.IGNORECASE)
PIP_NO_CACHE_RE = re.compile(r"--no-cache-dir", re.IGNORECASE)

# Curl/wget piped to shell
CURL_PIPE_RE = re.compile(
    r"(curl|wget)\s+[^|]*\|\s*(sh|bash|zsh|dash|/bin/sh|/bin/bash)",
    re.IGNORECASE,
)

# Sudo usage
SUDO_RE = re.compile(r"\bsudo\b")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    severity: Severity
    line: int
    end_line: int
    title: str
    message: str
    fix: str = ""

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "line": self.line,
            "end_line": self.end_line,
            "title": self.title,
            "message": self.message,
        }
        if self.fix:
            d["fix"] = self.fix
        return d


@dataclass
class Instruction:
    """A parsed Dockerfile instruction (possibly multi-line)."""
    keyword: str          # uppercase keyword: FROM, RUN, COPY, ...
    arguments: str        # everything after the keyword
    line: int             # first line number (1-based)
    end_line: int         # last line number
    raw_lines: list[str] = field(default_factory=list)  # original lines


@dataclass
class Stage:
    """A build stage (FROM ... AS name)."""
    base_image: str
    alias: Optional[str]
    line: int
    has_user: bool = False
    has_healthcheck: bool = False
    instructions: list[Instruction] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES: dict[str, dict] = {}


def rule(rule_id: str, severity: Severity, title: str):
    """Decorator to register a lint rule."""
    def decorator(fn):
        RULES[rule_id] = {
            "id": rule_id,
            "severity": severity,
            "title": title,
            "fn": fn,
        }
        return fn
    return decorator


# ---------------------------------------------------------------------------
# Dockerfile parser
# ---------------------------------------------------------------------------

VALID_INSTRUCTIONS = {
    "FROM", "RUN", "CMD", "LABEL", "MAINTAINER", "EXPOSE", "ENV",
    "ADD", "COPY", "ENTRYPOINT", "VOLUME", "USER", "WORKDIR",
    "ARG", "ONBUILD", "STOPSIGNAL", "HEALTHCHECK", "SHELL",
}

PARSER_DIRECTIVE_RE = re.compile(r"^#\s*(syntax|escape)\s*=\s*(.+)", re.IGNORECASE)


def parse_dockerfile(content: str) -> tuple[list[Instruction], list[str]]:
    """Parse Dockerfile content into instructions.

    Returns (instructions, parser_errors).
    """
    lines = content.splitlines()
    instructions: list[Instruction] = []
    errors: list[str] = []

    i = 0
    n = len(lines)

    # Skip parser directives and blank/comment lines at start
    while i < n:
        stripped = lines[i].strip()
        if PARSER_DIRECTIVE_RE.match(stripped):
            i += 1
            continue
        break

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Skip blank lines and comments
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Collect continuation lines (ending with \)
        start_line = i + 1  # 1-based
        raw_lines = [line]
        full_line = stripped

        while full_line.endswith("\\") and i + 1 < n:
            i += 1
            raw_lines.append(lines[i])
            continuation = lines[i].strip()
            # Remove trailing comment on continuation? No, keep it.
            full_line = full_line[:-1].rstrip() + " " + continuation

        end_line = i + 1  # 1-based

        # Parse keyword
        parts = full_line.split(None, 1)
        if not parts:
            i += 1
            continue

        keyword = parts[0].upper()
        arguments = parts[1] if len(parts) > 1 else ""

        # Handle ONBUILD prefix
        if keyword == "ONBUILD" and arguments:
            inner_parts = arguments.split(None, 1)
            if inner_parts:
                inner_kw = inner_parts[0].upper()
                if inner_kw in VALID_INSTRUCTIONS:
                    # Keep as ONBUILD but store the inner instruction info
                    pass

        if keyword in VALID_INSTRUCTIONS or keyword == "ONBUILD":
            instructions.append(Instruction(
                keyword=keyword,
                arguments=arguments,
                line=start_line,
                end_line=end_line,
                raw_lines=raw_lines,
            ))
        else:
            # Could be a typo or invalid instruction
            errors.append(f"Line {start_line}: Unknown instruction '{parts[0]}'")

        i += 1

    return instructions, errors


def build_stages(instructions: list[Instruction]) -> list[Stage]:
    """Group instructions into build stages."""
    stages: list[Stage] = []
    current: Optional[Stage] = None

    for inst in instructions:
        if inst.keyword == "FROM":
            # Parse FROM image[:tag] [AS name]
            args = inst.arguments.strip()
            alias = None
            as_match = re.search(r"\bAS\s+(\S+)", args, re.IGNORECASE)
            if as_match:
                alias = as_match.group(1)
                base_image = args[:as_match.start()].strip()
            else:
                base_image = args.split()[0] if args.split() else args

            current = Stage(
                base_image=base_image,
                alias=alias,
                line=inst.line,
            )
            stages.append(current)
            current.instructions.append(inst)
        elif current is not None:
            current.instructions.append(inst)
            if inst.keyword == "USER":
                current.has_user = True
            elif inst.keyword == "HEALTHCHECK":
                current.has_healthcheck = True

    return stages


# ---------------------------------------------------------------------------
# Lint rules
# ---------------------------------------------------------------------------

@rule("DA001", Severity.ERROR, "Invalid or unknown instruction")
def check_invalid_instructions(instructions, stages, findings, content):
    """Flag lines that don't match any known Dockerfile instruction."""
    # Already caught by parser errors, but also check mixed case
    for inst in instructions:
        orig = inst.raw_lines[0].strip().split(None, 1)[0] if inst.raw_lines else ""
        if orig and orig != orig.upper() and inst.keyword in VALID_INSTRUCTIONS:
            # Mixed case instruction — not an error per se, but worth a warning
            pass  # Handled by DA020


@rule("DA002", Severity.ERROR, "FROM uses :latest tag")
def check_latest_tag(instructions, stages, findings, content):
    for stage in stages:
        img = stage.base_image
        # Skip scratch and ARG-based images
        if img.lower() == "scratch" or img.startswith("$"):
            continue
        # Check for :latest or no tag at all
        if ":" not in img and "@" not in img:
            findings.append(Finding(
                rule_id="DA002",
                severity=Severity.ERROR,
                line=stage.line,
                end_line=stage.line,
                title="FROM uses implicit :latest tag",
                message=f"Image '{img}' has no explicit tag, defaults to :latest",
                fix=f"Pin to a specific version: {img}:<version>",
            ))
        elif img.endswith(":latest"):
            findings.append(Finding(
                rule_id="DA002",
                severity=Severity.ERROR,
                line=stage.line,
                end_line=stage.line,
                title="FROM uses :latest tag",
                message=f"Image '{img}' uses :latest which is mutable and unpredictable",
                fix=f"Pin to a specific version: {img.rsplit(':',1)[0]}:<version>",
            ))


@rule("DA003", Severity.WARNING, "No USER instruction (running as root)")
def check_no_user(instructions, stages, findings, content):
    if not stages:
        return
    # Only check the final stage
    final = stages[-1]
    if not final.has_user:
        findings.append(Finding(
            rule_id="DA003",
            severity=Severity.WARNING,
            line=final.line,
            end_line=final.instructions[-1].end_line if final.instructions else final.line,
            title="No USER instruction — container runs as root",
            message="The final stage has no USER instruction, so the container runs as root",
            fix="Add 'USER nonroot' or 'USER 1000' before CMD/ENTRYPOINT",
        ))


@rule("DA004", Severity.ERROR, "Secrets in ENV or ARG")
def check_secrets_in_env(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword not in ("ENV", "ARG"):
            continue
        line_text = inst.arguments
        for pattern, desc in SECRET_PATTERNS:
            if re.search(pattern, line_text):
                findings.append(Finding(
                    rule_id="DA004",
                    severity=Severity.ERROR,
                    line=inst.line,
                    end_line=inst.end_line,
                    title=f"Potential {desc} in {inst.keyword}",
                    message=f"{inst.keyword} may contain a {desc}. Secrets should not be baked into images.",
                    fix="Use build secrets (--mount=type=secret) or runtime environment variables instead",
                ))
                break  # One finding per instruction


@rule("DA005", Severity.WARNING, "Missing HEALTHCHECK")
def check_missing_healthcheck(instructions, stages, findings, content):
    if not stages:
        return
    final = stages[-1]
    if not final.has_healthcheck:
        findings.append(Finding(
            rule_id="DA005",
            severity=Severity.WARNING,
            line=final.line,
            end_line=final.instructions[-1].end_line if final.instructions else final.line,
            title="No HEALTHCHECK instruction",
            message="The final stage has no HEALTHCHECK. Orchestrators can't verify container health.",
            fix="Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
        ))


@rule("DA006", Severity.ERROR, "curl/wget piped to shell")
def check_curl_pipe(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "RUN":
            continue
        if CURL_PIPE_RE.search(inst.arguments):
            findings.append(Finding(
                rule_id="DA006",
                severity=Severity.ERROR,
                line=inst.line,
                end_line=inst.end_line,
                title="curl/wget piped to shell",
                message="Piping downloaded scripts directly to shell is a security risk",
                fix="Download the script first, verify its checksum, then execute it",
            ))


@rule("DA007", Severity.WARNING, "Consecutive RUN instructions")
def check_consecutive_run(instructions, stages, findings, content):
    for stage in stages:
        prev_run: Optional[Instruction] = None
        consecutive_count = 0
        first_run_line = 0

        for inst in stage.instructions:
            if inst.keyword == "RUN":
                if prev_run is not None:
                    consecutive_count += 1
                    if consecutive_count == 1:
                        first_run_line = prev_run.line
                else:
                    consecutive_count = 0
                    first_run_line = inst.line
                prev_run = inst
            else:
                if consecutive_count >= 2:
                    findings.append(Finding(
                        rule_id="DA007",
                        severity=Severity.WARNING,
                        line=first_run_line,
                        end_line=prev_run.end_line if prev_run else first_run_line,
                        title=f"{consecutive_count + 1} consecutive RUN instructions",
                        message="Multiple consecutive RUN instructions create unnecessary layers",
                        fix="Combine with && to reduce image size and build time",
                    ))
                prev_run = None
                consecutive_count = 0

        # Handle trailing consecutive RUNs
        if consecutive_count >= 2 and prev_run:
            findings.append(Finding(
                rule_id="DA007",
                severity=Severity.WARNING,
                line=first_run_line,
                end_line=prev_run.end_line,
                title=f"{consecutive_count + 1} consecutive RUN instructions",
                message="Multiple consecutive RUN instructions create unnecessary layers",
                fix="Combine with && to reduce image size and build time",
            ))


@rule("DA008", Severity.WARNING, "Use COPY instead of ADD")
def check_add_vs_copy(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "ADD":
            continue
        args = inst.arguments.strip()
        # ADD is appropriate for URLs and tar extraction
        if args.startswith("http://") or args.startswith("https://"):
            continue
        if re.search(r"\.(tar|tar\.gz|tgz|tar\.bz2|tar\.xz|zip)\b", args):
            continue
        findings.append(Finding(
            rule_id="DA008",
            severity=Severity.WARNING,
            line=inst.line,
            end_line=inst.end_line,
            title="Use COPY instead of ADD for local files",
            message="ADD has special behaviors (URL download, tar extraction). Use COPY for simple file copies.",
            fix=f"Replace ADD with COPY: COPY {args}",
        ))


@rule("DA009", Severity.INFO, "Deprecated MAINTAINER instruction")
def check_maintainer(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword == "MAINTAINER":
            findings.append(Finding(
                rule_id="DA009",
                severity=Severity.INFO,
                line=inst.line,
                end_line=inst.end_line,
                title="MAINTAINER is deprecated",
                message="MAINTAINER is deprecated since Docker 1.13",
                fix=f'Use LABEL maintainer="{inst.arguments.strip()}"',
            ))


@rule("DA010", Severity.WARNING, "apt-get install without --no-install-recommends")
def check_apt_no_recommends(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "RUN":
            continue
        if APT_INSTALL_RE.search(inst.arguments):
            if not APT_NO_RECOMMENDS_RE.search(inst.arguments):
                findings.append(Finding(
                    rule_id="DA010",
                    severity=Severity.WARNING,
                    line=inst.line,
                    end_line=inst.end_line,
                    title="apt-get install without --no-install-recommends",
                    message="Installing recommended packages bloats the image",
                    fix="Add --no-install-recommends: apt-get install --no-install-recommends ...",
                ))


@rule("DA011", Severity.WARNING, "apt-get without cleanup")
def check_apt_cleanup(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "RUN":
            continue
        if APT_INSTALL_RE.search(inst.arguments):
            if not APT_CLEAN_RE.search(inst.arguments):
                findings.append(Finding(
                    rule_id="DA011",
                    severity=Severity.WARNING,
                    line=inst.line,
                    end_line=inst.end_line,
                    title="apt-get install without cache cleanup",
                    message="Package manager cache remains in the layer, increasing image size",
                    fix="Add: && apt-get clean && rm -rf /var/lib/apt/lists/*",
                ))


@rule("DA012", Severity.WARNING, "apk add without --no-cache")
def check_apk_no_cache(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "RUN":
            continue
        if APK_ADD_RE.search(inst.arguments):
            if not APK_NO_CACHE_RE.search(inst.arguments):
                findings.append(Finding(
                    rule_id="DA012",
                    severity=Severity.WARNING,
                    line=inst.line,
                    end_line=inst.end_line,
                    title="apk add without --no-cache",
                    message="apk cache remains in the layer, increasing image size",
                    fix="Add --no-cache: apk add --no-cache ...",
                ))


@rule("DA013", Severity.WARNING, "pip install without --no-cache-dir")
def check_pip_no_cache(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "RUN":
            continue
        if PIP_INSTALL_RE.search(inst.arguments):
            if not PIP_NO_CACHE_RE.search(inst.arguments):
                findings.append(Finding(
                    rule_id="DA013",
                    severity=Severity.WARNING,
                    line=inst.line,
                    end_line=inst.end_line,
                    title="pip install without --no-cache-dir",
                    message="pip cache remains in the layer, increasing image size",
                    fix="Add --no-cache-dir: pip install --no-cache-dir ...",
                ))


@rule("DA014", Severity.WARNING, "Using sudo in RUN")
def check_sudo(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "RUN":
            continue
        if SUDO_RE.search(inst.arguments):
            findings.append(Finding(
                rule_id="DA014",
                severity=Severity.WARNING,
                line=inst.line,
                end_line=inst.end_line,
                title="Using sudo in RUN instruction",
                message="RUN instructions already execute as root (unless USER is set). sudo adds complexity.",
                fix="Remove sudo — use USER to switch users when needed",
            ))


@rule("DA015", Severity.INFO, "Exposing SSH port 22")
def check_ssh_port(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "EXPOSE":
            continue
        ports = re.findall(r"\b22\b", inst.arguments)
        if ports:
            findings.append(Finding(
                rule_id="DA015",
                severity=Severity.INFO,
                line=inst.line,
                end_line=inst.end_line,
                title="Exposing SSH port 22",
                message="SSH inside containers is an anti-pattern. Use docker exec for debugging.",
                fix="Remove EXPOSE 22 and use docker exec or kubectl exec instead",
            ))


@rule("DA016", Severity.WARNING, "WORKDIR with relative path")
def check_workdir_relative(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "WORKDIR":
            continue
        path = inst.arguments.strip()
        if path and not path.startswith("/") and not path.startswith("$"):
            findings.append(Finding(
                rule_id="DA016",
                severity=Severity.WARNING,
                line=inst.line,
                end_line=inst.end_line,
                title="WORKDIR uses relative path",
                message=f"WORKDIR '{path}' is relative, which can be confusing and error-prone",
                fix=f"Use absolute path: WORKDIR /{path}",
            ))


@rule("DA017", Severity.WARNING, "CMD/ENTRYPOINT in shell form")
def check_exec_form(instructions, stages, findings, content):
    if not stages:
        return
    final = stages[-1]
    for inst in final.instructions:
        if inst.keyword not in ("CMD", "ENTRYPOINT"):
            continue
        args = inst.arguments.strip()
        # Exec form starts with [
        if not args.startswith("["):
            findings.append(Finding(
                rule_id="DA017",
                severity=Severity.WARNING,
                line=inst.line,
                end_line=inst.end_line,
                title=f"{inst.keyword} uses shell form",
                message=f"{inst.keyword} in shell form doesn't receive signals properly (PID 1 is sh, not your app)",
                fix=f'Use exec form: {inst.keyword} ["{args.split()[0]}", ...]' if args.split() else "",
            ))


@rule("DA018", Severity.WARNING, "COPY with wildcard source")
def check_copy_wildcard(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword not in ("COPY", "ADD"):
            continue
        # Skip --from= (multi-stage copy) and --chown etc.
        args = inst.arguments
        # Remove flags
        args_clean = re.sub(r"--\S+\s+", "", args).strip()
        parts = args_clean.split()
        if len(parts) >= 2:
            sources = parts[:-1]
            for src in sources:
                if src in (".", "./"):
                    findings.append(Finding(
                        rule_id="DA018",
                        severity=Severity.WARNING,
                        line=inst.line,
                        end_line=inst.end_line,
                        title="COPY/ADD copies entire build context",
                        message=f"'{src}' copies everything. This likely includes files you don't need (docs, tests, .git).",
                        fix="Copy only needed files, or ensure .dockerignore is comprehensive",
                    ))


@rule("DA019", Severity.INFO, "Duplicate ENV keys")
def check_duplicate_env(instructions, stages, findings, content):
    for stage in stages:
        env_keys: dict[str, int] = {}
        for inst in stage.instructions:
            if inst.keyword != "ENV":
                continue
            # Parse ENV KEY=VALUE or ENV KEY VALUE
            args = inst.arguments.strip()
            # Modern form: ENV KEY=VALUE [KEY2=VALUE2 ...]
            kv_matches = re.findall(r"(\w+)=", args)
            if kv_matches:
                for key in kv_matches:
                    if key in env_keys:
                        findings.append(Finding(
                            rule_id="DA019",
                            severity=Severity.INFO,
                            line=inst.line,
                            end_line=inst.end_line,
                            title=f"Duplicate ENV key '{key}'",
                            message=f"ENV {key} was already set on line {env_keys[key]}",
                            fix="Remove the duplicate or consolidate ENV declarations",
                        ))
                    env_keys[key] = inst.line
            else:
                # Legacy form: ENV KEY VALUE
                parts = args.split(None, 1)
                if parts:
                    key = parts[0]
                    if key in env_keys:
                        findings.append(Finding(
                            rule_id="DA019",
                            severity=Severity.INFO,
                            line=inst.line,
                            end_line=inst.end_line,
                            title=f"Duplicate ENV key '{key}'",
                            message=f"ENV {key} was already set on line {env_keys[key]}",
                            fix="Remove the duplicate or consolidate ENV declarations",
                        ))
                    env_keys[key] = inst.line


@rule("DA020", Severity.INFO, "Instruction not uppercase")
def check_instruction_case(instructions, stages, findings, content):
    for inst in instructions:
        if not inst.raw_lines:
            continue
        first_line = inst.raw_lines[0].strip()
        orig_keyword = first_line.split(None, 1)[0] if first_line else ""
        if orig_keyword and orig_keyword != orig_keyword.upper():
            findings.append(Finding(
                rule_id="DA020",
                severity=Severity.INFO,
                line=inst.line,
                end_line=inst.end_line,
                title="Instruction not uppercase",
                message=f"'{orig_keyword}' should be uppercase: {orig_keyword.upper()}",
                fix=f"Change to: {orig_keyword.upper()}",
            ))


@rule("DA021", Severity.WARNING, "Missing FROM instruction")
def check_missing_from(instructions, stages, findings, content):
    if not instructions:
        return
    # Check if first non-ARG instruction is FROM
    for inst in instructions:
        if inst.keyword == "ARG":
            continue
        if inst.keyword != "FROM":
            findings.append(Finding(
                rule_id="DA021",
                severity=Severity.WARNING,
                line=inst.line,
                end_line=inst.end_line,
                title="First instruction is not FROM",
                message=f"Expected FROM but got {inst.keyword}. Dockerfile must start with FROM (or ARG before FROM).",
                fix="Add a FROM instruction before other instructions",
            ))
        break
    if not stages:
        findings.append(Finding(
            rule_id="DA021",
            severity=Severity.WARNING,
            line=1,
            end_line=1,
            title="No FROM instruction found",
            message="Dockerfile has no FROM instruction",
            fix="Add: FROM <base-image>:<tag>",
        ))


@rule("DA022", Severity.ERROR, "apt-get update without install in same RUN")
def check_apt_update_no_install(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "RUN":
            continue
        has_update = re.search(r"\bapt-get\s+update\b", inst.arguments, re.IGNORECASE)
        has_install = APT_INSTALL_RE.search(inst.arguments)
        if has_update and not has_install:
            findings.append(Finding(
                rule_id="DA022",
                severity=Severity.ERROR,
                line=inst.line,
                end_line=inst.end_line,
                title="apt-get update without install in same RUN",
                message="apt-get update in a separate RUN creates a cached layer that becomes stale",
                fix="Combine: RUN apt-get update && apt-get install -y ...",
            ))


@rule("DA023", Severity.WARNING, "apt-get install without -y")
def check_apt_install_yes(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "RUN":
            continue
        if APT_INSTALL_RE.search(inst.arguments):
            if not re.search(r"\s-y\b|\s--yes\b|\s-qq\b", inst.arguments):
                findings.append(Finding(
                    rule_id="DA023",
                    severity=Severity.WARNING,
                    line=inst.line,
                    end_line=inst.end_line,
                    title="apt-get install without -y flag",
                    message="Without -y, apt-get will prompt for confirmation and fail in non-interactive builds",
                    fix="Add -y: apt-get install -y ...",
                ))


@rule("DA024", Severity.WARNING, "COPY --from references undefined stage")
def check_copy_from_undefined(instructions, stages, findings, content):
    stage_names = set()
    for stage in stages:
        if stage.alias:
            stage_names.add(stage.alias.lower())

    for inst in instructions:
        if inst.keyword != "COPY":
            continue
        from_match = re.search(r"--from=(\S+)", inst.arguments)
        if from_match:
            ref = from_match.group(1)
            # Could be a stage name or index
            if ref.isdigit():
                idx = int(ref)
                if idx >= len(stages):
                    findings.append(Finding(
                        rule_id="DA024",
                        severity=Severity.WARNING,
                        line=inst.line,
                        end_line=inst.end_line,
                        title=f"COPY --from={ref} references non-existent stage index",
                        message=f"Stage index {ref} doesn't exist (only {len(stages)} stage(s))",
                        fix="Check stage index or use named stages with AS",
                    ))
            elif ref.lower() not in stage_names:
                # Could be an external image — that's fine
                # Only warn if it looks like it should be a stage name
                pass


@rule("DA025", Severity.ERROR, "RUN with apt-get install uses unpinned packages")
def check_unpinned_packages(instructions, stages, findings, content):
    """Check for apt-get install without pinned versions. Only flag if ALL packages
    are unpinned and there are 3+ packages (to reduce noise)."""
    for inst in instructions:
        if inst.keyword != "RUN":
            continue
        if not APT_INSTALL_RE.search(inst.arguments):
            continue
        # Extract packages after 'install'
        install_match = re.search(
            r"apt-get\s+install\s+(?:-\S+\s+)*(.+?)(?:\s*&&|\s*;|\s*$)",
            inst.arguments,
            re.IGNORECASE,
        )
        if not install_match:
            continue
        pkg_text = install_match.group(1)
        # Remove flags
        pkgs = [p for p in pkg_text.split() if not p.startswith("-") and not p.startswith("\\")]
        if len(pkgs) < 3:
            continue
        pinned = [p for p in pkgs if "=" in p]
        if not pinned and pkgs:
            findings.append(Finding(
                rule_id="DA025",
                severity=Severity.ERROR,
                line=inst.line,
                end_line=inst.end_line,
                title="apt-get install with unpinned package versions",
                message=f"{len(pkgs)} packages installed without version pinning",
                fix="Pin versions: package=version (e.g., curl=7.88.1-10+deb12u5)",
            ))


@rule("DA026", Severity.INFO, "Multiple CMD/ENTRYPOINT instructions")
def check_multiple_cmd(instructions, stages, findings, content):
    for stage in stages:
        cmds = [i for i in stage.instructions if i.keyword == "CMD"]
        entrypoints = [i for i in stage.instructions if i.keyword == "ENTRYPOINT"]
        if len(cmds) > 1:
            findings.append(Finding(
                rule_id="DA026",
                severity=Severity.INFO,
                line=cmds[-1].line,
                end_line=cmds[-1].end_line,
                title="Multiple CMD instructions in stage",
                message=f"Only the last CMD takes effect. {len(cmds)} CMD instructions found.",
                fix="Remove redundant CMD instructions",
            ))
        if len(entrypoints) > 1:
            findings.append(Finding(
                rule_id="DA026",
                severity=Severity.INFO,
                line=entrypoints[-1].line,
                end_line=entrypoints[-1].end_line,
                title="Multiple ENTRYPOINT instructions in stage",
                message=f"Only the last ENTRYPOINT takes effect. {len(entrypoints)} ENTRYPOINT instructions found.",
                fix="Remove redundant ENTRYPOINT instructions",
            ))


@rule("DA027", Severity.WARNING, "EXPOSE with invalid port")
def check_expose_port(instructions, stages, findings, content):
    for inst in instructions:
        if inst.keyword != "EXPOSE":
            continue
        tokens = inst.arguments.split()
        for token in tokens:
            # Remove /tcp or /udp suffix
            port_str = re.sub(r"/(tcp|udp)$", "", token, flags=re.IGNORECASE)
            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    findings.append(Finding(
                        rule_id="DA027",
                        severity=Severity.WARNING,
                        line=inst.line,
                        end_line=inst.end_line,
                        title=f"Invalid port number: {port}",
                        message=f"Port {port} is outside valid range (1-65535)",
                        fix="Use a port between 1 and 65535",
                    ))
            except ValueError:
                if not token.startswith("$"):  # ARG/ENV variable is fine
                    findings.append(Finding(
                        rule_id="DA027",
                        severity=Severity.WARNING,
                        line=inst.line,
                        end_line=inst.end_line,
                        title=f"Non-numeric EXPOSE value: {token}",
                        message=f"'{token}' is not a valid port specification",
                        fix="Use: EXPOSE <port>[/protocol]",
                    ))


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------

def calculate_grade(findings: list[Finding]) -> tuple[int, str]:
    """Calculate score (0-100) and letter grade."""
    score = 100
    for f in findings:
        score -= SEVERITY_WEIGHT.get(f.severity, 0)
    score = max(0, score)

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return score, grade


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

SEVERITY_SYMBOLS = {
    Severity.ERROR: "🔴",
    Severity.WARNING: "🟡",
    Severity.INFO: "ℹ️ ",
}

SEVERITY_COLORS = {
    Severity.ERROR: "\033[91m",
    Severity.WARNING: "\033[93m",
    Severity.INFO: "\033[96m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def format_text(filepath: str, findings: list[Finding], score: int, grade: str,
                parser_errors: list[str], verbose: bool = False) -> str:
    """Format findings as human-readable text."""
    color = supports_color()
    lines = []

    header = f"dockaudit v{__version__}"
    if color:
        lines.append(f"{BOLD}{header}{RESET}")
    else:
        lines.append(header)
    lines.append("=" * 60)
    lines.append(f"File: {filepath}")

    # Parser errors
    for err in parser_errors:
        if color:
            lines.append(f"  {SEVERITY_COLORS[Severity.ERROR]}✗ PARSE ERROR: {err}{RESET}")
        else:
            lines.append(f"  ✗ PARSE ERROR: {err}")

    if not findings and not parser_errors:
        grade_line = f"Grade: {grade} ({score}/100)"
        if color:
            lines.append(f"\n{BOLD}✅ No issues found!{RESET}")
            lines.append(f"{BOLD}{grade_line}{RESET}")
        else:
            lines.append(f"\n✅ No issues found!")
            lines.append(grade_line)
        lines.append("")
        return "\n".join(lines)

    lines.append("")

    # Group by severity
    errors = [f for f in findings if f.severity == Severity.ERROR]
    warnings = [f for f in findings if f.severity == Severity.WARNING]
    infos = [f for f in findings if f.severity == Severity.INFO]

    for group, label in [(errors, "ERRORS"), (warnings, "WARNINGS"), (infos, "INFO")]:
        if not group:
            continue
        sev = group[0].severity
        sym = SEVERITY_SYMBOLS[sev]
        if color:
            lines.append(f"{SEVERITY_COLORS[sev]}{BOLD}{sym} {label} ({len(group)}){RESET}")
        else:
            lines.append(f"{sym} {label} ({len(group)})")
        lines.append("-" * 60)

        for f in group:
            loc = f"Line {f.line}" if f.line == f.end_line else f"Lines {f.line}-{f.end_line}"
            if color:
                lines.append(f"  {SEVERITY_COLORS[sev]}[{f.rule_id}]{RESET} {f.title}")
                lines.append(f"  {DIM}{loc}: {f.message}{RESET}")
                if verbose and f.fix:
                    lines.append(f"  {DIM}Fix: {f.fix}{RESET}")
            else:
                lines.append(f"  [{f.rule_id}] {f.title}")
                lines.append(f"  {loc}: {f.message}")
                if verbose and f.fix:
                    lines.append(f"  Fix: {f.fix}")
            lines.append("")

    # Summary
    lines.append("=" * 60)
    grade_line = f"Grade: {grade} ({score}/100)"
    summary = f"Issues: {len(errors)} errors, {len(warnings)} warnings, {len(infos)} info"
    if color:
        lines.append(f"{BOLD}{grade_line}{RESET}")
    else:
        lines.append(grade_line)
    lines.append(summary)
    lines.append("")

    return "\n".join(lines)


def format_json(filepath: str, findings: list[Finding], score: int, grade: str,
                parser_errors: list[str]) -> str:
    """Format findings as JSON."""
    data = {
        "version": __version__,
        "file": filepath,
        "grade": grade,
        "score": score,
        "parser_errors": parser_errors,
        "findings": [f.to_dict() for f in findings],
        "summary": {
            "total": len(findings),
            "errors": sum(1 for f in findings if f.severity == Severity.ERROR),
            "warnings": sum(1 for f in findings if f.severity == Severity.WARNING),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
        },
    }
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Main lint function
# ---------------------------------------------------------------------------

def validate_dockerignore(dockerfile_path: str) -> list[Finding]:
    """Validate .dockerignore file for a given Dockerfile.
    
    Returns findings related to .dockerignore:
    - Missing .dockerignore file
    - Empty .dockerignore
    - Missing common patterns (.git, node_modules, etc.)
    """
    findings = []
    
    # Determine .dockerignore path (same directory as Dockerfile)
    if dockerfile_path == "<stdin>" or dockerfile_path == "-":
        # Can't validate .dockerignore for stdin input
        return findings
    
    dockerfile_dir = os.path.dirname(dockerfile_path) or "."
    dockerignore_path = os.path.join(dockerfile_dir, ".dockerignore")
    
    # Check if .dockerignore exists
    if not os.path.exists(dockerignore_path):
        findings.append(Finding(
            rule_id="DA099",
            severity=Severity.WARNING,
            line=0,
            end_line=0,
            title="Missing .dockerignore file",
            message="No .dockerignore file found. Build context may include unnecessary files.",
            fix="Create a .dockerignore file to exclude build artifacts, .git, node_modules, etc."
        ))
        return findings
    
    # Read and validate .dockerignore content
    try:
        with open(dockerignore_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, IOError):
        findings.append(Finding(
            rule_id="DA098",
            severity=Severity.INFO,
            line=0,
            end_line=0,
            title=".dockerignore read error",
            message=f"Could not read {dockerignore_path}",
            fix=""
        ))
        return findings
    
    # Check if empty
    non_comment_lines = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    if not non_comment_lines:
        findings.append(Finding(
            rule_id="DA097",
            severity=Severity.WARNING,
            line=0,
            end_line=0,
            title="Empty .dockerignore",
            message=".dockerignore exists but contains no patterns",
            fix="Add common exclusion patterns: .git, *.md, .env, node_modules, __pycache__, etc."
        ))
        return findings
    
    # Check for common recommended patterns
    patterns_text = "\n".join(non_comment_lines)
    recommended = {
        ".git": "version control history",
        "*.md": "documentation",
        ".env": "environment files",
    }
    
    missing_patterns = []
    for pattern, description in recommended.items():
        if pattern not in patterns_text:
            missing_patterns.append(f"{pattern} ({description})")
    
    if missing_patterns:
        findings.append(Finding(
            rule_id="DA096",
            severity=Severity.INFO,
            line=0,
            end_line=0,
            title="Common patterns missing from .dockerignore",
            message=f"Consider adding: {', '.join(missing_patterns)}",
            fix="Add commonly ignored patterns to reduce build context size and improve security"
        ))
    
    return findings


def lint_dockerfile(content: str, ignore_rules: set[str] | None = None,
                    min_severity: Severity = Severity.INFO) -> tuple[list[Finding], int, str, list[str]]:
    """Lint a Dockerfile and return (findings, score, grade, parser_errors)."""
    ignore_rules = ignore_rules or set()

    instructions, parser_errors = parse_dockerfile(content)
    stages = build_stages(instructions)

    all_findings: list[Finding] = []

    for rule_id, rule_info in RULES.items():
        if rule_id in ignore_rules:
            continue
        rule_info["fn"](instructions, stages, all_findings, content)

    # Filter by severity
    severity_order = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}
    min_sev_val = severity_order[min_severity]
    findings = [f for f in all_findings if severity_order[f.severity] <= min_sev_val]

    # Sort: errors first, then warnings, then info, then by line
    findings.sort(key=lambda f: (severity_order[f.severity], f.line))

    score, grade = calculate_grade(all_findings)  # Grade based on all findings, not filtered
    return findings, score, grade, parser_errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def list_rules() -> str:
    """List all rules."""
    lines = ["dockaudit rules:", ""]
    for rule_id in sorted(RULES):
        info = RULES[rule_id]
        sev = info["severity"].value.upper()
        lines.append(f"  {rule_id} [{sev:7s}] {info['title']}")
    lines.append(f"\nTotal: {len(RULES)} rules")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dockaudit",
        description="Pure Python Dockerfile linter & security auditor. Zero dependencies.",
    )
    parser.add_argument(
        "files", nargs="*", default=[],
        help="Dockerfile(s) to lint (default: Dockerfile)",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--check", nargs="?", const="B", default=None, metavar="GRADE",
        help="CI mode: exit 1 if grade below GRADE (default: B)",
    )
    parser.add_argument(
        "--severity", choices=["error", "warning", "info"], default="info",
        help="Minimum severity to show (default: info)",
    )
    parser.add_argument(
        "--ignore", default="",
        help="Comma-separated rule IDs to ignore (e.g., DA003,DA007)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show fix suggestions for each finding",
    )
    parser.add_argument(
        "--list-rules", action="store_true",
        help="List all rules and exit",
    )
    parser.add_argument(
        "--version", action="version", version=f"dockaudit {__version__}",
    )

    args = parser.parse_args(argv)

    if args.list_rules:
        print(list_rules())
        return 0

    files = args.files or ["Dockerfile"]
    ignore_rules = set(r.strip().upper() for r in args.ignore.split(",") if r.strip())
    min_severity = Severity(args.severity)

    exit_code = 0
    all_outputs = []

    for filepath in files:
        if filepath == "-":
            content = sys.stdin.read()
            filepath = "<stdin>"
        else:
            if not os.path.isfile(filepath):
                print(f"Error: {filepath} not found", file=sys.stderr)
                exit_code = 1
                continue
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

        findings, score, grade, parser_errors = lint_dockerfile(
            content, ignore_rules, min_severity
        )
        
        # Validate .dockerignore if not ignored
        dockerignore_findings = validate_dockerignore(filepath)
        dockerignore_findings = [
            f for f in dockerignore_findings
            if f.rule_id not in ignore_rules
        ]
        findings.extend(dockerignore_findings)

        if args.format == "json":
            all_outputs.append(format_json(filepath, findings, score, grade, parser_errors))
        else:
            all_outputs.append(format_text(filepath, findings, score, grade, parser_errors, args.verbose))

        if args.check:
            grade_order = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
            threshold = args.check.upper()
            if grade_order.get(grade, 4) > grade_order.get(threshold, 1):
                exit_code = 1

    if args.format == "json":
        if len(all_outputs) == 1:
            print(all_outputs[0])
        else:
            # Merge JSON outputs into array
            merged = [json.loads(o) for o in all_outputs]
            print(json.dumps(merged, indent=2))
    else:
        print("\n".join(all_outputs))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
