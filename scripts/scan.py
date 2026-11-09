#!/usr/bin/env python3
"""Draft offline evidence collector. Reads inert text, never executes project code.

Not a pentest, complete secret scanner, or launch clearance. No third-party deps.
Output is deliberately outside the inspected tree and never overwritten.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = "0.1"
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_MATCHES = 200
MAX_SKIPPED = 200
MAX_LABEL_CHARS = 512
MAX_RESULT_BYTES = 4 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", ".next", "dist", "build", "coverage", "__pycache__"}
PATTERNS = (
    ("DATA-SECRET-SUPABASE", "high", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}\b")),
    ("DATA-SECRET-STRIPE-LIVE", "high", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("DATA-SECRET-STRIPE-TEST", "medium", re.compile(r"\bsk_test_[A-Za-z0-9]{16,}\b")),
    ("DATA-PRIVATE-KEY", "high", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")),
)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{1,2048}\.[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,2048}\b")
CONTROLS = (
    ("PAY-01", "payments", "Server-side pricing and entitlement decisions", "Confirm the server derives price and entitlement from trusted records; verify in Stripe test mode."),
    ("PAY-02", "payments", "Webhook authenticity and duplicate handling", "Inspect signature validation and replay handling; reproduce safely with synthetic test events."),
    ("AUTH-01", "auth", "Cross-account and cross-tenant access", "Use two authorized synthetic accounts in an isolated environment to test read and write isolation."),
    ("AUTH-02", "auth", "Administrative role assignment", "Inspect server-side role assignment and test that an ordinary test account cannot elevate privileges."),
    ("DATA-01", "data", "Deployed policies and storage access", "Compare current deployed policies and storage permissions with the intended access matrix."),
    ("DATA-02", "data", "Sensitive logging and credential exposure", "Review deployment secrets, generated browser bundles, logs and credential lifecycle; this scan covers limited source patterns only."),
    ("BACKUP-01", "backup", "Backup coverage and retention", "Obtain current backup configuration and identify which database and file assets it covers."),
    ("BACKUP-02", "backup", "Successful isolated restore", "Review a recent restore record or arrange an authorized restore into an isolated copy, never over production."),
    ("FAIL-01", "failure", "Timeout, retry and duplicate behavior", "Verify the two agreed workflows under controlled failure conditions in a test environment."),
    ("FAIL-02", "failure", "Alerting, rate limiting and rollback", "Inspect alert delivery, rate-limit configuration and a documented rollback plan; do not load-test production."),
)
LIMITATIONS = [
    "Internal draft: not professionally validated or a security certification.",
    "Static source inspection only; no live environment, payments, tenant access, backup restore or failure-mode testing.",
    "No match does not prove absence of secrets. Only a small set of credential-shaped patterns is checked.",
    "Credential-shaped matches are unverified candidates; validity, deployment and exposure are unknown until reviewed.",
    "Public anon/publishable keys are not treated as privileged secrets; their presence does not prove correct permissions.",
    "Ignored directories, symlinks, binary files and configured limits are outside coverage. No git history is inspected.",
    "A directory manifest identifies inspected bytes, not a production deployment or complete repository revision.",
    "Metadata labels longer than 512 characters are truncated; at most 200 exclusion records are retained, with omitted counts reported.",
    "The byte budget counts all file reads, including rejected content. Directory enumeration is not a strict memory sandbox; use a small, stable local snapshot.",
]


def is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def validate_output(path: Path, root: Path) -> Path:
    # Do not create parents or replace existing files, directories, or symlinks.
    if path.exists() or path.is_symlink():
        raise ValueError("Output already exists; choose a new path.")
    resolved = path.resolve()
    if is_within(resolved, root):
        raise ValueError("Output must be outside the scanned root.")
    if not resolved.parent.is_dir():
        raise ValueError("Output parent directory must already exist.")
    return resolved


def redact_label(value: str) -> str:
    # Also protect path/revision metadata, which can itself contain credentials.
    for _, _, pattern in PATTERNS:
        value = pattern.sub("[REDACTED]", value)
    value = JWT_PATTERN.sub("[REDACTED_TOKEN]", value)
    value = "".join(c if c.isprintable() else "_" for c in value)
    return value if len(value) <= MAX_LABEL_CHARS else value[:MAX_LABEL_CHARS - 16] + "[path truncated]"


def unknown_controls() -> list[dict]:
    return [{
        "rule_id": rid, "module": module, "severity": "undetermined", "status": "unknown",
        "evidence": [], "affected_flow": flow,
        "business_impact": "Not established from this static scan; relevant business risk remains unverified.",
        "recommendation": action, "retest": action,
    } for rid, module, flow, action in CONTROLS]


def credential_finding(rid: str, severity: str, path: str, line: int) -> dict:
    return {
        "rule_id": rid, "module": "data", "severity": severity, "status": "fail",
        "evidence": [{"path": redact_label(path), "line": line,
                      "summary": "Credential-shaped material detected [REDACTED]. Validity and exposure not verified."}],
        "affected_flow": "Credential handling in inspected source",
        "business_impact": "If real and accessible to an unauthorized party, this credential could grant unintended access. Deployment and scope are unknown.",
        "recommendation": "Have a qualified reviewer confirm whether this is a real secret or a fixture. If real, revoke/rotate it through the owner's provider, remove it from source, and investigate exposure. Never paste it into chat.",
        "retest": "Rescan the corrected snapshot, verify replacement credentials stay server-side, and separately confirm revocation with the owner. A source rescan cannot prove revocation.",
    }


def service_role_jwt(token: str) -> bool:
    try:
        payload = token.split(".")[1]
        value = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return isinstance(value, dict) and value.get("role") == "service_role"
    except (ValueError, UnicodeError, RecursionError):
        return False


def open_relative(root: Path, relative: Path) -> int:
    """Anchor every path component; do not follow swapped ancestor symlinks."""
    if relative.is_absolute() or any(part == ".." for part in relative.parts):
        raise ValueError("Invalid relative path.")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(root, directory_flags)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)


def collect(root: Path, revision: str | None = None) -> dict:
    findings = unknown_controls()
    skipped: list[dict] = []
    digest = hashlib.sha256()
    scanned = total = bytes_read = entries = matches = skipped_omitted = 0
    limited = False
    stopped = False

    def skip(path: Path, reason: str) -> None:
        nonlocal skipped_omitted
        if len(skipped) < MAX_SKIPPED:
            skipped.append({"path": redact_label(path.relative_to(root).as_posix()), "reason": reason})
        else:
            skipped_omitted += 1

    def walk_error(error: OSError) -> None:
        # Never echo exception messages (may contain sensitive names).
        nonlocal stopped
        stopped = True

    for directory, dirs, names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        current = Path(directory)
        # A fixed traversal bound also counts ignored entries and directories.
        keep = []
        for name in sorted(dirs):
            entries += 1
            if entries > MAX_ENTRIES:
                limited = True
                break
            path = current / name
            if path.is_symlink():
                skip(path, "symlink_not_followed")
            elif name in SKIP_DIRS:
                skip(path, "ignored_directory")
            else:
                keep.append(name)
        dirs[:] = keep
        if limited:
            break
        for name in sorted(names):
            entries += 1
            if entries > MAX_ENTRIES or matches >= MAX_MATCHES:
                limited = True
                break
            path = current / name
            rel = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    skip(path, "symlink_not_followed")
                    continue
                if not stat.S_ISREG(info.st_mode):
                    skip(path, "not_regular_file")
                    continue
                if info.st_size > MAX_FILE_BYTES:
                    skip(path, "file_size_limit")
                    continue
                if bytes_read + info.st_size > MAX_TOTAL_BYTES:
                    skip(path, "total_byte_limit")
                    limited = True
                    break
                # O_NOFOLLOW prevents a file symlink swap; opened files remain bounded.
                fd = open_relative(root, path.relative_to(root))
                with os.fdopen(fd, "rb") as handle:
                    opened = os.fstat(handle.fileno())
                    if not stat.S_ISREG(opened.st_mode):
                        skip(path, "not_regular_file")
                        continue
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        skip(path, "file_changed_during_scan")
                        stopped = True
                        continue
                    data = handle.read(min(MAX_FILE_BYTES + 1, MAX_TOTAL_BYTES - bytes_read + 1))
                bytes_read += len(data)
                if bytes_read > MAX_TOTAL_BYTES:
                    skip(path, "total_byte_limit")
                    limited = True
                    break
                if len(data) > MAX_FILE_BYTES:
                    skip(path, "file_size_limit")
                    continue
                if total + len(data) > MAX_TOTAL_BYTES:
                    skip(path, "total_byte_limit")
                    limited = True
                    break
                if b"\x00" in data:
                    skip(path, "binary_file")
                    continue
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    skip(path, "non_utf8_file")
                    continue
                digest.update(rel.encode("utf-8", errors="surrogateescape") + b"\0" + hashlib.sha256(data).digest())
                scanned += 1
                total += len(data)
                for rid, severity, pattern in PATTERNS:
                    for match in pattern.finditer(text):
                        if matches >= MAX_MATCHES:
                            limited = True
                            break
                        findings.append(credential_finding(rid, severity, rel, text.count("\n", 0, match.start()) + 1))
                        matches += 1
                for match in JWT_PATTERN.finditer(text):
                    if matches >= MAX_MATCHES:
                        limited = True
                        break
                    if service_role_jwt(match.group()):
                        findings.append(credential_finding("DATA-SECRET-SERVICE-ROLE", "high", rel, text.count("\n", 0, match.start()) + 1))
                        matches += 1
            except OSError:
                skip(path, "read_error")
                stopped = True
        if limited:
            break
    if skipped_omitted:
        limited = True
    if stopped or limited:
        findings.append({
            "rule_id": "SCAN-COVERAGE", "module": "data", "severity": "undetermined", "status": "tool_error",
            "evidence": [], "affected_flow": "Static scan coverage",
            "business_impact": "The collector could not inspect all eligible files. Results are incomplete.",
            "recommendation": "Review coverage exclusions, fix access problems or reduce the target to the agreed snapshot, then rescan.",
            "retest": "Repeat the collector and check coverage before interpreting results.",
        })
    counts = {status: sum(f["status"] == status for f in findings)
              for status in ("pass", "fail", "unknown", "not_applicable", "tool_error")}
    return {
        "schema_version": SCHEMA_VERSION, "mode": "static_only",
        "snapshot": {"root_label": redact_label(root.name), "revision_declared": redact_label(revision) if revision else None,
                     "manifest_sha256": digest.hexdigest(), "checked_at": datetime.now(timezone.utc).isoformat()},
        "coverage": {"files_scanned": scanned, "bytes_scanned": total, "bytes_read": bytes_read,
                     "skipped": skipped, "skipped_omitted": skipped_omitted, "limits_reached": limited},
        "findings": findings,
        "summary": {"decision": "static_blockers_found" if counts["fail"] else "insufficient_evidence",
                    "counts": counts, "limitations": LIMITATIONS},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--revision", help="Optional owner-declared revision; not verified by this tool.")
    args = parser.parse_args()
    try:
        root = args.root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("Root must be a directory.")
        output = validate_output(args.output, root)
        result = collect(root, args.revision)
        content = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
        if len(content.encode("utf-8")) > MAX_RESULT_BYTES:
            raise ValueError("Result exceeds size budget.")
        with output.open("x", encoding="utf-8") as handle:
            handle.write(content)
        print("Draft static collection complete. Inspect coverage and unknowns; this is not launch clearance.")
        return 0
    except (OSError, ValueError):
        # Do not print raw paths, project content, credentials, or arbitrary exceptions.
        print("Collection refused or failed. Check root accessibility and choose a new output outside the inspected root with an existing parent.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
