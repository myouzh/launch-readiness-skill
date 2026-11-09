#!/usr/bin/env python3
"""Deterministic offline review inventory of an authorized, stable source snapshot.

Reads inert bytes once: no target imports, commands, dependency scripts or network.
Nominations are review starting points, not traced chains, vulnerabilities or passes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import scan

MAX_FILE_BYTES = scan.MAX_FILE_BYTES
MAX_TOTAL_BYTES = scan.MAX_TOTAL_BYTES
MAX_ENTRIES = scan.MAX_ENTRIES
MAX_SKIPPED = scan.MAX_SKIPPED
MAX_RESULT_BYTES = 1024 * 1024
MAX_ANCHORS = 300
MAX_DEPTH = 64
SKIP_DIRS = scan.SKIP_DIRS
SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rs", ".java", ".rb", ".php", ".cs", ".sql", ".prisma", ".sh"}
DEPENDENCIES = {
    "express": "Express", "fastify": "Fastify", "next": "Next.js",
    "react": "React", "vue": "Vue", "@nestjs/core": "NestJS",
    "@prisma/client": "Prisma", "prisma": "Prisma",
    "@supabase/supabase-js": "Supabase client", "stripe": "Stripe SDK",
    "pg": "PostgreSQL client", "mongoose": "Mongoose",
    "@aws-sdk/client-s3": "S3 client", "passport": "Passport",
}
# Fixed descriptions only. Matched code, identifiers and values never leave memory.
SIGNALS = {
    "auth": r"\b(?:passport|authenticate|requireAuth|authMiddleware|verifyToken)\s*(?:\.|\()|\b(?:getUser|getSession)\s*\(",
    "routes": r"\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete|use|route)\s*\(|\b(?:APIRouter|urlpatterns)\b|\b(?:GET|POST|PUT|DELETE)\s*\(",
    "data": r"\b(?:prisma|mongoose)\s*\.|\b(?:SELECT|INSERT INTO|CREATE TABLE)\b|\b(?:model|datasource)\s+\w+\s*\{",
    "storage": r"\b(?:storage|s3)\s*\.|\b(?:PutObjectCommand|GetObjectCommand|upload_file)\s*\(",
    "backup": r"\b(?:pg_dump|pg_restore|mongodump|sqlite3_backup|backup_database)\b",
    "error": r"\b(?:onError|errorHandler|setErrorHandler)\s*\(|\bexcept\b|\bcatch\s*\(",
    "tests": r"\b(?:describe|test|it)\s*\(|\bdef\s+test_",
}
PATTERNS = {key: re.compile(value) for key, value in SIGNALS.items()}
CATEGORIES = ("entrypoints", "auth", "routes", "data", "storage", "deployment", "migrations", "backup", "error", "tests")
LIMITATIONS = [
    "Context inventory only: candidate entrypoints are not a traced execution or critical chain.",
    "Indicators suggest technologies; missing indicators do not prove absence or non-applicability.",
    "No vulnerability, safety, pass or launch-readiness determination; deployment and behavior remain unknown.",
    "Only bounded UTF-8 local files are inspected; docs are not treated as implementation evidence.",
    "Manifest hashes accepted bytes and relative paths in deterministic traversal order, not a verified revision or deployed state.",
    "Single read pass; each anchor hash identifies those same bytes. Concurrent changes may invalidate snapshot coherence; use an immutable authorized snapshot.",
    "Path labels use scan.redact_label and may be redacted/truncated; hashes disambiguate content, not hidden names.",
]


def dependency_locations(text: str) -> dict[tuple[str, str], int]:
    """Locate actual dependency key tokens, not lookalikes in scripts or values.

    Called only after JSON shape validation. raw_decode skips inert values without
    interpreting them; duplicate sections/keys follow JSON's last-value behavior.
    """
    decoder = json.JSONDecoder()

    def whitespace(pos: int) -> int:
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        return pos

    def members(pos: int):
        pos = whitespace(pos + 1)
        while text[pos] != "}":
            key_start = pos
            key, pos = decoder.raw_decode(text, pos)
            pos = whitespace(pos)
            value_start = whitespace(pos + 1)  # colon
            value, end = decoder.raw_decode(text, value_start)
            yield key, key_start, value_start, value
            pos = whitespace(end)
            if text[pos] == ",":
                pos = whitespace(pos + 1)
            else:
                break

    sections = {}
    for section, _, start, value in members(whitespace(0)):
        sections[section] = (start, value)
    result = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        if section not in sections or not isinstance(sections[section][1], dict):
            continue
        for dep, start, _, _ in members(sections[section][0]):
            if dep in DEPENDENCIES:
                result[(section, dep)] = text.count("\n", 0, start) + 1
    return result


def open_directory(path: Path) -> int:
    """Pin an absolute directory, rejecting symlinks in every component."""
    path = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def output_parent(output: Path, root: Path) -> tuple[int, str]:
    output = Path(os.path.abspath(output))
    if scan.is_within(output, root):
        raise ValueError("Output must be outside root.")
    fd = open_directory(output.parent)
    try:
        # Also reject filesystem aliases (for example case-insensitive paths).
        root_fd = open_directory(root)
        try:
            root_info = os.fstat(root_fd)
        finally:
            os.close(root_fd)
        ancestor = os.dup(fd)
        try:
            while True:
                info = os.fstat(ancestor)
                identity = (info.st_dev, info.st_ino)
                if identity == (root_info.st_dev, root_info.st_ino):
                    raise ValueError("Output must be outside root.")
                parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=ancestor)
                parent_info = os.fstat(parent)
                os.close(ancestor)
                ancestor = parent
                if identity == (parent_info.st_dev, parent_info.st_ino):
                    break
        finally:
            os.close(ancestor)
        try:
            os.stat(output.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return fd, output.name
        raise ValueError("Output must be unused.")
    except BaseException:
        os.close(fd)
        raise


def collect(root: Path) -> dict:
    """Read one bounded snapshot; never call scan.collect or reread anchor files."""
    root = Path(os.path.abspath(root))
    root_fd = open_directory(root)
    digest = hashlib.sha256()
    coverage = {"files_scanned": 0, "bytes_scanned": 0, "bytes_read": 0,
                "entries_seen": 0, "skipped": [], "skipped_omitted": 0,
                "limits_reached": False, "read_errors": 0, "anchors_omitted": 0, "labels_truncated": 0}
    anchors = {name: [] for name in CATEGORIES}
    stacks: dict[str, list] = {}
    anchor_count = 0

    def label(value: str) -> str:
        redacted = scan.redact_label(value)
        if redacted.endswith("[path truncated]"):
            coverage["labels_truncated"] += 1
        return redacted

    def skip(rel: str, reason: str) -> None:
        if len(coverage["skipped"]) < MAX_SKIPPED:
            coverage["skipped"].append({"path": label(rel), "reason": reason})
        else:
            coverage["skipped_omitted"] += 1
            coverage["limits_reached"] = True

    def evidence(rel: str, line: int, sha: str, reason: str) -> dict:
        return {"path": label(rel), "line": line, "file_sha256": sha, "basis": reason}

    def nominate(category: str, rel: str, line: int, sha: str, basis: str) -> None:
        nonlocal anchor_count
        if anchor_count >= MAX_ANCHORS:
            coverage["anchors_omitted"] += 1
            coverage["limits_reached"] = True
            return
        anchors[category].append(evidence(rel, line, sha, basis))
        anchor_count += 1

    def stack(name: str, rel: str, line: int, sha: str, basis: str) -> None:
        # A fixed vocabulary and at most three anchors per technology bound metadata.
        found = stacks.setdefault(name, [])
        if len(found) < 3:
            found.append(evidence(rel, line, sha, basis))
        else:
            coverage["anchors_omitted"] += 1
            coverage["limits_reached"] = True

    def inspect(rel: str, text: str, sha: str) -> None:
        path = Path(rel)
        name = path.name.lower()
        parts = {part.lower() for part in path.parts[:-1]}
        docs = bool(parts & {"docs", "documentation", "examples", "fixtures", "__fixtures__"})
        if name == "package.json" and not docs:
            try:
                manifest = json.loads(text)
            except (ValueError, RecursionError):
                skip(rel, "invalid_manifest_json")
                return
            if not isinstance(manifest, dict):
                skip(rel, "invalid_manifest_shape")
                return
            locations = dependency_locations(text)
            # Examine dependency keys only, never scripts, versions or arbitrary values.
            for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                deps = manifest.get(section, {})
                if not isinstance(deps, dict):
                    continue
                for dep in sorted(set(deps) & DEPENDENCIES.keys()):
                    line = locations[(section, dep)]
                    stack(DEPENDENCIES[dep], rel, line, sha, "dependency name in inert package manifest (may be development-only)")
        if docs:
            return
        languages = {"pyproject.toml": "Python", "requirements.txt": "Python", "setup.py": "Python",
                     "go.mod": "Go", "cargo.toml": "Rust", "gemfile": "Ruby", "composer.json": "PHP"}
        if name in languages:
            stack(languages[name], rel, 1, sha, "language manifest filename; dependencies not executed")
        if name == "schema.prisma" and "prisma" in parts:
            stack("Prisma", rel, 1, sha, "conventional Prisma schema path; use unverified")
        if name == "config.toml" and path.parent.name.lower() == "supabase":
            stack("Supabase project layout", rel, 1, sha, "conventional Supabase project configuration path; deployment unknown")
        if name in {"dockerfile", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml", "vercel.json", "netlify.toml", "fly.toml", "wrangler.toml", "wrangler.json", "wrangler.jsonc"} or (".github" in parts and "workflows" in parts and path.suffix in {".yml", ".yaml"}):
            nominate("deployment", rel, 1, sha, "deployment configuration filename; values not exported")
        if path.suffix.lower() not in SOURCE_SUFFIXES:
            return
        if not text.strip():
            return
        is_test = bool(parts & {"test", "tests", "__tests__"}) or name.startswith("test_") or bool(re.search(r"\.(?:test|spec)\.", name))
        if name in {"server.js", "server.ts", "app.py", "main.py", "main.go", "main.rs", "manage.py"}:
            nominate("entrypoints", rel, 1, sha, "conventional source entrypoint filename; execution unverified")
        if "migrations" in parts and path.suffix.lower() in {".sql", ".py", ".js", ".ts", ".rb"}:
            nominate("migrations", rel, 1, sha, "migration-directory source file; application unverified")
        for category, pattern in PATTERNS.items():
            if category == "tests" and not is_test:
                continue
            if is_test and category != "tests":
                continue
            for line, value in enumerate(text.splitlines(), 1):
                # Skip obvious comment-only lines; lexical candidates still need human review.
                if value.lstrip().startswith(("//", "#", "*", "--")):
                    continue
                if pattern.search(value):
                    nominate(category, rel, line, sha, "implementation-shaped lexical candidate; not semantic proof")
                    break

    def walk(fd: int, prefix: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            skip(prefix, "depth_limit")
            coverage["limits_reached"] = True
            return
        entries = []
        try:
            with os.scandir(fd) as iterator:
                for entry in iterator:
                    if coverage["entries_seen"] >= MAX_ENTRIES:
                        coverage["limits_reached"] = True
                        skip(prefix or ".", "entry_limit")
                        return  # Partial enumeration is deliberately not processed.
                    coverage["entries_seen"] += 1
                    entries.append(entry.name)
        except OSError:
            coverage["read_errors"] += 1
            skip(prefix or ".", "directory_read_error")
            return
        for name in sorted(entries):
            rel = prefix + "/" + name if prefix else name
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    skip(rel, "symlink_not_followed")
                elif stat.S_ISDIR(info.st_mode):
                    if name in SKIP_DIRS:
                        skip(rel, "ignored_directory")
                        continue
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        opened = os.fstat(child)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            skip(rel, "directory_changed_during_inventory")
                            coverage["read_errors"] += 1
                        else:
                            walk(child, rel, depth + 1)
                    finally:
                        os.close(child)
                elif not stat.S_ISREG(info.st_mode):
                    skip(rel, "not_regular_file")
                elif info.st_size > MAX_FILE_BYTES:
                    skip(rel, "file_size_limit")
                    coverage["limits_reached"] = True
                elif coverage["bytes_read"] + info.st_size > MAX_TOTAL_BYTES:
                    skip(rel, "total_byte_limit")
                    coverage["limits_reached"] = True
                else:
                    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    with os.fdopen(file_fd, "rb") as handle:
                        before = os.fstat(handle.fileno())
                        if not stat.S_ISREG(before.st_mode) or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                            skip(rel, "file_changed_during_inventory")
                            coverage["read_errors"] += 1
                            continue
                        data = handle.read(min(MAX_FILE_BYTES + 1, MAX_TOTAL_BYTES - coverage["bytes_read"]))
                        after = os.fstat(handle.fileno())
                    coverage["bytes_read"] += len(data)
                    if len(data) > MAX_FILE_BYTES or len(data) != after.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                        skip(rel, "file_changed_or_size_limit")
                        coverage["read_errors"] += 1
                        coverage["limits_reached"] = True
                        continue
                    if b"\x00" in data:
                        skip(rel, "binary_file")
                        continue
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        skip(rel, "non_utf8_file")
                        continue
                    sha = hashlib.sha256(data).hexdigest()
                    digest.update(rel.encode("utf-8", errors="surrogateescape") + b"\x00" + bytes.fromhex(sha))
                    coverage["files_scanned"] += 1
                    coverage["bytes_scanned"] += len(data)
                    inspect(rel, text, sha)
            except OSError:
                coverage["read_errors"] += 1
                skip(rel, "read_error")
    try:
        walk(root_fd, "", 0)
    finally:
        os.close(root_fd)
    return {"schema_version": "0.1", "mode": "offline_context_inventory",
            "snapshot": {"root_label": label(root.name), "manifest_sha256": digest.hexdigest(),
                         "manifest_algorithm": "sha256(relative-path + NUL + binary-file-sha256), sorted depth-first single pass"},
            "coverage": coverage,
            "likely_stacks": [{"name": name, "evidence": stacks[name]} for name in sorted(stacks)],
            "review_entrypoints": anchors, "limitations": LIMITATIONS}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="Authorized stable local snapshot only")
    parser.add_argument("--output", type=Path, required=True, help="Unused JSON path outside root")
    args = parser.parse_args()
    parent_fd = None
    try:
        root = Path(os.path.abspath(args.root))
        # Validate before any inventory; pin output ancestors to prevent symlink swaps.
        root_fd = open_directory(root)
        os.close(root_fd)
        parent_fd, name = output_parent(args.output, root)
        result = collect(root)
        content = (json.dumps(result, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        if len(content) > MAX_RESULT_BYTES:
            raise ValueError("Result size budget exceeded.")
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent_fd)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        print("Offline context inventory written; inspect coverage and verify nominated entrypoints manually.")
        return 0
    except (OSError, ValueError, RecursionError):
        print("Inventory refused or failed. Use an accessible authorized snapshot and unused output outside root without symlink components.", file=sys.stderr)
        return 2
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


if __name__ == "__main__":
    raise SystemExit(main())
