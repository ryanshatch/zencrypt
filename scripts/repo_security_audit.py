#!/usr/bin/env python3
"""Lightweight repository exposure scanner for Zencrypt.

This script checks tracked files for:
1) High-risk filenames that should not be committed.
2) Potential hard-coded secrets by regex pattern.
3) Large binary/archive artifacts that increase attack surface.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BLOCKED_NAME_PATTERNS = [
    re.compile(r"(^|/)\.env($|\.)"),
    re.compile(r"(^|/)id_rsa(\.pub)?$"),
    re.compile(r"(^|/).*\.(pem|p12|pfx|jks|key)$", re.IGNORECASE),
    re.compile(r"(^|/).*\.(db|sqlite|sqlite3)$", re.IGNORECASE),
]

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
    re.compile(r"(?i)(secret|api[_-]?key|token|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{20,}"),
    re.compile(r"ghp_[0-9A-Za-z]{36}"),
]

BINARY_EXTENSIONS = {".7z", ".zip", ".tar", ".gz", ".gpg", ".jpg", ".jpeg", ".png", ".mp4"}
MAX_BINARY_SIZE = 10 * 1024 * 1024


def git_tracked_files() -> list[Path]:
    output = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True)
    return [ROOT / line for line in output.splitlines() if line.strip()]


def is_text_file(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            sample = f.read(2048)
        if b"\x00" in sample:
            return False
        sample.decode("utf-8")
        return True
    except Exception:
        return False


def scan() -> int:
    findings: list[str] = []
    warnings: list[str] = []
    for path in git_tracked_files():
        rel = path.relative_to(ROOT).as_posix()

        for pattern in BLOCKED_NAME_PATTERNS:
            if pattern.search(rel):
                findings.append(f"[blocked-name] {rel}")
                break

        if path.suffix.lower() in BINARY_EXTENSIONS:
            try:
                size = path.stat().st_size
                if size > MAX_BINARY_SIZE:
                    warnings.append(
                        f"[large-binary] {rel} ({size / (1024*1024):.1f} MB)"
                    )
            except FileNotFoundError:
                continue

        if is_text_file(path):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for pattern in SECRET_PATTERNS:
                if pattern.search(content):
                    findings.append(f"[possible-secret] {rel} :: {pattern.pattern}")
                    break

    if findings:
        print("Repository security audit found blocking issues:")
        for finding in findings:
            print(f" - {finding}")
        if warnings:
            print("\nAdditional warnings:")
            for warning in warnings:
                print(f" - {warning}")
        return 1

    if warnings:
        print("Repository security audit passed with warnings:")
        for warning in warnings:
            print(f" - {warning}")
        return 0

    print("Repository security audit passed: no high-confidence exposures found.")
    return 0


if __name__ == "__main__":
    sys.exit(scan())
