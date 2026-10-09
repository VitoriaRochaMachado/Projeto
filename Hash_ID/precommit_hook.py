"""Hook que bloqueia hashes de alta confiança em arquivos alterados."""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

from hash_identifier import identify

ALLOW_MARKER = "# pragma: allow-hash"
TOKEN_PATTERN = re.compile(r"(?:\$[A-Za-z0-9_-]+\$[^\s'\"`]+|\*[A-F0-9]{40}\b|"
                           r"\b[0-9A-Fa-f]{16,128}\b)")


@dataclass(frozen=True, slots=True)
class Finding:
    """Hash de alta confiança encontrado em um arquivo."""

    path: Path
    line_number: int
    value: str
    algorithm: str


def scan_file(path: Path) -> list[Finding]:
    """Retorna achados de alta confiança, respeitando a allowlist por linha."""
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return findings

    for line_number, line in enumerate(lines, start=1):
        if ALLOW_MARKER in line:
            continue

        for value in TOKEN_PATTERN.findall(line):
            candidates = identify(value.strip(".,;:()[]{}"))
            if not candidates:
                continue

            best = candidates[0]
            if best.confidence_score > 0.8 and "não é" not in best.algorithm.lower(
            ):
                findings.append(
                    Finding(path, line_number, value, best.algorithm))

    return findings


def main(argv: list[str] | None = None) -> int:
    """Verifica os arquivos recebidos pelo pre-commit."""
    filenames = (argv if argv is not None else sys.argv[1:])
    findings = [
        finding for filename in filenames
        for finding in scan_file(Path(filename))
    ]

    for finding in findings:
        print(f"{finding.path}:{finding.line_number}: possível "
              f"{finding.algorithm} encontrado: {finding.value}")

    if findings:
        print(f"Use `{ALLOW_MARKER}` apenas para fixtures intencionais.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
