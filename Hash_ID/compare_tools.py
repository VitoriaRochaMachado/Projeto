"""Compara o Hash_ID com hashid e Name-That-Hash nas mesmas entradas."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path

from hash_identifier import identify

DEFAULT_SAMPLES = [
    "5f4dcc3b5aa765d61d8327deb882cf99",
    "a" * 40,
    "a" * 64,
    "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G",
    "https://example.com/login",
]


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Resultado de uma ferramenta para uma entrada."""

    sample: str
    tool: str
    available: bool
    output: str


def _run_external(command: list[str], sample: str) -> ToolResult:
    executable = command[0]
    resolved = shutil.which(executable)
    if resolved is None:
        return ToolResult(sample, executable, False, "não instalado")

    # O ponto de entrada deste projeto também se chama ``hashid``. Sem esta
    # verificação, uma comparação executada dentro do venv chamaria o próprio
    # Hash_ID duas vezes e apresentaria a segunda execução como ferramenta
    # externa. Launchers gerados pelo uv são scripts de texto; binários ou
    # arquivos sem permissão simplesmente seguem para a execução normal.
    if executable == "hashid":
        try:
            launcher = Path(resolved).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            launcher = ""
        if "from hash_identifier import main" in launcher:
            return ToolResult(
                sample,
                executable,
                False,
                "HashID externo não instalado (nome ocupado pela CLI local)",
            )

    completed = subprocess.run(
        [resolved, *command[1:], sample],
        capture_output=True,
        check=False,
        text=True,
        timeout=15,
    )
    output = (completed.stdout or completed.stderr).strip()
    return ToolResult(sample, executable, True, output)


def compare_sample(sample: str) -> list[ToolResult]:
    """Executa as ferramentas disponíveis sobre uma única amostra."""
    candidates = identify(sample)
    own_output = (", ".join(
        f"{candidate.algorithm} ({candidate.confidence_score:.2f})"
        for candidate in candidates) if candidates else "sem identificação")
    return [
        ToolResult(sample, "Hash_ID", True, own_output),
        _run_external(["hashid"], sample),
        _run_external(["nth", "--text"], sample),
    ]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", nargs="*", default=DEFAULT_SAMPLES)
    parser.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    """Executa a comparação e informa ferramentas externas ausentes."""
    args = _build_parser().parse_args()
    results = [
        result for sample in args.samples for result in compare_sample(sample)
    ]

    if args.json:
        print(json.dumps([asdict(result) for result in results], indent=2))
    else:
        for result in results:
            status = "ok" if result.available else "indisponível"
            print(
                f"[{status}] {result.tool} | {result.sample} | {result.output}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
