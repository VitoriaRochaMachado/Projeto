"""Analisa as primeiras linhas de um dump de hashes e mede a vazão."""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from hash_identifier import identify


@dataclass(frozen=True, slots=True)
class DumpStats:
    """Resumo serializável da análise de um dump."""

    processed: int
    identified: int
    algorithms: dict[str, int]
    elapsed_seconds: float
    hashes_per_second: float


def extract_hash(line: str) -> str:
    """Extrai o hash de uma linha HIBP no formato ``HASH:CONTAGEM``."""
    return line.strip().split(":", 1)[0]


def analyze_dump(path: Path, limit: int = 1000) -> DumpStats:
    """Identifica até ``limit`` linhas e devolve métricas agregadas."""
    if limit <= 0:
        raise ValueError("limit deve ser maior que zero")

    processed = 0
    identified = 0
    algorithms: Counter[str] = Counter()
    started = time.perf_counter()

    with path.open(encoding="utf-8", errors="replace") as dump_file:
        for line in dump_file:
            if processed >= limit:
                break

            hash_value = extract_hash(line)
            if not hash_value:
                continue

            processed += 1
            candidates = identify(hash_value)
            if candidates:
                identified += 1
                algorithms[candidates[0].algorithm] += 1

    elapsed = time.perf_counter() - started
    throughput = processed / elapsed if elapsed > 0 else 0.0
    return DumpStats(
        processed=processed,
        identified=identified,
        algorithms=dict(algorithms),
        elapsed_seconds=elapsed,
        hashes_per_second=throughput,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path, help="Arquivo de dump a analisar")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    """Executa a análise pela linha de comando."""
    args = _build_parser().parse_args()
    stats = analyze_dump(args.dump, args.limit)

    if args.json:
        print(json.dumps(asdict(stats), ensure_ascii=False, indent=2))
    else:
        print(f"Processados: {stats.processed}")
        print(f"Identificados: {stats.identified}")
        print(f"Algoritmos: {stats.algorithms}")
        print(f"Tempo: {stats.elapsed_seconds:.6f}s")
        print(f"Vazão: {stats.hashes_per_second:.2f} hashes/s")

    return 0 if stats.processed > 0 and stats.identified == stats.processed else 1


if __name__ == "__main__":
    raise SystemExit(main())
