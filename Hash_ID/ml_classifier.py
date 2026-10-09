"""Experimento de classificação probabilística de formatos de hash.

O módulo gera amostras rotuladas a partir de senhas sintéticas, treina uma
regressão logística sobre n-gramas de caracteres e compara sua acurácia com o
identificador estrutural baseado em regras.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import string
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import joblib
import bcrypt
from argon2 import PasswordHasher
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

from hash_identifier import identify

ALGORITHMS = ("md5", "sha1", "sha256", "sha512", "bcrypt", "argon2id")
LABEL_TO_RULE = {
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "bcrypt": "bcrypt",
    "argon2id": "Argon2id",
}


@dataclass(frozen=True, slots=True)
class TrainingMetrics:
    """Métricas reproduzíveis da separação de teste."""

    total_samples: int
    test_samples: int
    ml_accuracy: float
    rule_accuracy: float


def _random_password(generator: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#_-"
    length = generator.randint(8, 20)
    return "".join(generator.choice(alphabet) for _ in range(length))


def iter_samples(count: int, seed: int = 42) -> Iterator[tuple[str, str]]:
    """Produz ``(label, hash)`` usando algoritmos reais e senhas sintéticas."""
    if count <= 0:
        raise ValueError("count deve ser maior que zero")

    generator = random.Random(seed)
    argon2_hasher = PasswordHasher(
        time_cost=1,
        memory_cost=1024,
        parallelism=1,
        hash_len=16,
        salt_len=8,
    )

    for index in range(count):
        label = ALGORITHMS[index % len(ALGORITHMS)]
        password = _random_password(generator)
        encoded = password.encode()

        if label == "md5":
            value = hashlib.md5(encoded, usedforsecurity=False).hexdigest()
        elif label == "sha1":
            value = hashlib.sha1(encoded, usedforsecurity=False).hexdigest()
        elif label == "sha256":
            value = hashlib.sha256(encoded).hexdigest()
        elif label == "sha512":
            value = hashlib.sha512(encoded).hexdigest()
        elif label == "bcrypt":
            value = bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=4)).decode()
        else:
            value = argon2_hasher.hash(password)

        yield label, value


def write_dataset(
    output: Path,
    count: int = 100_000,
    seed: int = 42,
) -> dict[str, int]:
    """Escreve um CSV rotulado e retorna a distribuição das classes."""
    output.parent.mkdir(parents=True, exist_ok=True)
    distribution = dict.fromkeys(ALGORITHMS, 0)

    with output.open("w", newline="", encoding="utf-8") as dataset:
        writer = csv.writer(dataset)
        writer.writerow(["label", "hash"])
        for label, value in iter_samples(count, seed):
            writer.writerow([label, value])
            distribution[label] += 1

    return distribution


def _read_dataset(path: Path) -> tuple[list[str], list[str]]:
    labels: list[str] = []
    values: list[str] = []
    with path.open(encoding="utf-8", newline="") as dataset:
        for row in csv.DictReader(dataset):
            labels.append(row["label"])
            values.append(row["hash"])
    if not values:
        raise ValueError("dataset vazio")
    return values, labels


def _rule_accuracy(values: list[str], labels: list[str]) -> float:
    correct = 0
    for value, label in zip(values, labels, strict=True):
        candidates = identify(value)
        if candidates and candidates[0].algorithm == LABEL_TO_RULE[label]:
            correct += 1
    return correct / len(values)


def _add_length_token(values: Any) -> list[str]:
    """Preserva explicitamente o comprimento antes da extração de n-gramas."""
    return [f"__LEN_{len(str(value))}__{value}" for value in values]


def train_model(
    dataset_path: Path,
    model_path: Path,
    random_state: int = 42,
) -> TrainingMetrics:
    """Treina, avalia e salva um Pipeline TF-IDF + regressão logística."""
    values, labels = _read_dataset(dataset_path)
    train_values, test_values, train_labels, test_labels = train_test_split(
        values,
        labels,
        test_size=0.2,
        random_state=random_state,
        stratify=labels,
    )

    model: Any = Pipeline([
        (
            "length_token",
            FunctionTransformer(_add_length_token, validate=False),
        ),
        (
            "features",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(1, 4),
                min_df=1,
                norm=None,
                use_idf=False,
            ),
        ),
        (
            "classifier",
            LogisticRegression(max_iter=1000, random_state=random_state),
        ),
    ])
    model.fit(train_values, train_labels)
    predictions = model.predict(test_values)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    return TrainingMetrics(
        total_samples=len(values),
        test_samples=len(test_values),
        ml_accuracy=float(accuracy_score(test_labels, predictions)),
        rule_accuracy=_rule_accuracy(test_values, test_labels),
    )


def predict_hash(model_path: Path, value: str) -> tuple[str, float]:
    """Carrega o modelo e retorna classe e probabilidade da melhor previsão."""
    model: Any = joblib.load(model_path)
    label = str(model.predict([value])[0])
    probabilities = model.predict_proba([value])[0]
    probability = float(max(probabilities))
    return label, probability


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="gera o CSV rotulado")
    generate.add_argument("--output",
                          type=Path,
                          default=Path("data/hash_samples.csv"))
    generate.add_argument("--samples", type=int, default=100_000)
    generate.add_argument("--seed", type=int, default=42)

    train = subparsers.add_parser("train", help="treina e avalia o modelo")
    train.add_argument("--input",
                       type=Path,
                       default=Path("data/hash_samples.csv"))
    train.add_argument("--model",
                       type=Path,
                       default=Path("models/hash_classifier.joblib"))

    predict = subparsers.add_parser("predict", help="classifica uma entrada")
    predict.add_argument("value")
    predict.add_argument("--model",
                         type=Path,
                         default=Path("models/hash_classifier.joblib"))
    return parser


def main() -> int:
    """Ponto de entrada dos três estágios do experimento."""
    args = _build_parser().parse_args()

    if args.command == "generate":
        distribution = write_dataset(args.output, args.samples, args.seed)
        print(
            json.dumps({
                "output": str(args.output),
                "classes": distribution
            },
                       indent=2))
        return 0

    if args.command == "train":
        metrics = train_model(args.input, args.model)
        print(json.dumps(asdict(metrics), indent=2))
        return 0

    label, probability = predict_hash(args.model, args.value)
    print(json.dumps({"label": label, "probability": probability}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
