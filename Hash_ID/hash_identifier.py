"""
©AngelaMos | 2026
Copyright (C) 2026 Murilo Miacci
hash_identifier.py

Identifica que tipo de hash uma string é, inspecionando seu formato.

Quando alguém lhe entrega uma string de caracteres aleatórios como
`5f4dcc3b5aa765d61d8327deb882cf99` ou `$2b$12$EixZaYVK1fsbw1ZfbX3OXe...`,
a primeira pergunta é: qual algoritmo a produziu? Você NÃO pode quebrar
ou analisar um hash sem saber qual "sabor" de hash está olhando. Toda
ferramenta de quebra — hashcat, john the ripper — precisa que você
especifique um algoritmo antes de começar.

Este script faz a parte da observação. Dada uma string de hash, ele retorna
candidatos classificados com uma pontuação de confiança e um motivo curto.

────────────────────────────────────────────────────────────────────
Como a identificação realmente funciona
────────────────────────────────────────────────────────────────────
Não há mágica aqui. Strings de hash carregam pistas de formato:

  1. PREFIXO. Muitos hashes modernos são armazenados no "formato de string PHC" —
     um formato autodescritivo que começa com um marcador como `$2b$`
     (bcrypt) ou `$argon2id$` (Argon2id). Quando vemos um prefixo
     conhecido, sabemos o algoritmo com ALTA confiança.

  2. COMPRIMENTO. A saída hexadecimal bruta de uma função de hash tem sempre o
     mesmo comprimento: MD5 produz 16 bytes = 32 caracteres hex; SHA-1 produz 20
     bytes = 40 caracteres hex; SHA-256 produz 32 bytes = 64 caracteres hex,
     e assim por diante. O comprimento por si só estreita o campo.

  3. CONJUNTO DE CARACTERES (CHARSET). Diferentes formatos usam diferentes alfabetos.
     Hashes hexadecimais usam apenas 0-9 e a-f. Base64 usa 0-9, A-Z, a-z, +, /, e =.
     Uma string com `+` nela não é um hash hexadecimal.

Portanto, nosso algoritmo é: tentar regras de prefixo primeiro, recorrer a regras
de comprimento + charset, e retornar os candidatos classificados por confiança.

────────────────────────────────────────────────────────────────────
O que este script pode e não pode fazer
────────────────────────────────────────────────────────────────────
PODE:    sugerir algoritmos prováveis para um hash que você encontrou.
NÃO PODE: dizer qual é a senha que originou o hash.
          (isso é trabalho do hashcat — veja ../../beginner/hash-cracker)

────────────────────────────────────────────────────────────────────
O que este arquivo expõe
────────────────────────────────────────────────────────────────────
  HashCandidate          — um palpite classificado (algoritmo, confiança, motivo)
  identify(text)         — retorna candidatos classificados para uma string de hash
  main()                 — ponto de entrada da CLI usado por `hashid <hash>`
"""

# Biblioteca padrão: analisa flags de linha de comando como `--top 3` em um
# objeto amigável para não termos que fatiar `sys.argv` manualmente.
import argparse

# Biblioteca padrão: serializa os resultados para a saída --json.
import json

# Biblioteca padrão: expressões regulares ajudam a interpretar registros
# compostos e parâmetros de bcrypt / Argon2.
import re

# Biblioteca padrão: acesso a internos do interpretador — usamos para
# escrever no stderr e sair do processo com um código de status específico.
import sys

# Biblioteca padrão: um decorador que transforma uma classe em um registro de
# dados pequeno e imutável sem escrever código repetitivo de `__init__`.
from dataclasses import asdict, dataclass

# Biblioteca padrão: representa com segurança o caminho passado para --file.
from pathlib import Path

# Biblioteca padrão: uma dica de tipo que fixa um valor a um pequeno conjunto
# fixo de strings (aqui: "high", "medium", "low"). O Mypy captura erros de digitação.
from typing import Literal

# Terceiros (rich): o impressor que desenha a tabela no terminal,
# com suporte a cores e Unicode.
from rich.console import Console

# Terceiros (rich): constrói a tabela ASCII colorida que imprimimos para
# os candidatos a hash classificados.
from rich.table import Table

# =============================================================================
# Tipo de Confiança — apenas três valores válidos
# =============================================================================
# Literal["high", "medium", "low"] é uma dica de tipo que diz "esta string
# pode ser APENAS um destes três valores". O Mypy pegará erros como "hgih"
# em tempo de edição. Escolhemos Literal em vez de Enum porque prefiro
# Literals para conjuntos fixos pequenos.

Confidence = Literal["high", "medium", "low"]
CrackDifficulty = Literal["trivial", "moderate", "hard", "very_hard"]
FieldType = Literal["username", "hash", "salt", "garbage"]

# =============================================================================
# Modos Hashcat — dica prática para o próximo passo
# =============================================================================
# Nem todo candidato possui um modo direto no hashcat. Quando não houver uma
# correspondência segura, o campo hashcat_mode permanece None.

HASHCAT_MODES: dict[str, int] = {
    "MD5": 0,
    "SHA-1": 100,
    "MySQL323": 200,
    "MySQL5": 300,
    "phpass": 400,
    "MD5 crypt": 500,
    "MD4": 900,
    "NTLM": 1000,
    "SHA-224": 1300,
    "SHA-256": 1400,
    "DES crypt": 1500,
    "Apache MD5-crypt": 1600,
    "SHA-512": 1700,
    "SHA-512 crypt": 1800,
    "bcrypt": 3200,
    "NetNTLMv1": 5500,
    "NetNTLMv2": 5600,
    "RIPEMD-160": 6000,
    "SHA-256 crypt": 7400,
    "Drupal 7 (SHA-512)": 7900,
    "scrypt": 8900,
    "SHA-384": 10800,
    "SHA3-224": 17300,
    "SHA3-256": 17400,
    "SHA3-384": 17500,
    "SHA3-512": 17600,
    "Argon2id": 34000,
    "Argon2i": 34000,
    "Argon2d": 34000,
}

# Estimativa estrutural, não uma promessa de tempo de quebra. O hardware, a
# qualidade da senha, o salt e os parâmetros do hash continuam determinantes.
CRACK_DIFFICULTY: dict[str, CrackDifficulty] = {
    "MD5": "trivial",
    "NTLM": "trivial",
    "MD4": "trivial",
    "MySQL323": "trivial",
    "MySQL5": "trivial",
    "SHA-1": "trivial",
    "SHA-224": "moderate",
    "SHA-256": "moderate",
    "SHA-384": "moderate",
    "SHA-512": "moderate",
    "SHA3-224": "moderate",
    "SHA3-256": "moderate",
    "SHA3-384": "moderate",
    "SHA3-512": "moderate",
    "MD5 crypt": "moderate",
    "Apache MD5-crypt": "moderate",
    "SHA-256 crypt": "hard",
    "SHA-512 crypt": "hard",
    "phpass": "moderate",
    "scrypt": "hard",
    "bcrypt": "hard",
    "Argon2id": "very_hard",
    "Argon2i": "very_hard",
    "Argon2d": "very_hard",
}

# =============================================================================
# Tipo de Resultado — o que identify() retorna para cada palpite
# =============================================================================


@dataclass(frozen=True, slots=True)
class HashCandidate:
    """
    Uma possível identificação de uma string de hash.

    `frozen=True` torna a dataclass imutável — uma vez criada, seus
    campos não podem mudar. `slots=True` torna as instâncias leves na
    memória. Juntas, essas duas flags criam um "objeto de valor" limpo.

    Campos
    ------
    algorithm
        Nome legível do algoritmo como "SHA-256" ou "bcrypt".
    confidence
        Quão certos estamos. "high" vem de correspondências de prefixo definitivas,
        "medium" de correspondências de comprimento que têm apenas um candidato
        óbvio, "low" para comprimentos que podem ser muitas coisas.
    reason
        Explicação curta exibida ao lado do nome do algoritmo. Mantém a
        saída depurável — o usuário pode ver POR QUE cada palpite foi feito.
    hashcat_mode
        Modo numérico do hashcat quando existe uma correspondência conhecida.
    confidence_score
        Pontuação interna de 0.0 a 1.0 formada pelos sinais observáveis.
    crack_difficulty
        Estimativa didática de dificuldade de quebra.
    """

    algorithm: str
    confidence: Confidence
    reason: str
    hashcat_mode: int | None = None
    confidence_score: float = -1.0
    crack_difficulty: CrackDifficulty | None = None

    def __post_init__(self) -> None:
        """Preenche automaticamente o modo hashcat a partir do algoritmo."""
        if self.hashcat_mode is None:
            object.__setattr__(
                self,
                "hashcat_mode",
                HASHCAT_MODES.get(self.algorithm),
            )
        if self.confidence_score < 0:
            default_scores: dict[Confidence, float] = {
                "high": 0.95,
                "medium": 0.60,
                "low": 0.30,
            }
            object.__setattr__(
                self,
                "confidence_score",
                default_scores[self.confidence],
            )
        if self.crack_difficulty is None:
            object.__setattr__(
                self,
                "crack_difficulty",
                CRACK_DIFFICULTY.get(self.algorithm),
            )


@dataclass(frozen=True, slots=True)
class FieldAnalysis:
    """Classificação de um campo de um registro separado por dois-pontos."""

    value: str
    field_type: FieldType
    candidate: HashCandidate | None = None


# =============================================================================
# Regras de Prefixo — o sinal mais forte que temos
# =============================================================================
# Hashes modernos usam strings estilo PHC: um marcador `$` inicial diz
# exatamente qual algoritmo produziu o hash. Quando vemos um desses
# prefixos, relatamos ALTA confiança. O terceiro elemento de cada tupla
# é uma nota curta que incluímos no campo de motivo.
#
# A ordem importa quando os prefixos se sobrepõem. Listamos prefixos mais
# específicos PRIMEIRO para que correspondam antes dos genéricos.

PREFIX_RULES: list[tuple[str, str, str]] = [
    # Família Argon2 — venceu a Password Hashing Competition de 2015
    ("$argon2id$", "Argon2id", "string PHC moderna, o padrão atual"),
    ("$argon2i$", "Argon2i",
     "string PHC, variante resistente a canais laterais"),
    ("$argon2d$", "Argon2d", "string PHC, variante resistente a GPU"),
    # bcrypt e suas variantes — cavalo de batalha dos últimos 15 anos
    ("$2y$", "bcrypt", "string PHC bcrypt, variante 2y (PHP)"),
    ("$2b$", "bcrypt", "string PHC bcrypt, variante 2b (atual)"),
    ("$2a$", "bcrypt", "string PHC bcrypt, variante 2a (legado)"),
    ("$2x$", "bcrypt", "string PHC bcrypt, variante 2x (correção de legado)"),
    # Família Unix crypt(3) — o que o /etc/shadow usa no Linux
    ("$6$", "SHA-512 crypt", "Unix crypt(3) usando SHA-512 (padrão no Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) usando SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) usando MD5 (legado, fraco)"),
    # Variante MD5 do Apache htpasswd — mesma família MD5 do $1$ acima, mas
    # com o ajuste de manipulação de salt do Apache. Este é o formato que
    # `htpasswd -m` emite por padrão.
    ("$apr1$", "Apache MD5-crypt",
     "variante MD5 do Apache htpasswd (`htpasswd -m`)"),
    # yescrypt — novo padrão Linux em algumas distribuições
    ("$y$", "yescrypt", "string PHC, sucessor moderno do Linux crypt"),
    # phpass — usado pelo WordPress, phpBB e outros apps PHP
    ("$P$", "phpass", "hash de senha do WordPress / phpBB"),
    ("$H$", "phpass", "variante phpass estilo phpBB"),
    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "hash estilo PHC do Drupal 7"),
    # scrypt como algumas implementações o codificam
    ("$7$", "scrypt", "hash estilo PHC scrypt"),
    # PBKDF2 legado usado por produtos Atlassian / Jira
    (
        "$pbkdf2$",
        "PBKDF2-SHA1 (Atlassian)",
        "hash PBKDF2-SHA1 legado do Atlassian / Jira",
    ),
    # Padrão do Django — reconhecível pelo nome do algoritmo no prefixo
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "hash de senha padrão do Django"
     ),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "hash de senha legado do Django"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "wrapper bcrypt do Django"),
    ("argon2$", "Django Argon2", "wrapper Argon2 do Django"),
    # Esquemas de senha LDAP — carga base64 após o marcador
    ("{SSHA}", "LDAP SSHA", "SHA-1 com salt do LDAP (carga base64)"),
    ("{SHA}", "LDAP SHA", "SHA-1 do LDAP (carga base64)"),
    ("{SMD5}", "LDAP SMD5", "MD5 com salt do LDAP (carga base64)"),
    ("{MD5}", "LDAP MD5", "MD5 do LDAP (carga base64)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP envolvendo um hash crypt(3)"),
]

# =============================================================================
# Regras de comprimento e hex — fallback quando nenhum prefixo correspondeu
# =============================================================================
# A saída bruta de um hash tem sempre o mesmo comprimento, então uma string de
# N caracteres hex estreita o algoritmo. A lista de algoritmos para cada
# comprimento é ordenada pela prevalência no MUNDO REAL. O primeiro item recebe
# confiança MÉDIA (o "padrão mais provável"), o restante BAIXA.

# Caracteres hex são 0-9 mais a-f (ou A-F se maiúsculos)
HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")

# Conjunto de caracteres hex apenas maiúsculos — alguns formatos (MySQL5) APENAS
# emitem hex maiúsculo. Verificar isso nos permite rejeitar strings minúsculas
# como falsos positivos.
_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

# Comprimento-em-caracteres-hex → lista de algoritmos, ordenada por frequência
HEX_LENGTH_RULES: dict[int, list[str]] = {
    # 16 caracteres hex = 8 bytes = 64 bits. Saída do OLD_PASSWORD() do MySQL.
    16: ["MySQL323", "CRC-64"],
    # 24 caracteres hex = formato legado solicitado no desafio 1.2
    24: ["Tiger-128"],
    # 32 caracteres hex = 16 bytes = 128 bits
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    # 40 caracteres hex = 20 bytes = 160 bits
    40: ["SHA-1", "RIPEMD-160"],
    # 48 caracteres hex = 24 bytes = 192 bits
    48: ["Tiger-192"],
    # 56 caracteres hex = 28 bytes = 224 bits
    56: ["SHA-224", "SHA3-224"],
    # 64 caracteres hex = 32 bytes = 256 bits
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    # 80 caracteres hex = 40 bytes = 320 bits (incomum)
    80: ["RIPEMD-320"],
    # 96 caracteres hex = 48 bytes = 384 bits
    96: ["SHA-384", "SHA3-384"],
    # 128 caracteres hex = 64 bytes = 512 bits
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}

# Alfabetos usados para reconhecer formatos que parecem hashes, mas normalmente
# são identificadores ou dados codificados.
BASE58_CHARSET: frozenset[str] = frozenset(
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
BASE32_CHARSET: frozenset[str] = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

# =============================================================================
# Auxiliares
# =============================================================================


def _is_hex(text: str) -> bool:
    """
    Retorna True se cada caractere no texto for um dígito hex e o texto não estiver vazio.

    Um hash como "5f4dcc..." passa; uma string vazia ou qualquer coisa com
    um caractere não-hex falha. Usamos o frozenset HEX_CHARSET para testes
    de pertinência porque `c in frozenset` é uma busca O(1).
    """
    return bool(text) and all(c in HEX_CHARSET for c in text)


# Layout MySQL5: `*` seguido por 40 caracteres hex maiúsculos.
_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1


def _is_mysql5(text: str) -> bool:
    """
    Retorna True para o formato de senha MySQL5: `*` e 40 caracteres hex MAIÚSCULOS.

    O MySQL5 armazena SHA-1(SHA-1(senha)) impresso em hex maiúsculo com um `*` inicial.
    Rejeitamos minúsculas aqui para não retornar um veredito de ALTA confiança
    em uma string editada manualmente ou digitada incorretamente.
    """
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1:]
    return all(c in _HEX_UPPER_CHARSET for c in body)


# DES crypt tradicional — hashes /etc/passwd legados de sistemas Unix pré-shadow.
# Eles não têm prefixo: apenas 13 caracteres de um alfabeto específico de 64 chars.
_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_DESCRYPT_TOTAL_LENGTH = 13


def _is_descrypt(text: str) -> bool:
    """
    Retorna True para o DES crypt tradicional de 13 caracteres (legado /etc/passwd).

    Sem prefixo — apenas 13 caracteres extraídos de `./0-9A-Za-z`.
    Relatamos confiança MÉDIA (não ALTA) porque uma string de 13 caracteres
    nesse charset PODE ser outras coisas (IDs de sessão, valores codificados).
    """
    return len(text) == _DESCRYPT_TOTAL_LENGTH and all(c in _DESCRYPT_CHARSET
                                                       for c in text)


def _is_base58(text: str) -> bool:
    """Retorna True para uma string longa formada apenas pelo alfabeto Base58."""
    return len(text) >= 26 and all(c in BASE58_CHARSET for c in text)


def _is_base32(text: str) -> bool:
    """Retorna True para uma string longa formada apenas pelo alfabeto Base32."""
    return len(text) >= 16 and all(c in BASE32_CHARSET for c in text)


def _confidence_label(score: float) -> Confidence:
    """Converte a pontuação numérica para a faixa exibida na CLI."""
    if score > 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    return "low"


def _estimate_crack_difficulty(
    algorithm: str,
    raw_input: str,
) -> CrackDifficulty | None:
    """Estima dificuldade e interpreta parâmetros quando eles estão presentes."""
    difficulty = CRACK_DIFFICULTY.get(algorithm)

    if algorithm == "bcrypt":
        match = re.match(r"^\$2[abxy]\$(\d{2})\$", raw_input)
        if match:
            cost = int(match.group(1))
            if cost <= 4:
                difficulty = "moderate"
            elif cost <= 12:
                difficulty = "hard"
            else:
                difficulty = "very_hard"

    elif algorithm.startswith("Argon2"):
        match = re.search(r"m=(\d+),t=(\d+),p=(\d+)", raw_input)
        if match:
            memory, time_cost, _parallelism = map(int, match.groups())
            if memory >= 65_536 and time_cost >= 3:
                difficulty = "very_hard"
            elif memory >= 8_192 and time_cost >= 2:
                difficulty = "hard"
            else:
                difficulty = "moderate"

    return difficulty


def _candidate(
    *,
    algorithm: str,
    score: float,
    reason: str,
    raw_input: str,
) -> HashCandidate:
    """Cria um candidato usando a pontuação como fonte da confiança."""
    bounded_score = max(0.0, min(1.0, score))
    return HashCandidate(
        algorithm=algorithm,
        confidence=_confidence_label(bounded_score),
        reason=reason,
        hashcat_mode=HASHCAT_MODES.get(algorithm),
        confidence_score=bounded_score,
        crack_difficulty=_estimate_crack_difficulty(algorithm, raw_input),
    )


def _is_actual_hash_candidate(candidate: HashCandidate) -> bool:
    """Distingue candidatos de hash das pistas explicitamente marcadas como não-hash."""
    label = candidate.algorithm.lower()
    return "não é" not in label and "provavelmente não" not in label


def split_record(raw_input: str) -> list[FieldAnalysis]:
    """Classifica os campos de um registro no formato ``usuario:hash:salt``."""
    fields = raw_input.strip().split(":")
    analyses: list[FieldAnalysis] = []

    for index, value in enumerate(fields):
        candidates = identify(value)
        if candidates and _is_actual_hash_candidate(candidates[0]):
            analyses.append(
                FieldAnalysis(
                    value=value,
                    field_type="hash",
                    candidate=candidates[0],
                ))
            continue

        if index == 0 and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{1,63}", value):
            analyses.append(FieldAnalysis(value=value, field_type="username"))
            continue

        if value and len(value) <= 64 and not any(c.isspace() for c in value):
            analyses.append(FieldAnalysis(value=value, field_type="salt"))
            continue

        analyses.append(FieldAnalysis(value=value, field_type="garbage"))

    return analyses


# =============================================================================
# O identificador propriamente dito
# =============================================================================
# pylint: disable=too-many-return-statements,too-many-branches


def identify(raw_input: str) -> list[HashCandidate]:
    """
    Retorna candidatos classificados para qual algoritmo produziu `raw_input`.

    Algoritmo
    ---------
    Espaços em branco são removidos de `raw_input` primeiro. Então os seis
    passos de correspondência abaixo rodam em ordem:

    1. Percorre a tabela PREFIX_RULES. O primeiro prefixo que corresponder
       vence (confiança ALTA).
    2. Verifica formatos especiais não-PHC em ordem — registros de desafio-resposta
       NetNTLMv1/v2, MySQL5 (`*<40 hex>`) e o DES crypt legado de 13 chars.
    3. Se a entrada for hex puro, procura seu comprimento em HEX_LENGTH_RULES.
       O primeiro item recebe confiança MÉDIA; o resto BAIXA.
    4. Se a entrada tiver o formato `$<algo>$...` mas nenhuma regra de prefixo
       correspondeu, recorre a uma correspondência genérica de string PHC (confiança BAIXA).
    5. Procura pistas de formatos que não são hashes: URL, hexadecimal com
       prefixo 0x, JWT, Base64, Base32 e Base58.
    6. Se nada corresponder, retorna uma lista vazia.

    Parâmetros
    ----------
    raw_input
        A string de hash a identificar.

    Retorna
    -------
    list[HashCandidate]
        Pode estar vazia. Quando não vazia, os candidatos são ordenados por
        confiança (alta antes de média antes de baixa).
    """
    # Remove espaços em branco — hashes colados costumam vir com quebras de linha.
    text = raw_input.strip()

    if not text:
        return []

    # ----- Passo 1: regras de prefixo -----
    # Percorre a tabela de cima para baixo. A confiança ALTA é o rótulo correto
    # porque um prefixo conhecido é uma autoidentificação definitiva.
    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                _candidate(
                    algorithm=algorithm,
                    score=0.95,
                    reason=f"prefixo `{prefix}` — {note}",
                    raw_input=text,
                )
            ]

    # ----- Passo 2: formatos especiais não-PHC -----
    # Formatos que não se encaixam no molde PHC `$algo$...` mas têm formas inconfundíveis.

    # NetNTLMv1 / NetNTLMv2 — saídas dominantes de ferramentas de pentest AD.
    # NÃO são hashes no sentido de "função irreversível" — são registros de
    # desafio-resposta. O literal `::` é a pista estrutural.
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        # Layout NetNTLMv2:
        #   usuario :: dominio : desafio : hmac(32 hex) : blob(>=32 hex)
        if len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4]):
            return [
                _candidate(
                    algorithm="NetNTLMv2",
                    score=0.85,
                    reason="formato usuario::dominio:desafio:hmac(32 hex):blob",
                    raw_input=text,
                )
            ]
        # Layout NetNTLMv1:
        #   usuario :: dominio : lmhash(48 hex) : nthash(48 hex) : desafio
        if len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3]):
            return [
                _candidate(
                    algorithm="NetNTLMv1",
                    score=0.85,
                    reason=
                    "formato usuario::dominio:lm(48 hex):nt(48 hex):desafio",
                    raw_input=text,
                )
            ]

    # MySQL5 — literal `*` + 40 caracteres hex maiúsculos
    if _is_mysql5(text):
        return [
            _candidate(
                algorithm="MySQL5",
                score=0.85,
                reason=
                "começa com `*` seguido por 40 caracteres hex maiúsculos",
                raw_input=text,
            )
        ]

    # DES crypt tradicional de 13 caracteres — formato legado /etc/passwd
    if _is_descrypt(text):
        return [
            _candidate(
                algorithm="DES crypt",
                score=0.60,
                reason=
                "13 caracteres em `./0-9A-Za-z` — formato legado /etc/passwd",
                raw_input=text,
            )
        ]

    # ----- Passo 3: comprimento + charset hex -----
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            # Peso de comprimento (0.55 / posição) + pequeno bônus por charset hex.
            score = (0.55 / (index + 1)) + 0.05
            label = ("candidato mais provável para este comprimento" if index
                     == 0 else "também possível para este comprimento")
            candidates.append(
                _candidate(
                    algorithm=algorithm,
                    score=score,
                    reason=f"{len(text)} caracteres hex — {label}",
                    raw_input=text,
                ))
        return candidates

    # ----- Passo 4: fallback genérico para string PHC -----
    # Se a entrada começa com `$<nome>$...` e <nome> parece um identificador
    # plausível, é quase certamente uma string PHC de um algoritmo para o qual
    # não temos uma regra específica.
    if text.startswith("$"):
        rest = text[1:]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            # A especificação PHC restringe IDs de algoritmo a alfanuméricos
            # mais `-` e `_`.
            if algo_name and all(c.isalnum() or c in "-_" for c in algo_name):
                return [
                    _candidate(
                        algorithm=f"String PHC ({algo_name})",
                        score=0.35,
                        reason=
                        f"formato `${algo_name}$...` — PHC genérico, sem regra específica",
                        raw_input=text,
                    )
                ]

    # ----- Passo 5: dicas de formatos que não são hashes -----
    # Estes formatos são reconhecidos apenas pela forma, então permanecem com
    # confiança BAIXA. A ferramenta não tenta decodificar ou validar o conteúdo.
    if text.startswith(("http://", "https://")):
        return [
            _candidate(
                algorithm="URL (não é um hash)",
                score=0.30,
                reason="começa com `http://` ou `https://`",
                raw_input=text,
            )
        ]

    if text.startswith("0x") and _is_hex(text[2:]):
        return [
            _candidate(
                algorithm=
                "Hexadecimal com prefixo 0x (não é necessariamente um hash)",
                score=0.30,
                reason=
                "prefixo `0x` costuma indicar endereço ou valor hexadecimal",
                raw_input=text,
            )
        ]

    if text.startswith("eyJ"):
        # JWTs sempre começam com `eyJ` porque seu cabeçalho JSON `{"alg":...}`
        # em base64 começa com esses três caracteres.
        return [
            _candidate(
                algorithm="JWT (não é um hash)",
                score=0.30,
                reason='prefixo `eyJ` é o base64 de `{"` — JWT, não é um hash',
                raw_input=text,
            )
        ]
    if any(c in text for c in "+/=") and len(text) > 8:
        # Hashes hex NUNCA contêm `+`, `/`, ou `=`.
        return [
            _candidate(
                algorithm="Blob Base64 (não é um hash)",
                score=0.30,
                reason="contém caracteres exclusivos de base64 (`+`, `/`, `=`)",
                raw_input=text,
            )
        ]

    if _is_base32(text):
        return [
            _candidate(
                algorithm="Base32 (provavelmente não é um hash)",
                score=0.30,
                reason="usa somente letras maiúsculas e dígitos de 2 a 7",
                raw_input=text,
            )
        ]

    if _is_base58(text):
        return [
            _candidate(
                algorithm="Base58 (provavelmente não é um hash)",
                score=0.30,
                reason=
                "alfabeto Base58 usado por endereços Bitcoin e hashes IPFS",
                raw_input=text,
            )
        ]

    # ----- Passo 6: nada correspondeu -----
    return []


# =============================================================================
# CLI — argparse + uma tabela rich
# =============================================================================


def _build_argument_parser() -> argparse.ArgumentParser:
    """
    Constrói o analisador argparse usado pelo main().
    """
    parser = argparse.ArgumentParser(
        prog="hashid",
        description=(
            "Identifica uma string de hash por prefixo, comprimento e charset. "
            "Retorna candidatos classificados com confiança e raciocínio."),
    )
    parser.add_argument(
        "hash",
        nargs="?",
        help=
        "A string de hash a identificar (envolva em aspas simples se contiver $).",
    )
    parser.add_argument(
        "--top",
        "-n",
        type=int,
        default=5,
        help="Mostra no máximo este número de candidatos (padrão: 5).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Imprime o resultado em JSON em vez da tabela colorida.",
    )
    parser.add_argument(
        "--file",
        dest="input_file",
        type=Path,
        help="Lê uma entrada por linha de um arquivo.",
    )
    parser.add_argument(
        "--split",
        action="store_true",
        help="Classifica campos separados por dois-pontos (usuario:hash:salt).",
    )
    return parser


def _render_table(
    raw_input: str,
    candidates: list[HashCandidate],
    console: Console,
) -> None:
    """
    Imprime uma Tabela rich mostrando os candidatos identificados.
    """
    table = Table(
        title=f"Candidatos para: {raw_input.strip()}",
        title_style="bold cyan",
        show_lines=False,
    )
    table.add_column("algoritmo", style="bold white", no_wrap=True)
    table.add_column("confiança", no_wrap=True)
    table.add_column("pontuação", no_wrap=True)
    table.add_column("dificuldade", no_wrap=True)
    table.add_column("hashcat", no_wrap=True)
    table.add_column("motivo", style="dim")

    # Cores para os níveis de confiança.
    confidence_colors: dict[Confidence, str] = {
        "high": "green",
        "medium": "yellow",
        "low": "cyan",
    }
    for candidate in candidates:
        color = confidence_colors[candidate.confidence]
        table.add_row(
            candidate.algorithm,
            f"[{color}]{candidate.confidence}[/{color}]",
            f"{candidate.confidence_score:.2f}",
            candidate.crack_difficulty or "-",
            (str(candidate.hashcat_mode)
             if candidate.hashcat_mode is not None else "-"),
            candidate.reason,
        )
    console.print(table)


def _read_inputs(
    hash_value: str | None,
    input_file: Path | None,
) -> list[str]:
    """Lê uma entrada posicional, um arquivo ou o stdin, ignorando linhas vazias."""
    if hash_value is not None:
        return [hash_value]

    if input_file is not None:
        with input_file.open(encoding="utf-8") as source:
            return [line.strip() for line in source if line.strip()]

    return [line.strip() for line in sys.stdin if line.strip()]


def _json_record(
    raw_input: str,
    candidates: list[HashCandidate],
) -> dict[str, object]:
    """Converte uma entrada e seus candidatos para uma estrutura serializável."""
    return {
        "input": raw_input,
        "candidates": [asdict(candidate) for candidate in candidates],
    }


def _render_batch(results: list[tuple[str, list[HashCandidate]]], ) -> None:
    """Imprime uma linha tabulada por entrada em modo de processamento em lote."""
    for raw_input, candidates in results:
        if not candidates:
            print(f"{raw_input}\tsem identificação")
            continue

        best = candidates[0]
        mode = str(best.hashcat_mode) if best.hashcat_mode is not None else "-"
        print(f"{raw_input}\t{best.algorithm}\t{best.confidence}\t"
              f"score={best.confidence_score:.2f}\t"
              f"difficulty={best.crack_difficulty or '-'}\t"
              f"hashcat={mode}\t{best.reason}")


def _split_json_record(
    raw_input: str,
    fields: list[FieldAnalysis],
) -> dict[str, object]:
    """Converte um registro dividido para JSON."""
    return {
        "input": raw_input,
        "fields": [asdict(field) for field in fields],
    }


def _render_split(
    raw_input: str,
    fields: list[FieldAnalysis],
    console: Console,
) -> None:
    """Mostra a classificação de cada campo de um registro composto."""
    table = Table(title=f"Campos de: {raw_input}", title_style="bold cyan")
    table.add_column("campo", style="bold white")
    table.add_column("tipo", no_wrap=True)
    table.add_column("algoritmo")
    table.add_column("pontuação", no_wrap=True)

    for field in fields:
        algorithm = field.candidate.algorithm if field.candidate else "-"
        score = (f"{field.candidate.confidence_score:.2f}"
                 if field.candidate else "-")
        table.add_row(field.value or "(vazio)", field.field_type, algorithm,
                      score)

    console.print(table)


def main() -> int:
    """
    Ponto de entrada da CLI — retorna um código de saída (0 = ok, 1 = nada encontrado).
    """
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    if args.top <= 0:
        parser.error("--top deve ser maior que zero")

    if args.hash is not None and args.input_file is not None:
        parser.error("use o hash posicional ou --file, mas não ambos")

    if args.hash is None and args.input_file is None and sys.stdin.isatty():
        parser.error("forneça um hash, use --file ou envie dados pelo stdin")

    inputs = _read_inputs(args.hash, args.input_file)

    if not inputs:
        console.print("[red]Nenhuma entrada fornecida.[/red]")
        return 1

    if args.split:
        split_results = [(raw_input, split_record(raw_input))
                         for raw_input in inputs]
        records_with_hash = all(
            any(field.field_type == "hash" for field in fields)
            for _, fields in split_results)

        if args.json:
            if len(split_results) == 1:
                split_payload: object = _split_json_record(*split_results[0])
            else:
                split_payload = {
                    "results": [
                        _split_json_record(raw_input, fields)
                        for raw_input, fields in split_results
                    ]
                }
            print(json.dumps(split_payload, ensure_ascii=False, indent=2))
        else:
            for raw_input, fields in split_results:
                _render_split(raw_input, fields, console)

        return 0 if records_with_hash else 1

    results = [(raw_input, identify(raw_input)[:args.top])
               for raw_input in inputs]
    all_identified = all(candidates for _, candidates in results)

    if args.json:
        if len(results) == 1:
            payload: object = _json_record(*results[0])
        else:
            payload = {
                "results": [
                    _json_record(raw_input, candidates)
                    for raw_input, candidates in results
                ]
            }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if all_identified else 1

    batch_mode = args.input_file is not None or args.hash is None
    if batch_mode:
        _render_batch(results)
        return 0 if all_identified else 1

    raw_input, candidates = results[0]
    if not candidates:
        console.print(
            "[red]Nenhuma identificação possível.[/red] "
            "A entrada não correspondeu a nenhum prefixo conhecido, formato especial "
            "ou comprimento hexadecimal.")
        return 1

    _render_table(raw_input, candidates, console)

    # Quando conhecemos um modo, mostramos um comando pronto para o hashcat.
    best = candidates[0]
    if best.hashcat_mode is not None:
        console.print(
            "\n[dim]Próximo passo: "
            f"hashcat -m {best.hashcat_mode} -a 0 '{raw_input}' wordlist.txt[/dim]"
        )
    elif best.confidence == "high":
        console.print(
            "\n[dim]Próximo passo: consulte a documentação do hashcat para "
            "confirmar o modo correspondente.[/dim]")

    return 0


# Guarda padrão "se invocado diretamente como script".
if __name__ == "__main__":
    sys.exit(main())
