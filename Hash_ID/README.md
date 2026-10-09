# Hash_ID

![Mode](https://img.shields.io/badge/Mode-Individual-402)
![Difficulty](https://img.shields.io/badge/Difficulty-N1_Iniciante-brightgreen)
![Stack](https://img.shields.io/badge/Stack-Python-3776AB)

> Identifique o algoritmo por trás de uma string de hash por seu prefixo, comprimento e conjunto de caracteres — o primeiro passo em qualquer fluxo de trabalho de quebra de senhas.

_Esta é uma visão geral rápida — teoria de segurança, arquitetura e tutoriais completos estão em [/learn](./learn/00-Introdução.md)._

> [!NOTE]
> Esta ferramenta foi desenvolvida para alguém que nunca escreveu Python antes. O código-fonte é amplamente comentado como material de apoio ao aprendizado, a pasta `learn/` explica cada conceito do zero, e toda a ferramenta consiste em um único arquivo legível.

## 🎯 Objective

Construir uma ferramenta de linha de comando que identifica o algoritmo de hash de uma string com base em padrões observáveis (prefixo, comprimento, conjunto de caracteres), retornando candidatos classificados com níveis de confiança.

## 🧠 Learning Outcomes

- O que são hashes e por que não são criptografia reversível
- Como identificar algoritmos por formato, comprimento e prefixo
- Os três sinais de identificação: prefixo, comprimento, conjunto de caracteres
- Fundamentos de Python: funções puras, tipagem, testes, CLI
- Como estruturar um pipeline de decisão em camadas

## � Caso tenha dificuldades com a base do projeto

> [!NOTE]
> Este projeto ensina Python do zero nos módulos `learn/`. Se você empacar na base, estes recursos rápidos ajudam a recuperar o fluxo.

- [Curso em Vídeo — Python para Iniciantes](https://www.cursoemvideo.com/course/curso-python-3/) — vídeo-aula passo a passo
- [Python Tutorial for Beginners — freeCodeCamp.org](https://www.youtube.com/watch?v=rfscVS0vtbw) — introdução prática a Python
- [Hash algorithms — Computerphile](https://youtu.be/b4b8ktEV4Bg?si=4KDOBMfntwpbWxkw) — entenda hashes em 10 minutos

## 🛠️ Scope

### MVP

- **Desafios Nível 1 (1.1–1.3):** adicionar uma regra de prefixo, adicionar uma regra por comprimento hexadecimal e criar a saída `--json`.
- **Desafios Nível 2 (2.1–2.3):** entrada por arquivo/stdin, dicas de modo do hashcat e reconhecimento de entradas que não são hashes.
- Manter a identificação dos formatos existentes, os níveis de confiança e a justificativa funcionando enquanto esses desafios são implementados.
- Demonstrar cada desafio com testes automatizados e uma execução da CLI.

### Stretch

- **Nível 3 (3.1–3.3):** identificação de múltiplos hashes, pontuação de confiança e estimativa de dificuldade de quebra.
- **Nível 4 (4.1–4.3):** análise de dump real, comparação com ferramentas existentes e hook de `pre-commit`.

### Conquer

- **Nível 5 (5.1–5.2):** documentar as limitações estruturais do identificador e construir um classificador probabilístico com ML.

## ✅ Definition of Done

- [x] `just test` passa (mais de 70 testes)
- [x] `just lint` passa (ruff + mypy --strict + pylint)
- [x] `just run -- <hash>` identifica corretamente os hashes de demonstração
- [x] Códigos de saída corretos para scripts de shell

## 🧪 Validation

```bash
just test       # executa o pytest (72 testes)
just lint       # ruff + mypy --strict + pylint
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
# ✔ MD5 (medium) — 32 caracteres hexadecimais, candidato mais provável para este comprimento
```

Teste com os [hashes de demonstração](#hashes-de-demonstração) abaixo.

## 🎬 Demo

Execute a ferramenta com os hashes de demonstração e explique:

- Como cada hash foi identificado (prefixo, comprimento, formato)
- Por que alguns candidatos têm confiança `high` e outros `medium`/`low`
- O que a ferramenta **não** consegue concluir com certeza

## 🚀 Getting Started

Dentro de `projects/Individual/a-Hash_ID/`:

```bash
sudo apt update
wget -qO- https://astral.sh/uv/install.sh | sh
uv venv --python 3.14
source .venv/bin/activate
./install.sh
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
```

No Windows (PowerShell), depois de instalar Python, `uv` e `just`:

```powershell
cd projects\Individual\a-Hash_ID
uv venv --python 3.14
uv sync --all-extras
just test
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
```

Se você acabou de instalar `uv` ou `just` e o comando ainda não aparece,
feche e abra o PowerShell uma vez para atualizar o `PATH`.

> [!TIP]
> Este projeto utiliza o [`just`](https://github.com/casey/just) como executor de comandos. Digite `just` para ver todos os comandos disponíveis.
>
> Instalação: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Hashes de Demonstração

| Hash                                                                          | Detectado como   | Motivo                             |
| ----------------------------------------------------------------------------- | ---------------- | ---------------------------------- |
| `5f4dcc3b5aa765d61d8327deb882cf99`                                            | MD5              | 32 caracteres hexadecimais         |
| `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`            | SHA-256          | 64 caracteres hexadecimais         |
| `$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQNQy.uK4Of2T7G.VHvgvWK`              | bcrypt           | prefixo `$2b$`                     |
| `$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG` | Argon2id         | prefixo `$argon2id$`               |
| `$apr1$JlOdSlVe$ipa1mTAv3LFRBHHzqaIaH/`                                       | Apache MD5-crypt | prefixo `$apr1$`                   |
| `*A4B6157319038724E3560894F7F932C8886EBFCF`                                   | MySQL5           | começa com `*` + 40 hex maiúsculos |
| `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgN...`  | JWT (não é hash) | prefixo `eyJ` = base64 de `{"`     |

> [!IMPORTANT]
> Sempre envolva hashes que começam com `$` em **aspas simples**. Sem as aspas, seu shell tentará expandir `$2`, `$P$`, `$1$` etc. como variáveis de shell.

## Ferramentas

```bash
just            # lista os comandos disponíveis
just test       # executa o pytest
just lint       # ruff + mypy --strict + pylint
just format     # yapf
just run -- <h> # identifica um hash
```

## Recursos implementados

- regras por prefixo, comprimento e charset;
- saída humana ou JSON;
- entrada única, arquivo ou stdin;
- modo Hashcat, pontuação de confiança e dificuldade estimada;
- `--split` para registros `usuario:hash:salt`;
- detecção de URL, JWT, Base64, Base32, Base58 e valores `0x`;
- análise de dumps HIBP com medição de vazão;
- comparação reproduzível com `hashid` e Name-That-Hash;
- hook de pre-commit;
- experimento de ML com 100 mil amostras sintéticas.

### JSON

```bash
just run -- --json 5f4dcc3b5aa765d61d8327deb882cf99
```

### Arquivo e stdin

```bash
just run -- --file hashes.txt
cat hashes.txt | uv run hashid
```

Há entradas prontas em `examples/hashes.txt` e `examples/records.txt`.

No PowerShell:

```powershell
Get-Content .\hashes.txt | uv run hashid
```

### Registros compostos

```bash
just run -- --split 'alice:5f4dcc3b5aa765d61d8327deb882cf99:salt123'
```

### Dump, comparação e pre-commit

```bash
uv run python analyze_dump.py examples/hibp_demo.txt --limit 1000
uv run python compare_tools.py
uv run pre-commit install
uv run pre-commit run --all-files
```

### Experimento de ML

```bash
uv run python ml_classifier.py generate --samples 100000
uv run python ml_classifier.py train
uv run python ml_classifier.py predict 5f4dcc3b5aa765d61d8327deb882cf99
```

Consulte também:

- [`docs/limitations.md`](docs/limitations.md)
- [`docs/dump-analysis.md`](docs/dump-analysis.md)
- [`docs/comparison.md`](docs/comparison.md)
- [`docs/pre-commit.md`](docs/pre-commit.md)
- [`docs/ml-experiment.md`](docs/ml-experiment.md)

## Requisitos

- **Python 3.14+** — o script de instalação fará a verificação.
- [`uv`](https://github.com/astral-sh/uv) — gerenciador moderno de pacotes para Python.
- [`just`](https://github.com/casey/just) — executor de comandos.

Depois da instalação das dependências, a identificação normal não precisa de
acesso à rede. O experimento de ML usa as dependências opcionais instaladas por
`uv sync --all-extras`.

## 📚 Learning Resources

| Módulo                                          | Tópico                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------ |
| [00 - Introdução](learn/00-Introdução.md)       | Início rápido, pré-requisitos, problemas comuns                    |
| [01 - Conceitos](learn/01-Conceitos.md)         | O que são hashes, violações reais, os três sinais de identificação |
| [02 - Arquitetura](learn/02-Arquitetura.md)     | Arquitetura em três camadas, pipeline de decisão em seis etapas    |
| [03 - Implementação](learn/03-Implementação.md) | Explicação linha por linha — cada recurso do Python explicado      |
| [04 - Desafios](learn/04-Desafios.md)           | Cinco níveis de ideias para extensão                               |

## 🔗 Referências externas

- [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) — catálogo de formatos de hash reais
- [Name That Hash](https://nth.skerritt.blog/) — ferramenta online de identificação de hashes
- [Crypto 101](https://www.crypto101.io/) — introdução a criptografia aplicada

## 🧭 Next Step

Após concluir `Hash_ID`, você pode avançar para o projeto em equipe do mesmo ramo: [`Hash_Cracker`](../../Team/Hash_Cracker/README.md) — quebra de hashes com ataques de dicionário, brute force e regras.

> [!NOTE]
> **Não é obrigatório** avançar para o próximo projeto imediatamente. Você pode fazer múltiplos projetos primários em paralelo, respeitando as janelas de entrega do calendário.

---

@CarterPerez-dev | Copyright (C) 2026 Murilo Miacci
