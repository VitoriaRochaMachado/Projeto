# Hash_ID — passos desde o início

Este pacote contém os arquivos modificados e novos para os desafios dos níveis
1 a 5. Extraia o ZIP dentro da pasta original `a-Hash_ID` e permita substituir
os arquivos de mesmo nome. Mantenha as pastas originais `learn/` e `assets/`.

## Windows (PowerShell)

1. Instale o Python 3.14, o `uv` e o `just`.
2. Feche e abra o PowerShell após a instalação para atualizar o `PATH`.
3. Entre na pasta do projeto.
4. Execute:

```powershell
uv venv --python 3.14
uv sync --all-extras
just test
just lint
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
```

Não altere a receita `test`: ela permanece executando `uv run pytest`.

## Linux/macOS

Dentro da pasta do projeto:

```bash
chmod +x install.sh
./install.sh
just test
just lint
just run -- 5f4dcc3b5aa765d61d8327deb882cf99
```

## Demonstrações

```bash
just run -- --json 5f4dcc3b5aa765d61d8327deb882cf99
just run -- --file examples/hashes.txt
just run -- --split 'alice:5f4dcc3b5aa765d61d8327deb882cf99:salt123'
uv run python analyze_dump.py examples/hibp_demo.txt --limit 1000
uv run python compare_tools.py
uv run pre-commit install
uv run pre-commit run --all-files
```

No PowerShell, hashes que começam com `$` também devem ficar entre aspas
simples.

## Experimento de ML

O dataset e o modelo são gerados localmente e não estão dentro do ZIP porque
juntos ocupam dezenas de megabytes:

```bash
uv run python ml_classifier.py generate --samples 100000
uv run python ml_classifier.py train
uv run python ml_classifier.py predict 5f4dcc3b5aa765d61d8327deb882cf99
```

## Arquivos modificados ou adicionados

- `hash_identifier.py`
- `test_hash_identifier.py`
- `justfile`
- `pyproject.toml`
- `uv.lock`
- `README.md`
- `install.sh`
- `.gitignore`
- `.pre-commit-config.yaml`
- `analyze_dump.py`
- `compare_tools.py`
- `precommit_hook.py`
- `ml_classifier.py`
- `docs/*.md`
- `examples/*.txt`

## Observação sobre o Nível 4

O exemplo HIBP incluído é pequeno e serve para validar o analisador. O dump
completo não é redistribuído. Para medir as primeiras 1000 linhas de um dump
real, obtenha legalmente a versão SHA-1 do Have I Been Pwned e passe o caminho
do arquivo para `analyze_dump.py`.

Da mesma forma, `compare_tools.py` marca HashID e Name-That-Hash como
`indisponível` quando eles não estão instalados; o script não inventa resultados.
