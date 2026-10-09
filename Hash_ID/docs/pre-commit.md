# Hook de pre-commit

Instale e ative:

```bash
uv sync --all-extras
uv run pre-commit install
uv run pre-commit run --all-files
```

O hook bloqueia somente candidatos com pontuação maior que `0.8`. Fixtures
intencionais podem ser liberadas na própria linha:

```text
$2b$12$exemplo... # pragma: allow-hash
```

Use a liberação com cuidado: ela documenta que o valor foi revisado e não é um
segredo real.
