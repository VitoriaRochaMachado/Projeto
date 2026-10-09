# Análise de dump HIBP

O script `analyze_dump.py` lê o formato SHA-1 distribuído pelo
Have I Been Pwned (`HASH:CONTAGEM`), identifica até o limite solicitado e mede
a vazão.

Use apenas dados públicos, dados próprios ou material de CTF. Não use dumps
privados ou dados obtidos sem autorização.

## Execução

```bash
uv run python analyze_dump.py pwned-passwords-sha1-ordered-by-hash-v8.txt --limit 1000
```

Saída JSON:

```bash
uv run python analyze_dump.py pwned-passwords-sha1-ordered-by-hash-v8.txt \
  --limit 1000 --json
```

O resultado real depende do arquivo e do computador. Por isso, números de vazão
não são fixados neste documento. Em dumps grandes, a impressão no terminal
normalmente custa mais que a identificação estrutural; este script agrega os
resultados e imprime apenas o resumo.
