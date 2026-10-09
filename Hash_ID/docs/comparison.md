# Comparação com hashid e Name-That-Hash

O script `compare_tools.py` executa o Hash_ID, `hashid` e `nth` sobre as mesmas
amostras. Ferramentas ausentes são marcadas como `indisponível`; o relatório não
inventa resultados.

Como a CLI deste projeto também se chama `hashid`, o script inspeciona o
launcher encontrado no ambiente virtual. Se ele apontar para
`hash_identifier:main`, a entrada é marcada como indisponível em vez de comparar
o Hash_ID com ele mesmo.

```bash
uv run python compare_tools.py
uv run python compare_tools.py --json
```

Para uma entrada específica:

```bash
uv run python compare_tools.py 5f4dcc3b5aa765d61d8327deb882cf99
```

## Conclusões estruturais

- Hash_ID é conservador: prefixos conhecidos recebem confiança alta, enquanto
  comprimentos compartilhados retornam vários candidatos.
- `hashid` possui um catálogo amplo de assinaturas, mas a comparação deve levar
  em conta falsos positivos, não apenas quantidade de formatos.
- Name-That-Hash costuma apresentar mais metadados e possibilidades; isso pode
  aumentar cobertura e também produzir listas maiores.
- Para entrada em lote, a medição justa deve desabilitar saída colorida e usar
  as mesmas amostras, máquina e quantidade de execuções.

As saídas concretas dependem das versões instaladas. Guarde o JSON produzido
pelo script junto ao relatório se precisar apresentar números reproduzíveis.
