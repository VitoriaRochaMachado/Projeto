# Experimento probabilístico com ML

O experimento usa hashes de senhas sintéticas e nunca precisa de dados reais de
usuários. O pipeline combina TF-IDF de n-gramas de caracteres com regressão
logística.

## 1. Instalar os extras

```bash
uv sync --all-extras
```

## 2. Gerar 100 mil amostras

```bash
uv run python ml_classifier.py generate --samples 100000
```

O CSV é salvo em `data/hash_samples.csv`. São usadas seis classes: MD5, SHA-1,
SHA-256, SHA-512, bcrypt e Argon2id.

## 3. Treinar e comparar

```bash
uv run python ml_classifier.py train
```

O comando imprime a acurácia do modelo e a acurácia das regras sobre a mesma
separação de teste. O modelo é salvo em `models/hash_classifier.joblib`.

## 4. Fazer uma previsão

```bash
uv run python ml_classifier.py predict \
  5f4dcc3b5aa765d61d8327deb882cf99
```

## Interpretação

Uma acurácia alta não prova que ML distingue MD5 de NTLM: o experimento atual
não inclui NTLM porque sua forma textual é idêntica à do MD5. O objetivo é
comparar abordagens, não substituir a documentação das limitações.

## Execução de validação deste projeto

Uma execução reproduzível com `seed=42`, Python 3.14.8 e 100 mil amostras
produziu:

```json
{
  "total_samples": 100000,
  "test_samples": 20000,
  "ml_accuracy": 1.0,
  "rule_accuracy": 1.0
}
```

Esse resultado não significa que o problema geral está resolvido. As seis
classes usadas possuem diferenças estruturais fortes; a limitação de formatos
idênticos continua válida.
