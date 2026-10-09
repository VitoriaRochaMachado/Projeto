# Limitações estruturais do Hash_ID

O Hash_ID identifica formatos por sinais observáveis. Ele não descobre o
algoritmo criptográfico olhando para os bits internos do digest e não recupera
a senha original.

## Formatos indistinguíveis

| Forma observada | Possibilidades | Por que não é possível separar |
| --- | --- | --- |
| 32 caracteres hex | MD5, NTLM, MD4, RIPEMD-128 | Todos produzem 128 bits e usam a mesma representação hexadecimal. |
| 40 caracteres hex | SHA-1, RIPEMD-160 | Ambos produzem 160 bits. |
| 64 caracteres hex | SHA-256, SHA3-256, BLAKE2s-256, RIPEMD-256 | Todos produzem 256 bits. |
| 128 caracteres hex | SHA-512, SHA3-512, BLAKE2b-512, Whirlpool | Todos produzem 512 bits. |

Nesses casos, o primeiro resultado é apenas o candidato mais comum no contexto
de senhas. Não é uma confirmação matemática.

## Truncamento

Um SHA-256 truncado para 32 caracteres parece um MD5. Depois que os bytes finais
são removidos, o formato não carrega informação suficiente para revelar sua
origem.

## Maiúsculas, minúsculas e codificação

Bibliotecas podem exibir o mesmo digest em caixa alta ou baixa. Um digest
também pode ser representado em hexadecimal, Base64 ou em um formato próprio.
O identificador vê a representação textual, não a função que a originou.

## Salt e contexto externo

Hashes brutos geralmente não incluem o salt, o nome do usuário, a aplicação ou
a versão do sistema. Esses dados externos podem ser decisivos. Um valor de 32
hex vindo do banco SAM do Windows é provavelmente NTLM; o mesmo valor em uma
API antiga pode ser MD5.

## Prefixos podem ser falsificados

Qualquer pessoa pode escrever uma string que começa com `$2b$` ou `$argon2id$`.
O prefixo produz evidência forte de formato, mas a ferramenta não recalcula nem
valida criptograficamente o conteúdo completo.

## Falsos positivos em Base32 e Base58

Os detectores verificam apenas tamanho e alfabeto. Identificadores aleatórios,
tokens e palavras podem coincidir com esses alfabetos. Por isso a confiança é
baixa.

## Dificuldade de quebra

A estimativa é educacional. O resultado real depende de:

- qualidade e comprimento da senha;
- presença de salt único;
- custo configurado pelo algoritmo;
- hardware e implementação;
- tamanho e qualidade da wordlist.

Uma senha longa e aleatória usando um algoritmo rápido ainda pode ser
impraticável; uma senha fraca usando um algoritmo moderno ainda pode cair.

## Classificador de ML

O modelo aprende padrões das classes presentes no conjunto de treinamento. Ele
não resolve formatos estruturalmente idênticos e pode parecer muito preciso
quando as classes têm prefixos ou comprimentos diferentes. A avaliação deve usar
amostras separadas e incluir casos ambíguos e adversariais.
