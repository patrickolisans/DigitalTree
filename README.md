# DigitalTree

Implementação em C de uma árvore digital m-ária com $m = 4$ para representar endereços IPv4 em uma estrutura de firewall.

## O que a aplicação faz

- Mantém a lista de IPs bloqueados como um banco interno da aplicação, representado por uma árvore digital baseada em símbolos binários de 2 bits (representando o conceito de m-ária com $m = 4$).
- Persiste essa lista em um arquivo TXT para armazenamento externo.
- Permite inserir, remover e consultar IPs.
- Verifica uma lista de IPs de entrada contra a lista bloqueada, simulando um firewall.

## Estrutura do projeto

- src/firewall_tree.h: interface da estrutura da árvore.
- src/firewall_tree.c: implementação da árvore digital e operações de arquivo.
- src/main.c: ponto de entrada com CLI para operações.
- tests/blocked_ips.txt: exemplo de lista de IPs bloqueados.
- tests/input_ips.txt: exemplo de lista de IPs a serem verificados.

## Como compilar

```bash
make
```

## Como usar

### Verificar uma lista de IPs

```bash
./build/firewall --blocked tests/blocked_ips.txt --input tests/input_ips.txt
```

### Inserir um IP na lista bloqueada

```bash
./build/firewall --blocked tests/blocked_ips.txt --add 1.2.3.4
```

### Remover um IP da lista bloqueada

```bash
./build/firewall --blocked tests/blocked_ips.txt --remove 1.2.3.4
```

### Consultar se um IP está bloqueado

```bash
./build/firewall --blocked tests/blocked_ips.txt --query 8.8.8.8
```

## Observação

A árvore usa a representação de cada octeto em bits, transformando o IPv4 em um caminho de símbolos de 2 bits, o que é compatível com a ideia de uma árvore digital $m$-ária com $m = 4$.
