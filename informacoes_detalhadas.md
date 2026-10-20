# Documentação de Design: CTF MIPS Memory Forensics

## 1. Visão Geral e Narrativa (Lore)

**Cenário:** Durante um ataque cibernético, o mecanismo de segurança de um sistema embarcado de missão crítica foi acionado. Para proteger a chave de acesso (a *Flag*), o sistema dividiu a chave de 8 bytes em dois blocos de 4 bytes na memória RAM.

**O Twist de Segurança:** Para evitar uma leitura direta da memória (*dump*), o sistema preservou a primeira metade em texto claro, mas aplicou uma operação lógica **XOR** na segunda metade, usando a primeira metade como "chave de criptografia" (Seed).

**Missão do Aluno:** Atuar como perito forense utilizando um terminal restrito MIPS. O aluno deve vasculhar 50 endereços de memória, encontrar os dois blocos de dados anômalos, carregá-los nos registradores e aplicar a operação reversa (XOR) para revelar a flag completa.

## 2. Configurações do Simulador

* **Dificuldade:** Média. O simulador não converte dados para texto legível (ASCII). A saída será estritamente em Hexadecimal, exigindo que o aluno reconheça padrões numéricos e utilize ferramentas externas (como o *CyberChef* ou conversores online) para traduzir o Hex final para texto.
* **Arquitetura Base:** Subconjunto MIPS de 32 bits (cada endereço de memória armazena 4 bytes/1 Palavra).
* **Espaço de Busca:** 50 endereços consecutivos de memória.
* **Início:** `0x1000`
* **Fim:** `0x10C4` (Avançando de 4 em 4 bytes).



## 3. Estrutura da Memória (O Segredo)

A maioria dos endereços de memória conterá "ruído". Apenas dois endereços específicos conterão dados maiores:

* **Endereço A (`0x1014`):** Contém a **Metade 1** (Texto claro em Hex).
* Valor em Hex: `0x584F525F` (Tradução: `XOR_`)


* **Endereço B (`0x102C`):** Contém a **Metade 2 Criptografada**.
* Valor em Hex: `0x107B1114` (Lixo eletrônico)


* **A Lógica Reversa:** Em criptografia XOR, aplicar a mesma operação reverte o processo.
* `0x584F525F` (Metade 1) **XOR** `0x107B1114` (Metade 2 Criptografada) = `0x4834434B`
* Tradução de `0x4834434B`: `H4CK`
* **Flag Final:** `XOR_H4CK`



## 4. Conjunto de Instruções Disponíveis (ISA)

O terminal aceitará comandos iterativos, divididos entre instruções MIPS puras e comandos de auxílio do CTF.

| Comando        | Tipo | Descrição                                                                        |
| -------------- | ---- | -------------------------------------------------------------------------------- |
| `li $reg, imm` | MIPS | **Load Immediate:** Carrega um endereço ou valor constante num registrador. <br> |

<br>*Ex: `li $s0, 0x1000*` |
| `lw $reg1, offset($reg2)` | MIPS | **Load Word:** Lê o conteúdo de 32 bits da memória no endereço apontado por `$reg2` e carrega em `$reg1`. <br>

<br>*Ex: `lw $t0, 0($s0)*` |
| `addi $reg1, $reg2, imm` | MIPS | **Add Immediate:** Soma uma constante aritmética para avançar os ponteiros de memória. <br>

<br>*Ex: `addi $s0, $s0, 4*` |
| `xor $rd, $rs, $rt` | MIPS | **Bitwise Exclusive-OR:** Realiza a operação XOR bit a bit entre `$rs` e `$rt`, armazenando o resultado em `$rd`. <br>

<br>*Ex: `xor $t2, $t0, $t1*` |
| `show $reg` | CTF Tool | Exibe no terminal o valor atual armazenado no registrador especificado, **apenas em Hexadecimal**. <br>

<br>*Ex: `show $t2` -> `[0x57314E7D]*` |
| `show mem offset($reg)` | CTF Tool | Inspeciona diretamente o conteúdo de um endereço na memória (atalho de visualização). |
| `reset` | CTF Tool | Zera os registradores da máquina virtual. |

## 5. Fluxo de Resolução Esperado (Gabarito do Aluno)

Para resolver o desafio, o aluno terá que aplicar seus conhecimentos de manipulação de ponteiros e operações lógicas em Assembly. O passo a passo ideal executado no terminal será:

```
# 1. Configurar o ponteiro inicial da memória
li $s0, 0x1014

# 2. Inspecionar o primeiro endereço (Metade 1):
lw $t0, 0($s0)
show $t0 
# Retorno: [0x584F525F] (Ruído, continua buscando) -> ASCII: XOR_

# 3. Ao chegar no endereço 0x102C (Metade 2 Criptografada):
lw $t1, 0($s0)
show $t1
# Retorno: [0x107B1114] -> O aluno converte externamente e não faz sentido.

# 4. O Pulo do Gato: Aluno aplica a operação lógica MIPS entre os dois registradores
xor $t2, $t0, $t1

# 5. O aluno verifica o resultado do registrador de destino
show $t2
# Retorno: [0x4834434B] -> O aluno converte externamente e acha "H4CK}"

# 6. Flag: XOR_H4CK

```

---