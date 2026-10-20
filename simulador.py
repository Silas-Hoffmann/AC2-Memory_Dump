#!/usr/bin/env python3
"""
CTF MIPS Memory Forensics Simulator
Desafio de Arquitetura de Computadores / Engenharia Reversa em MIPS
"""

import re
import sys
import random

BANNER = r"""
================================================================================
  _____ _____ _____   __  __ _____ _____   _____     _           _     
 / ____|_   _/ ____| |  \/  |_   _|  __ \ / ____|   | |         | |    
| |      | || |  __  | \  / | | | | |__) | (___     | |     __ _| |__  
| |      | || | |_ | | |\/| | | | |  ___/ \___ \    | |    / _` | '_ \ 
| |____ _| || |__| | | |  | |_| |_| |     ____) |   | |___| (_| | |_) |
 \_____|_____\_____| |_|  |_|_____|_|    |_____/    |______\__,_|_.__/ 
                                                                       
        SISTEMA DE RECUPERAÇÃO FORENSE DE MEMÓRIA CRÍTICA (MIPS-32)
================================================================================
"""

HELP_TEXT = """
Instruções Suportadas:
--------------------------------------------------------------------------------
Comandos MIPS:
  li $reg, imm             -> Carrega endereço em $reg
  lw $rt, offset($rs)      -> Lê 32 bits da memória em $rt
  addi $rt, $rs, imm       -> Soma imediata
  xor $rd, $rs, $rt        -> XOR bit a bit
  show $reg                -> Exibe o valor do registrador em Hexadecimal
  show mem offset($rs)     -> Inspeciona diretamente o conteúdo da memória em Hex
  dump                     -> Exibe os valores de todos os registradores ativos
  reset                    -> Reseta todos os registradores para zero
  submit <flag>            -> Valida a flag encontrada
  help                     -> Exibe o menu de ajuda
--------------------------------------------------------------------------------
"""

FLAG_SECRET = "donotshare{53cur1tyfl49}"

# Endereços e Dados do Desafio
MEM_START = 0x1000
MEM_END = 0x10C4
ADDR_HALF1 = 0x1014
VAL_HALF1 = 0x584F525F  # 'XOR_'

ADDR_HALF2 = 0x102C  # Alinhado em 4 bytes (offset 44)
VAL_HALF2 = 0x107B1114  # 'XOR_' ^ 'H4CK' = 0x584F525F ^ 0x4834434B


class MIPSSimulator:
    def __init__(self):
        self.regs = {f"${i}": 0 for i in range(32)}
        # Mapeamento com nomes amigáveis MIPS
        self.reg_aliases = {
            "$zero": "$0", "$at": "$1",
            "$v0": "$2", "$v1": "$3",
            "$a0": "$4", "$a1": "$5", "$a2": "$6", "$a3": "$7",
            "$t0": "$8", "$t1": "$9", "$t2": "$10", "$t3": "$11",
            "$t4": "$12", "$t5": "$13", "$t6": "$14", "$t7": "$15",
            "$s0": "$16", "$s1": "$17", "$s2": "$18", "$s3": "$19",
            "$s4": "$20", "$s5": "$21", "$s6": "$22", "$s7": "$23",
            "$t8": "$24", "$t9": "$25",
            "$k0": "$26", "$k1": "$27",
            "$gp": "$28", "$sp": "$29", "$fp": "$30", "$ra": "$31"
        }
        self.memory = {}
        self.init_memory()

    def init_memory(self):
        """Inicializa o bloco de 50 palavras de memória (0x1000 a 0x10C4)."""
        # Semente fixa para ruído reprodutível com valores hexadecimais realistas de 32 bits
        rng = random.Random(1337)

        def is_ascii_printable(val: int) -> bool:
            b = val.to_bytes(4, "big")
            return all(32 <= x <= 126 for x in b)

        addr = MEM_START
        while addr <= MEM_END:
            while True:
                # Gera valores hexadecimais variados de 32 bits (dump de memória real)
                cand = rng.randint(0x10000000, 0xEFFFFFFF)
                # Garante que nenhum ruído forme texto ASCII legível por acidente
                if not is_ascii_printable(cand) and cand not in (VAL_HALF1, VAL_HALF2):
                    self.memory[addr] = cand
                    break
            addr += 4

        # Injeta os dois blocos do desafio
        self.memory[ADDR_HALF1] = VAL_HALF1
        self.memory[ADDR_HALF2] = VAL_HALF2

    def canonical_reg(self, name: str) -> str:
        name = name.lower().strip()
        if not name.startswith("$"):
            name = "$" + name
        if name in self.reg_aliases:
            return self.reg_aliases[name]
        if name in self.regs:
            return name
        return None

    def get_reg_name(self, canon: str) -> str:
        for alias, c in self.reg_aliases.items():
            if c == canon:
                return alias
        return canon

    def parse_immediate(self, val_str: str) -> int:
        val_str = val_str.strip()
        if val_str.lower().startswith("0x"):
            return int(val_str, 16)
        return int(val_str, 10)

    def parse_offset_reg(self, token: str):
        """Analisa strings no formato offset($reg), ex: 0($s0), 4($16), ($s0)"""
        match = re.match(r"^([+-]?(?:0x[0-9a-fA-F]+|\d+))?\s*\(\s*(\$[a-zA-Z0-9]+)\s*\)$", token.strip())
        if not match:
            return None, None
        offset_str, reg_str = match.groups()
        offset = self.parse_immediate(offset_str) if offset_str else 0
        reg = self.canonical_reg(reg_str)
        return offset, reg

    def execute_line(self, line: str):
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        # Trata comandos do terminal CTF primeiro
        if line.lower() in ("help", "?"):
            print(HELP_TEXT)
            return

        if line.lower() == "reset":
            for r in self.regs:
                self.regs[r] = 0
            print("[+] Registradores resetados")
            return

        if line.lower() == "dump":
            self.cmd_dump()
            return

        if line.lower().startswith("submit"):
            parts = line.split(maxsplit=1)
            if len(parts) < 2:
                print("[-] Uso: submit <flag>")
                return
            submitted = parts[1].strip()
            self.check_submission(submitted)
            return

        if line.lower().startswith("show mem"):
            self.cmd_show_mem(line[8:].strip())
            return

        if line.lower().startswith("show"):
            self.cmd_show_reg(line[4:].strip())
            return

        # Parsing de instruções Assembly MIPS
        tokens = [t.strip().rstrip(",") for t in line.split() if t.strip()]
        if not tokens:
            return

        op = tokens[0].lower()

        if op == "li":
            # li $reg, imm
            if len(tokens) != 3:
                print("[-] Erro de sintaxe")
                return
            reg = self.canonical_reg(tokens[1])
            if not reg or reg == "$0":
                print(f"[-] Registrador inválido ou somente leitura: {tokens[1]}")
                return
            try:
                imm = self.parse_immediate(tokens[2]) & 0xFFFFFFFF
                self.regs[reg] = imm
            except ValueError:
                print(f"[-] Imediato inválido: {tokens[2]}")

        elif op == "lw":
            # lw $rt, offset($rs)
            if len(tokens) != 3:
                print("[-] Erro de sintaxe")
                return
            rt = self.canonical_reg(tokens[1])
            if not rt or rt == "$0":
                print(f"[-] Registrador de destino inválido: {tokens[1]}")
                return
            offset, rs = self.parse_offset_reg(tokens[2])
            if rs is None:
                print(f"[-] Formato de operando de memória inválido: {tokens[2]}. Exemplo esperado: 0($s0)")
                return
            addr = (self.regs[rs] + offset) & 0xFFFFFFFF
            if addr % 4 != 0:
                print(f"[-] Erro de Alinhamento: Endereço 0x{addr:08X} não está alinhado a 4 bytes.")
                return
            if addr not in self.memory:
                print(f"[-] Falha de Segmentação: Endereço 0x{addr:08X} fora da faixa mapeada.")
                return
            self.regs[rt] = self.memory[addr] & 0xFFFFFFFF

        elif op == "addi":
            # addi $rt, $rs, imm
            if len(tokens) != 4:
                print("[-] Erro de sintaxe")
                return
            rt = self.canonical_reg(tokens[1])
            rs = self.canonical_reg(tokens[2])
            if not rt or not rs or rt == "$0":
                print("[-] Registrador(es) inválido(s).")
                return
            try:
                imm = self.parse_immediate(tokens[3])
                self.regs[rt] = (self.regs[rs] + imm) & 0xFFFFFFFF
            except ValueError:
                print(f"[-] Imediato inválido: {tokens[3]}")

        elif op == "xor":
            # xor $rd, $rs, $rt
            if len(tokens) != 4:
                print("[-] Erro de sintaxe")
                return
            rd = self.canonical_reg(tokens[1])
            rs = self.canonical_reg(tokens[2])
            rt = self.canonical_reg(tokens[3])
            if not rd or not rs or not rt or rd == "$0":
                print("[-] Registrador(es) inválido(s).")
                return
            self.regs[rd] = (self.regs[rs] ^ self.regs[rt]) & 0xFFFFFFFF

        else:
            print(f"[-] Instrução ou comando desconhecido: '{op}'. Digite 'help' para ajuda.")

    def cmd_show_reg(self, arg: str):
        reg = self.canonical_reg(arg)
        if not reg:
            print(f"[-] Registrador desconhecido: '{arg}'.")
            return
        val = self.regs[reg]
        print(f"[0x{val:08X}]")

    def cmd_show_mem(self, arg: str):
        # Suporta tanto 0($s0) quanto endereço direto 0x1014
        offset, rs = self.parse_offset_reg(arg)
        if rs is not None:
            addr = (self.regs[rs] + offset) & 0xFFFFFFFF
        else:
            try:
                addr = self.parse_immediate(arg) & 0xFFFFFFFF
            except ValueError:
                print(f"[-] Endereço ou formato de memória inválido: '{arg}'")
                return

        if addr % 4 != 0:
            print(f"[-] Endereço 0x{addr:08X} desalinhado.")
            return

        if addr in self.memory:
            val = self.memory[addr]
            print(f"[0x{addr:08X}]: 0x{val:08X}")
        else:
            print(f"[-] Endereço 0x{addr:08X} fora da faixa de memória alocada.")

    def cmd_dump(self):
        print("\n--- Estado dos Registradores Ativos ---")
        count = 0
        for i in range(32):
            canon = f"${i}"
            val = self.regs[canon]
            alias = self.get_reg_name(canon)
            if val != 0 or alias in ("$s0", "$t0", "$t1", "$t2"):
                print(f"{alias:<5} ({canon:<3}): 0x{val:08X}   ", end="")
                count += 1
                if count % 3 == 0:
                    print()
        if count % 3 != 0:
            print()
        print("---------------------------------------\n")

    def check_submission(self, submitted: str):
        sub_clean = submitted.strip().strip('"').strip("'")
        # Aceita a flag padrão do desafio ou o valor recuperado
        if sub_clean == FLAG_SECRET:
            print("\n" + "=" * 60)
            print("  PARABÉNS! FLAG CORRETA SUBMETIDA COM SUCESSO!")
            print(f"  Flag: {FLAG_SECRET}")
            print("  Você concluiu o desafio forense MIPS.")
            print("=" * 60 + "\n")
        elif sub_clean.upper() == "XOR_H4CK":
            print("\n[+] Excelente! Você recuperou os dados da memória com sucesso!")
            print(f"[+] Flag do desafio desbloqueada. Entregue a seguinte flag para finalizar: {FLAG_SECRET}\n")
        else:
            print(f"[-] Flag incorreta: '{sub_clean}'. Continue tentando!\n")


def main():
    print(BANNER)
    print(HELP_TEXT)
    sim = MIPSSimulator()
    while True:
        try:
            line = input("mips-forensics> ")
            sim.execute_line(line)
        except (KeyboardInterrupt, EOFError):
            print("\n[+] Saindo...")
            break


if __name__ == "__main__":
    main()
