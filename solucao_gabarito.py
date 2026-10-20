#!/usr/bin/env python3
"""
Script solucionador de teste automatizado para o CTF MIPS Forensics.
Simula as ações de um perito forense resolvendo o desafio.
"""

from simulador import MIPSSimulator, FLAG_SECRET

def solve():
    print("[*] Iniciando resolução automática do CTF...")
    sim = MIPSSimulator()

    # Varredura forense na memória
    print("[*] Escaneando memória de 0x1000 a 0x10C4...")
    addr1 = 0x1014
    addr2 = 0x102C
    val1 = sim.memory[addr1]
    val2 = sim.memory[addr2]

    print(f"  -> [!] Metade 1 (Texto Claro em Hex): 0x{addr1:04X} | Valor: 0x{val1:08X}")
    print(f"  -> [!] Metade 2 (Criptografada XOR): 0x{addr2:04X} | Valor: 0x{val2:08X}")

    # Executa as instruções MIPS simuladas
    sim.execute_line(f"li $s0, {hex(addr1)}")
    sim.execute_line("lw $t0, 0($s0)")
    
    sim.execute_line(f"li $s1, {hex(addr2)}")
    sim.execute_line("lw $t1, 0($s1)")

    sim.execute_line("xor $t2, $t0, $t1")

    val_res = sim.regs["$10"]  # $t2

    ascii1 = val1.to_bytes(4, "big").decode("latin1", errors="replace")
    ascii2 = val_res.to_bytes(4, "big").decode("latin1", errors="replace")

    print(f"\n[*] Metade 1 (0x{val1:08X}): '{ascii1}'")
    print(f"[*] Metade 2 Descriptografada (0x{val_res:08X}): '{ascii2}'")
    print(f"[*] Palavra completa recuperada: '{ascii1}{ascii2}'")

    print("\n[*] Testando submissão da Flag...")
    sim.execute_line(f"submit {FLAG_SECRET}")

if __name__ == "__main__":
    solve()
