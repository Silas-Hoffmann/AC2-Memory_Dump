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
    anomalous = []
    noise = {0x00000000, 0xFFFFFFFF, 0x00000001, 0x00000002, 0x00000010, 0x000000FF}

    for addr in sorted(sim.memory.keys()):
        val = sim.memory[addr]
        if val not in noise:
            anomalous.append((addr, val))
            print(f"  -> [!] Endereço anômalo encontrado: 0x{addr:04X} | Valor: 0x{val:08X}")

    assert len(anomalous) == 2, "Deveriam existir exatamente 2 endereços anômalos."

    addr1, val1 = anomalous[0]
    addr2, val2 = anomalous[1]

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
