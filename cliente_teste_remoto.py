#!/usr/bin/env python3
"""
Cliente de Teste / Leitor Remoto de Memória do CTF MIPS.
Conecta na URL remota do desafio, inicia uma sessão e lê os 50 endereços de memória.
"""

import sys
import json
import urllib.request
import urllib.error

# URL base do servidor hospedado
BASE_URL = "https://ac2-memory-dump.onrender.com"

MEM_START = 0x1000
TOTAL_WORDS = 50


def init_session(base_url: str) -> str:
    """Inicia uma sessão e obtém o sessionId único."""
    url = f"{base_url.rstrip('/')}/api/init"
    print(f"[*] Conectando ao servidor: {url}")
    
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "MIPS-CTF-Client/1.0"}
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Erro ao inicializar sessão. Status: {resp.status}")
        data = json.loads(resp.read().decode("utf-8"))
        session_id = data.get("sessionId")
        print(f"[+] Sessão criada com sucesso! SessionId: {session_id}")
        return session_id


def exec_command(base_url: str, session_id: str, command: str) -> str:
    """Envia um comando para o simulador remoto e retorna a saída."""
    url = f"{base_url.rstrip('/')}/api/exec"
    payload = json.dumps({"sessionId": session_id, "command": command}).encode("utf-8")
    
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "MIPS-CTF-Client/1.0"
        }
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Erro ao executar comando '{command}'. Status: {resp.status}")
        data = json.loads(resp.read().decode("utf-8"))
        return data.get("output", "").strip()


def main():
    target_url = sys.argv[1] if len(sys.argv) > 1 else BASE_URL
    print(f"=== TESTE DE LEITURA REMOTA DE MEMÓRIA (CTF MIPS) ===")
    print(f"Alvo: {target_url}\n")

    try:
        session_id = init_session(target_url)
    except urllib.error.URLError as e:
        print(f"[-] Falha na conexão com o servidor: {e}")
        print("[-] Verifique se o serviço no Render está ativo (serviços gratuitos podem demorar ~40s para acordar).")
        sys.exit(1)

    print(f"\n[*] Lendo os {TOTAL_WORDS} endereços de memória via 'show mem'...")
    print("-" * 55)
    print(f"{'Índice':<8} {'Endereço':<16} {'Valor Hex':<16}")
    print("-" * 55)

    dump = {}
    for i in range(TOTAL_WORDS):
        addr = MEM_START + (i * 4)
        cmd = f"show mem 0x{addr:04X}"
        out = exec_command(target_url, session_id, cmd)
        
        # O retorno é no formato: [0x00001000]: 0x000000FF
        parts = out.split(":")
        val_str = parts[1].strip() if len(parts) > 1 else out
        dump[addr] = val_str
        print(f"[{i:02d}]     0x{addr:08X}     {val_str}")

    print("-" * 55)
    print(f"[+] Leitura concluída! Total de endereços lidos: {len(dump)}")
    
    # Exemplo de verificação dos dados recebidos
    print("\n[*] Destaque dos endereços do desafio encontrados no dump:")
    for target in (0x1014, 0x102C):
        if target in dump:
            print(f"  -> Endereço 0x{target:04X}: {dump[target]}")


if __name__ == "__main__":
    main()
