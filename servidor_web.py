#!/usr/bin/env python3
"""
Servidor Web Seguro para o Desafio CTF MIPS Memory Forensics.
Isolamento total por sessão (UUID), sem execução de comandos do sistema operacional (zero RCE).
"""

import os
import sys
import uuid
import json
import time
import io
import contextlib
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Importa a engine de simulação segura
from simulador import MIPSSimulator, BANNER, HELP_TEXT, FLAG_SECRET

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8080))

# Gerenciamento de sessões em memória
# session_id -> {"sim": MIPSSimulator, "last_active": timestamp, "output_history": list}
SESSIONS = {}
SESSION_TIMEOUT = 1800  # 30 minutos

def get_or_create_session(session_id: str):
    now = time.time()
    # Limpeza de sessões expiradas
    expired = [sid for sid, s in SESSIONS.items() if now - s["last_active"] > SESSION_TIMEOUT]
    for sid in expired:
        del SESSIONS[sid]

    if not session_id or session_id not in SESSIONS:
        new_id = str(uuid.uuid4())
        sim = MIPSSimulator()
        SESSIONS[new_id] = {
            "sim": sim,
            "last_active": now
        }
        return new_id, SESSIONS[new_id]

    SESSIONS[session_id]["last_active"] = now
    return session_id, SESSIONS[session_id]


class CTFRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        # Medidas de segurança HTTP Sandbox
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; font-src https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;")
        super().end_headers()

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_content = self.get_index_html()
            self.wfile.write(html_content.encode("utf-8"))
            return
        elif self.path == "/api/init":
            new_id, _ = get_or_create_session(None)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            banner_init = BANNER.strip() + "\n\n" + HELP_TEXT.strip() + "\n"
            resp = {
                "sessionId": new_id,
                "banner": banner_init
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return
        else:
            self.send_error(404, "Arquivo não encontrado")

    def do_POST(self):
        if self.path == "/api/exec":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 1024:  # Limite rígido para evitar buffer overflow / DoS
                self.send_error(413, "Comando muito longo")
                return

            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                self.send_error(400, "JSON Inválido")
                return

            session_id = data.get("sessionId")
            command = data.get("command", "")

            # Sanitização e limitação do comando
            command = str(command)[:200].strip()

            active_id, session_data = get_or_create_session(session_id)
            sim = session_data["sim"]

            # Captura a saída do simulador
            stdout_buf = io.StringIO()
            with contextlib.redirect_stdout(stdout_buf):
                sim.execute_line(command)

            output = stdout_buf.getvalue()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            resp = {
                "sessionId": active_id,
                "output": output
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
            return
        else:
            self.send_error(404, "Endpoint não encontrado")

    def get_index_html(self):
        return r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mips-forensics</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html, body {
            width: 100%;
            height: 100%;
            background-color: #000000;
            color: #00ff00;
            font-family: 'Courier New', Courier, monospace;
            overflow: hidden;
        }

        #terminal {
            display: flex;
            flex-direction: column;
            width: 100vw;
            height: 100vh;
            padding: 12px;
        }

        #terminalScreen {
            flex: 1;
            overflow-y: auto;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.35;
            font-size: 14px;
        }

        #terminalScreen::-webkit-scrollbar {
            width: 6px;
        }

        #terminalScreen::-webkit-scrollbar-thumb {
            background: #005500;
        }

        .cmd-line {
            margin: 2px 0;
        }

        .cmd-output {
            margin-bottom: 4px;
        }

        .input-bar {
            display: flex;
            align-items: center;
            padding-top: 4px;
            font-size: 14px;
        }

        .prompt {
            color: #00ff00;
            font-weight: bold;
            white-space: nowrap;
            margin-right: 8px;
        }

        #term-input {
            flex: 1;
            background: transparent;
            border: none;
            outline: none;
            color: #00ff00;
            font-family: inherit;
            font-size: 14px;
            caret-color: #00ff00;
        }
    </style>
</head>
<body>

<div id="terminal">
    <div id="terminalScreen"></div>
    <div class="input-bar">
        <span class="prompt">mips-forensics&gt;</span>
        <input type="text" id="term-input" autocomplete="off" spellcheck="false" autofocus>
    </div>
</div>

<script>
    let sessionId = null;
    const screen = document.getElementById("terminalScreen");
    const input = document.getElementById("term-input");

    let history = [];
    let historyIndex = -1;

    async function initSession() {
        try {
            const res = await fetch("/api/init");
            const data = await res.json();
            sessionId = data.sessionId;
            appendOutput(data.banner);
        } catch (err) {
            appendOutput("[-] Erro ao conectar: " + err);
        }
    }

    function appendOutput(text, isCommand = false, cmdText = "") {
        if (isCommand) {
            const p = document.createElement("div");
            p.className = "cmd-line";
            p.innerHTML = `<span class="prompt">mips-forensics&gt;</span> ${escapeHtml(cmdText)}`;
            screen.appendChild(p);
        }

        if (text) {
            const out = document.createElement("div");
            out.className = "cmd-output";
            out.textContent = text;
            screen.appendChild(out);
        }

        screen.scrollTop = screen.scrollHeight;
    }

    function escapeHtml(text) {
        return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    async function sendCommand() {
        const cmd = input.value;
        if (!cmd.trim()) return;

        history.push(cmd);
        historyIndex = history.length;
        input.value = "";

        appendOutput("", true, cmd);

        if (cmd.trim().toLowerCase() === "clear") {
            screen.innerHTML = "";
            return;
        }

        try {
            const res = await fetch("/api/exec", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ sessionId: sessionId, command: cmd })
            });

            const data = await res.json();
            if (data.sessionId) sessionId = data.sessionId;
            if (data.output) {
                appendOutput(data.output);
            }
        } catch (err) {
            appendOutput("[-] Erro: " + err);
        }
    }

    input.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            sendCommand();
        } else if (e.key === "ArrowUp") {
            if (historyIndex > 0) {
                historyIndex--;
                input.value = history[historyIndex];
            }
            e.preventDefault();
        } else if (e.key === "ArrowDown") {
            if (historyIndex < history.length - 1) {
                historyIndex++;
                input.value = history[historyIndex];
            } else {
                historyIndex = history.length;
                input.value = "";
            }
            e.preventDefault();
        }
    });

    document.addEventListener("click", () => input.focus());

    initSession();
</script>

</body>
</html>
"""

def main():
    server_address = (HOST, PORT)
    httpd = HTTPServer(server_address, CTFRequestHandler)
    print(f"[+] Servidor CTF MIPS Sandbox iniciado em http://{HOST}:{PORT}")
    print("[+] Isolamento ativo: sem shell externo, sessões individuais em memória.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Encerrando servidor.")
        httpd.server_close()

if __name__ == "__main__":
    main()
