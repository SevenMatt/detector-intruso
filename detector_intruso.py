import os
import sys
import argparse
import socket
import platform
import datetime
import subprocess
import re

SUSPICIOUS_KEYWORDS = [
    "mimikatz", "nc.exe", "ncat", "netcat", "meterpreter", "cobalt",
    "keylog", "cryptominer", "xmrig", "minerd", "backdoor", "reverse",
    "psexec", "wce", "procdump", "hashcat", "hydra",
    "powershell -enc", "certutil -urlcache", "bitsadmin /transfer",
    "/tmp/sh", "/dev/shm", "python -c import socket"
]

SUSPICIOUS_PORTS = {
    4444: "Metasploit default", 5555: "Reverse shell comum",
    9999: "Reverse shell comum", 1337: "Backdoor comum",
    31337: "Backdoor clássico", 9001: "Shell/C2 comum", 8888: "Shell/C2 comum",
}

RESULTS = []
ACTIONS_TAKEN = []
ATTACKER_IPS = set()

def log(sev, msg):
    icon = {"CRIT": "[!!]", "WARN": "[! ]", "INFO": "[  ]", "ACT": "[>>]"}[sev]
    line = f"{icon} {sev}: {msg}"
    print(line)
    RESULTS.append((sev, msg))

def act(msg):
    print(f"[>>] ACT: {msg}")
    ACTIONS_TAKEN.append(msg)

def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
    except Exception as e:
        return f"ERRO: {e}"

def is_admin():
    if platform.system() == "Windows":
        try:
            return os.getuid() == 0 if hasattr(os, "getuid") else True
        except Exception:
            return True
    return os.geteuid() == 0

#Detecção

def check_processos():
    print("\n[1] PROCESSOS SUSPEITOS")  
    suspeitos = []
    if platform.system() == "Windows":
        out = run(["powershell", "-Command",
                   "Get-CimInstance Win32_Process | "
                   "Select-Object ProcessId,CommandLine | Format-List"])
        cur = {}
        for line in out.splitlines():
            if line.startswith("ProcessId"):
                cur["pid"] = line.split(":", 1)[1].strip()
            elif line.startswith("CommandLine"):
                cur["cmd"] = line.split(":", 1)[1].strip()
                low = cur.get("cmd", "").lower()
                if any(k in low for k in SUSPICIOUS_KEYWORDS):
                    suspeitos.append((cur["pid"], cur["cmd"]))
                    log("CRIT", f"Processo suspeito PID={cur['pid']}: {cur['cmd']}")
                cur = {}
    else:
        out = run(["ps", "-eo", "pid,user,args"])
        for line in out.splitlines()[1:]:
            parts = line.strip().split(None, 2)
            if len(parts) < 3:
                continue
            pid, user, args = parts
            low = args.lower()
            if any(k in low for k in SUSPICIOUS_KEYWORDS):
                suspeitos.append((pid, args))
                log("CRIT", f"Processo suspeito PID={pid} ({user}): {args}")
    return suspeitos

def extrair_ips_e_pids():
    print("\n[2] CONEXÕES DE REDE ATIVAS")
    achados = [] 
    if platform.system() == "Windows":
        out = run(["netstat", "-ano"])
        for line in out.splitlines():
            m = re.match(r"\s*\S+\s+\S+:(\d+)\s+(\S+):(\d+)\s+\S+\s+(\d+)", line)
            if m and "ESTABLISHED" in line.upper():
                port_local, ip_rem, port_rem, pid = m.groups()
                if int(port_local) in SUSPICIOUS_PORTS or int(port_rem) in SUSPICIOUS_PORTS:
                    ATTACKER_IPS.add(ip_rem)
                    achados.append((pid, ip_rem, port_rem))
                    log("CRIT", f"Conexão suspeita PID={pid} -> {ip_rem}:{port_rem}")
    else:
        out = run(["ss", "-tunp"])
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)", line)
            mp = re.search(r"pid=(\d+)", line)
            if m and mp:
                ip_rem, port_rem = m.groups()
                port_par = re.search(r":(\d+)\s", line)
                if (port_par and int(port_par.group(1)) in SUSPICIOUS_PORTS) or \
                   int(port_rem) in SUSPICIOUS_PORTS:
                    ATTACKER_IPS.add(ip_rem)
                    achados.append((mp.group(1), ip_rem, port_rem))
                    log("CRIT", f"Conexão suspeita PID={mp.group(1)} -> {ip_rem}:{port_rem}")
    return achados

PERSIST_RUNKEYS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
]

def check_persistencia():
    print("\n=== [3] PERSISTÊNCIA ===")
    itens = []
    if platform.system() == "Windows":
        for k in PERSIST_RUNKEYS:
            out = run(["reg", "query", k])
            for line in out.splitlines():
                if "REG_" in line:
                    low = line.lower()
                    if any(x in low for x in ["temp", "appdata", "powershell", "vbs", ".exe"]):
                        itens.append(("runkey", k, line.strip()))
                        log("CRIT", f"Run key suspeita: {k} -> {line.strip()}")
        out = run(["schtasks", "/query", "/fo", "csv"])
        for line in out.splitlines():
            low = line.lower()
            if any(x in low for x in ["temp", "powershell", "wget", "curl", ".vbs"]):
                itens.append(("task", None, line))
                log("WARN", f"Tarefa agendada suspeita: {line.strip()}")
    else:
        cron_files = ["/etc/crontab", "/var/spool/cron/crontabs", "/etc/cron.d"]
        for f in cron_files:
            if os.path.isfile(f):
                out = run(["cat", f])
                for line in out.splitlines():
                    if any(x in line.lower() for x in ["/tmp", "/dev/shm", "curl", "wget", "python -c", "nc "]):
                        itens.append(("cron", f, line.strip()))
                        log("CRIT", f"Cron suspeito em {f}: {line.strip()}")
        home = os.path.expanduser("~")
        for f in [f"{home}/.bashrc", f"{home}/.profile", f"{home}/.bash_profile"]:
            if os.path.isfile(f):
                for line in open(f, errors="ignore").read().splitlines():
                    if any(x in line.lower() for x in ["curl", "wget", "nc ", "/tmp", "base64"]):
                        itens.append(("shellrc", f, line.strip()))
                        log("WARN", f"Persistência em {f}: {line.strip()}")
    return itens

def matar_processo(pid):
    if platform.system() == "Windows":
        run(["taskkill", "/F", "/PID", str(pid)])
    else:
        run(["kill", "-9", str(pid)])
    act(f"Processo {pid} finalizado")

def bloquear_ip(ip):
    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return
    if platform.system() == "Windows":
        run(["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=Bloqueio IR {ip}", "dir=in", "action=block", f"remoteip={ip}"])
        run(["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=Bloqueio IR {ip} out", "dir=out", "action=block", f"remoteip={ip}"])
    else:
        out = run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        if "ERRO" not in out:
            run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
        else:
            run(["nft", "add", "rule", "inet", "filter", "input",
                 "ip", "saddr", ip, "drop"])
    act(f"IP {ip} bloqueado no firewall (entrada e saída)")

def matar_conexao_windows(pid, ip, porta):
    matar_processo(pid)

def matar_conexao_linux(ip, porta):
    run(["bash", "-c", f"ss -K dst {ip} dport =:{porta}"])
    act(f"Conexão com {ip}:{porta} encerrada via ss -K")

def remover_persistencia(itens):
    for tipo, ctx, val in itens:
        if tipo == "runkey" and platform.system() == "Windows":
            parts = val.split()
            if parts:
                nome = parts[0]
                run(["reg", "delete", ctx, "/v", nome, "/f"])
                act(f"Run key removida: {nome} de {ctx}")
        elif tipo == "task" and platform.system() == "Windows":
            m = re.search(r'"([^"]+)"', val)
            if m:
                run(["schtasks", "/delete", "/tn", m.group(1), "/f"])
                act(f"Tarefa agendada removida: {m.group(1)}")
        elif tipo == "cron":
            run(["bash", "-c", f"sed -i '\\|{val.split()[0]}|d' {ctx}" if ctx else "true"])
            act(f"Entrada de cron comentada/removida em {ctx}")
        elif tipo == "shellrc":
            run(["bash", "-c", f"sed -i 's|{val}|# REMOVIDO POR IR: {val}|' {ctx}"])
            act(f"Linha de persistência neutralizada em {ctx}")

def conta_suspeita_remover():
    if platform.system() == "Windows": 
        out = run(["net", "localgroup", "administrators"])
        for line in out.splitlines():
            nome = line.strip()
            if nome and nome not in ("Administrator", "Administrador", "O comando foi concluído com êxito.") \
               and nome.startswith("ir_"):
                run(["net", "user", nome, "/delete"])
                act(f"Conta suspeita '{nome}' removida")
    else:
        out = run(["bash", "-c", "awk -F: '$3==0 && $1!=\"root\" {print $1}' /etc/passwd"])
        for u in out.split():
            run(["userdel", "-r", u])
            act(f"Conta root não autorizada '{u}' removida")


def responder(suspeitos, conexoes, persist_itens, confirmar=True):
    print("\n" + "=" * 60)
    print("MODO CONTENÇÃO — REMOÇÃO DO INVASOR")
    print("=" * 60)
    resumo = (f"Processos a finalizar: {[p[0] for p in suspeitos]}\n"
              f"IPs a bloquear: {list(ATTACKER_IPS)}\n"
              f"Itens de persistência: {len(persist_itens)}")
    print(resumo)
    if confirmar:
        r = input("\nConfirmar contenção? (SIM/NÃO): ").strip().upper()
        if r != "SIM":
            print("Contenção cancelada. Nada foi alterado.")
            return

    for ip in list(ATTACKER_IPS):
        bloquear_ip(ip)

    for pid, ip, porta in conexoes:
        if platform.system() == "Windows":
            matar_conexao_windows(pid, ip, porta)
        else:
            matar_conexao_linux(ip, porta)

    for pid, cmd in suspeitos:
        try:
            matar_processo(int(pid))
        except ValueError:
            pass

    remover_persistencia(persist_itens)
    conta_suspeita_remover()

    print("\nCONTENÇÃO CONCLUÍDA")
    for a in ACTIONS_TAKEN:
        print(f"  • {a}")
    print("\nRECOMENDAÇÕES PÓS-CONTENÇÃO:")
    print("  1. Troque todas as senhas de OUTRO dispositivo confiável.")
    print("  2. Revise regras de firewall criadas (nomes começam com 'Bloqueio IR').")
    print("  3. Faça backup/imagens forenses antes de formatar, se necessário.")
    print("  4. Atualize o sistema e verifique o mesmo vetor de entrada novamente.")

def relatorio():
    print("\n" + "=" * 60)
    print("RELATÓRIO FINAL")
    print("=" * 60)
    crit = [r for r in RESULTS if r[0] == "CRIT"]
    warn = [r for r in RESULTS if r[0] == "WARN"]
    print(f"CRÍTICOS: {len(crit)} | AVISOS: {len(warn)} | AÇÕES: {len(ACTIONS_TAKEN)}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Detecção e contenção de intrusos")
    ap.add_argument("--detect", action="store_true", help="apenas detectar")
    ap.add_argument("--respond", action="store_true", help="detectar e conter")
    ap.add_argument("--no-confirm", action="store_true", help="pula confirmação")
    args = ap.parse_args()

    if args.respond and not is_admin():
        print("ERRO: modo --respond requer privilégios de administrador/root.")
        sys.exit(1)

    print(f"Detector de Intrusão — {platform.system()} — {datetime.datetime.now()}")
    print(f"Modo: {'CONTENÇÃO' if args.respond else 'APENAS DETECÇÃO'}\n")

    suspeitos = check_processos()
    conexoes = extrair_ips_e_pids()
    persist_itens = check_persistencia()

    if args.respond:
        responder(suspeitos, conexoes, persist_itens, confirmar=not args.no_confirm)
    relatorio()