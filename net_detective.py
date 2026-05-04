#!/usr/bin/env python3
"""
net_detective.py

Scanner de rede local: descobre hosts ativos via ping, realiza port scanning
TCP e classifica cada porta aberta por nivel de risco.

Dependencias:
    pip install rich scapy

Uso:
    python net_detective.py
    python net_detective.py --target 192.168.1.0/24
    python net_detective.py --target 192.168.1.1 --ports 22,80,443
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

theme = Theme({
    "title":    "bold white on black",
    "clean":    "green",
    "warning":  "bold yellow",
    "suspect":  "bold red",
    "critical": "bold red",
    "info":     "dim white",
    "label":    "cyan",
    "host_up":  "bold green",
})

console = Console(theme=theme)

PORT_INFO = {
    21:    ("FTP",           "critical", "Transferencia sem criptografia."),
    22:    ("SSH",           "clean",    "Acesso remoto seguro."),
    23:    ("Telnet",        "critical", "Protocolo sem criptografia, credenciais em texto puro."),
    25:    ("SMTP",          "warning",  "Servidor de e-mail exposto, verificar relay aberto."),
    53:    ("DNS",           "warning",  "Resolver DNS visivel, checar queries externas."),
    80:    ("HTTP",          "warning",  "Trafego sem HTTPS."),
    110:   ("POP3",          "warning",  "E-mail sem criptografia."),
    135:   ("RPC",           "suspect",  "RPC exposto, vetor comum em redes Windows."),
    139:   ("NetBIOS",       "critical", "Compartilhamentos Windows visiveis na rede."),
    143:   ("IMAP",          "warning",  "IMAP sem TLS, credenciais em texto puro."),
    443:   ("HTTPS",         "clean",    "Trafego web criptografado."),
    445:   ("SMB",           "critical", "SMB exposto, risco alto em redes nao segmentadas."),
    1433:  ("MSSQL",         "critical", "SQL Server visivel na rede."),
    1723:  ("PPTP",          "warning",  "Protocolo VPN considerado inseguro."),
    2049:  ("NFS",           "warning",  "Compartilhamento NFS aberto."),
    3000:  ("Dev/Node",      "warning",  "Porta tipica de servidor de desenvolvimento."),
    3306:  ("MySQL",         "critical", "Banco de dados exposto diretamente na rede."),
    3389:  ("RDP",           "suspect",  "Acesso remoto Windows exposto."),
    4444:  ("Shell/MSF",     "critical", "Porta associada a shells reversos e Metasploit."),
    5432:  ("PostgreSQL",    "critical", "Banco de dados exposto na rede."),
    5900:  ("VNC",           "critical", "Acesso remoto de tela sem VPN."),
    6379:  ("Redis",         "critical", "Redis sem autenticacao por padrao."),
    8080:  ("HTTP-Alt",      "warning",  "Porta alternativa HTTP, checar se e painel admin."),
    8443:  ("HTTPS-Alt",     "warning",  "HTTPS alternativo, aplicacao secundaria."),
    9200:  ("Elasticsearch", "critical", "Elasticsearch sem auth, dados possivelmente expostos."),
    27017: ("MongoDB",       "critical", "MongoDB historicamente sem senha por padrao."),
}

INSTABLE_ON_WORKSTATION = {4444, 6379, 9200, 27017, 2049, 135, 139, 445}


def get_local_network() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def ping_host(ip: str) -> bool:
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", str(ip)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return result.returncode == 0
    except Exception:
        return False


def check_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256).decode("utf-8", errors="ignore").strip()
                return data[:80] if data else ""
            except Exception:
                return ""
    except Exception:
        return ""


def print_header():
    console.print()
    console.print(Panel(
        Text.assemble(
            ("Net Detective\n", "bold white"),
            (f"Iniciado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", "dim white"),
        ),
        border_style="white",
        box=box.DOUBLE,
        padding=(1, 4),
    ))
    console.print()


def section(title: str):
    console.print()
    console.print(Rule(f"[label] {title.upper()} [/label]", style="dim white"))
    console.print()


def scan_network(network: str) -> list[dict]:
    section("Descoberta de hosts")
    console.print(f"[info]Rede alvo: {network}[/info]")
    console.print()

    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        console.print(f"[critical]Rede invalida: {network}[/critical]")
        sys.exit(1)

    hosts = list(net.hosts())
    active = []

    table = Table(
        title="Hosts ativos",
        box=box.SIMPLE_HEAD,
        border_style="dim white",
    )
    table.add_column("IP",       style="label", width=16)
    table.add_column("Hostname", style="info",  width=30)
    table.add_column("Status",   justify="center", width=10)

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[info]{task.description}[/info]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Varrendo {len(hosts)} enderecos...", total=len(hosts))

        def check(ip):
            up = ping_host(str(ip))
            progress.advance(task)
            return str(ip), up

        with ThreadPoolExecutor(max_workers=64) as ex:
            futures = {ex.submit(check, ip): ip for ip in hosts}
            for future in as_completed(futures):
                ip_str, up = future.result()
                if up:
                    hostname = resolve_hostname(ip_str)
                    active.append({"ip": ip_str, "hostname": hostname})

    for h in sorted(active, key=lambda x: list(map(int, x["ip"].split(".")))):
        table.add_row(h["ip"], h["hostname"], "[host_up]ATIVO[/host_up]")

    if not active:
        console.print("[info]Nenhum host encontrado.[/info]")
        return []

    console.print(table)
    console.print(f"[info]{len(active)} host(s) encontrado(s).[/info]")
    return active


def scan_ports(hosts: list[dict], ports: list[int]) -> list[dict]:
    section("Port scanning")

    all_findings = []

    for host in hosts:
        ip       = host["ip"]
        hostname = host["hostname"]

        console.print(f"[label]{ip}[/label] [info]({hostname})[/info]")

        open_ports = []
        with ThreadPoolExecutor(max_workers=32) as ex:
            results = {ex.submit(check_port, ip, p): p for p in ports}
            for future in as_completed(results):
                port = results[future]
                if future.result():
                    open_ports.append(port)

        if not open_ports:
            console.print("  [info]Nenhuma porta aberta detectada.[/info]\n")
            continue

        banners = {}
        for port in open_ports:
            b = grab_banner(ip, port)
            if b:
                banners[port] = b

        table = Table(box=box.SIMPLE, padding=(0, 1))
        table.add_column("Porta",   style="label", width=7, justify="right")
        table.add_column("Servico", width=14)
        table.add_column("Nivel",   width=10, justify="center")
        table.add_column("Observacao", style="info")

        for port in sorted(open_ports):
            if port in PORT_INFO:
                svc, severity, comment = PORT_INFO[port]

                if port in INSTABLE_ON_WORKSTATION and severity != "critical":
                    severity = "critical"
                    comment += " Incomum para este tipo de host."

                badge = {
                    "clean":    "[clean]OK[/clean]",
                    "warning":  "[warning]AVISO[/warning]",
                    "suspect":  "[suspect]SUSPEITO[/suspect]",
                    "critical": "[critical]CRITICO[/critical]",
                }.get(severity, severity)

                note = comment
                if port in banners:
                    note += f"\n  Banner: {banners[port]}"

                all_findings.append({"ip": ip, "port": port, "service": svc, "severity": severity})
            else:
                badge = "[warning]DESCONHECIDA[/warning]"
                svc   = "?"
                note  = "Porta sem registro."
                all_findings.append({"ip": ip, "port": port, "service": "desconhecido", "severity": "warning"})

            table.add_row(str(port), svc, badge, note)

        console.print(table)
        console.print()

    return all_findings


def detect_anomalies(hosts: list[dict], findings: list[dict]):
    section("Analise de anomalias")

    found = False

    port_count = Counter(f["ip"] for f in findings)
    for ip, count in port_count.items():
        if count > 8:
            console.print(f"  [suspect]{ip}[/suspect] [info]tem {count} portas abertas.[/info]")
            found = True

    dev_ports = {3000, 8080, 4000, 5000, 8888}
    for f in findings:
        if f["port"] in dev_ports:
            console.print(f"  [warning]{f['ip']}:{f['port']}[/warning] [info]Porta de desenvolvimento ativa em producao.[/info]")
            found = True

    db_ports = {3306, 5432, 1433, 27017, 6379, 9200}
    db_per_host: dict[str, list] = {}
    for f in findings:
        if f["port"] in db_ports:
            db_per_host.setdefault(f["ip"], []).append(f["port"])
    for ip, dbs in db_per_host.items():
        if len(dbs) > 1:
            ports_str = ", ".join(str(p) for p in dbs)
            console.print(f"  [critical]{ip}[/critical] [info]tem {len(dbs)} bancos de dados expostos ({ports_str}).[/info]")
            found = True

    for ip in set(f["ip"] for f in findings):
        host_ports = {f["port"] for f in findings if f["ip"] == ip}
        if 22 in host_ports and 23 in host_ports:
            console.print(f"  [critical]{ip}[/critical] [info]SSH e Telnet abertos simultaneamente.[/info]")
            found = True

    if not found:
        console.print("  [info]Nenhuma anomalia detectada.[/info]")

    console.print()


def print_summary(findings: list[dict]):
    section("Resumo")

    critical = [f for f in findings if f["severity"] == "critical"]
    warnings  = [f for f in findings if f["severity"] == "warning"]
    suspects  = [f for f in findings if f["severity"] == "suspect"]
    score = len(critical) * 3 + len(suspects) * 2 + len(warnings)

    if score == 0:
        verdict, style = "Rede limpa", "clean"
    elif score < 5:
        verdict, style = "Pontos de atencao", "warning"
    elif score < 12:
        verdict, style = "Multiplos servicos expostos", "suspect"
    else:
        verdict, style = "Risco alto", "critical"

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="dim white", width=16)
    table.add_column()
    table.add_row("Veredicto", f"[{style}]{verdict}[/{style}]")
    table.add_row("Criticos",  f"[critical]{len(critical)}[/critical]")
    table.add_row("Suspeitos", f"[suspect]{len(suspects)}[/suspect]")
    table.add_row("Avisos",    f"[warning]{len(warnings)}[/warning]")
    table.add_row("Score",     f"[label]{score}[/label]")

    console.print(Panel(table, title="[label]Resultado[/label]", border_style="white"))
    console.print()


DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 1433, 1723, 2049, 3000, 3306, 3389,
    4444, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
]


def main():
    parser = argparse.ArgumentParser(description="Net Detective: scanner de rede e analise de portas.")
    parser.add_argument("--target", "-t", default=None,
                        help="Rede ou IP alvo. Ex: 192.168.1.0/24 ou 192.168.1.1")
    parser.add_argument("--ports", "-p", default=None,
                        help="Portas separadas por virgula. Ex: 22,80,443")
    args = parser.parse_args()

    target = args.target or get_local_network()
    ports  = DEFAULT_PORTS

    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            console.print("[critical]Formato de portas invalido. Use: 22,80,443[/critical]")
            sys.exit(1)

    print_header()
    console.print(f"[info]Alvo: {target} | {len(ports)} portas[/info]\n")

    hosts    = scan_network(target)
    if not hosts:
        console.print("[info]Nenhum host ativo encontrado.[/info]")
        sys.exit(0)

    findings = scan_ports(hosts, ports)
    detect_anomalies(hosts, findings)
    print_summary(findings)


if __name__ == "__main__":
    main()
