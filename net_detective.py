#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║                      NET DETECTIVE  🔍                   ║
╚══════════════════════════════════════════════════════════╝

Dependências:
    pip install rich scapy

Uso:
    python net_detective.py
    python net_detective.py --target 192.168.1.0/24
    python net_detective.py --target 192.168.1.1 --ports 22,80,443,3306,5432
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
import time
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

# ─────────────────────────────────────────────
# TEMA DO DETETIVE — paleta noir
# ─────────────────────────────────────────────
detective_theme = Theme({
    "title":     "bold white on black",
    "clue":      "bold yellow",
    "suspect":   "bold red",
    "clean":     "green",
    "warning":   "bold yellow",
    "critical":  "bold red",
    "info":      "dim white",
    "narrator":  "italic cyan",
    "port_open": "bold green",
    "port_sus":  "bold red",
    "port_warn": "bold yellow",
    "host_up":   "bold green",
    "host_down": "dim red",
})

console = Console(theme=detective_theme)

# ─────────────────────────────────────────────
# BANCO DE EVIDÊNCIAS — portas e o que revelam
# ─────────────────────────────────────────────
PORT_VERDICTS = {
    21:    ("FTP",         "critical", "Transferência de arquivo SEM criptografia. Isso é 1995, não 2024."),
    22:    ("SSH",         "clean",    "Acesso remoto seguro. Parece legítimo — por enquanto."),
    23:    ("Telnet",      "critical", "TELNET? Sério? Qualquer um na rede pode ler tudo em texto puro."),
    25:    ("SMTP",        "warning",  "Servidor de e-mail exposto. Possível relay aberto ou spam farm."),
    53:    ("DNS",         "warning",  "Resolver DNS visível. Verifique se está aceitando queries externas."),
    80:    ("HTTP",        "warning",  "Web sem HTTPS. Dados do usuário trafegam às claras."),
    110:   ("POP3",        "warning",  "E-mail legado sem criptografia. Esqueceram de modernizar isso."),
    135:   ("RPC",         "suspect",  "RPC da Microsoft exposto. Clássico vetor de exploração em redes Windows."),
    139:   ("NetBIOS",     "critical", "NetBIOS ativo. Compartilhamentos Windows visíveis na rede."),
    143:   ("IMAP",        "warning",  "IMAP sem TLS. Credenciais de e-mail viajando em texto claro."),
    443:   ("HTTPS",       "clean",    "Tráfego web criptografado. Tudo certo aqui."),
    445:   ("SMB",         "critical", "SMB exposto. Palavra-chave: EternalBlue, WannaCry. Isso é sério."),
    1433:  ("MSSQL",       "critical", "Banco SQL Server visível na rede. Deveria estar atrás de firewall."),
    1723:  ("PPTP",        "warning",  "VPN PPTP — protocolo considerado quebrado desde 2012."),
    2049:  ("NFS",         "warning",  "Compartilhamento NFS aberto. Quem mais pode montar esse disco?"),
    3000:  ("Dev Server?", "warning",  "Porta popular de dev (Node/React). Alguém esqueceu de desligar?"),
    3306:  ("MySQL",       "critical", "Banco de dados MySQL exposto diretamente na rede. Perigo."),
    3389:  ("RDP",         "suspect",  "Acesso remoto Windows exposto. Força bruta é questão de tempo."),
    4444:  ("Metasploit?", "critical", "Porta 4444 — assinatura clássica de shell reverso ou Metasploit."),
    5432:  ("PostgreSQL",  "critical", "PostgreSQL exposto. Banco de dados não deveria ser público."),
    5900:  ("VNC",         "critical", "VNC sem VPN é convite aberto. Controle remoto de tela exposto."),
    6379:  ("Redis",       "critical", "Redis sem autenticação por padrão. Banco em memória na rede? Não."),
    8080:  ("HTTP Alt",    "warning",  "Porta alternativa HTTP — proxy, painel admin ou servidor de dev?"),
    8443:  ("HTTPS Alt",   "warning",  "HTTPS alternativo — aplicação secundária ou painel de gerência?"),
    9200:  ("Elasticsearch","critical","Elasticsearch sem auth. Dados indexados potencialmente expostos."),
    27017: ("MongoDB",     "critical", "MongoDB — historicamente configurado sem senha por padrão."),
}

# Portas que são SUSPEITAS por não terem motivo de estar abertas em hosts comuns
UNUSUAL_FOR_WORKSTATION = {4444, 6379, 9200, 27017, 2049, 135, 139, 445}

# ─────────────────────────────────────────────
# UTILIDADES
# ─────────────────────────────────────────────

def get_local_network() -> str:
    """Descobre a rede local do host automaticamente."""
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
    """Ping silencioso."""
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
    """Tenta conexão TCP na porta."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def resolve_hostname(ip: str) -> str:
    """Tenta resolver o nome do host."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "desconhecido"


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """Tenta capturar banner do serviço."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(256).decode("utf-8", errors="ignore").strip()
                return banner[:80] if banner else ""
            except Exception:
                return ""
    except Exception:
        return ""


# ─────────────────────────────────────────────
# CENAS DA INVESTIGAÇÃO
# ─────────────────────────────────────────────

def print_intro():
    console.print()
    console.print(Panel(
        Text.assemble(
            ("NET DETECTIVE\n", "bold white"),
            ('"Toda rede tem um segredo.\n', "italic cyan"),
            (' Eu acho os dois."', "italic cyan"),
        ),
        subtitle=f"[info]Iniciado em {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}[/info]",
        border_style="white",
        box=box.DOUBLE,
        padding=(1, 4),
    ))
    console.print()


def print_scene(number: int, title: str):
    console.print()
    console.print(Rule(f"[clue]▸ CENA {number}: {title.upper()}[/clue]", style="dim white"))
    console.print()


def narrate(text: str):
    console.print(f"[narrator]  {text}[/narrator]")


def conclude(findings: list[dict]):
    """Resumo final — o detetive fecha o caso."""
    print_scene(99, "Conclusão do Caso")

    critical = [f for f in findings if f["severity"] == "critical"]
    warnings  = [f for f in findings if f["severity"] == "warning"]
    suspects  = [f for f in findings if f["severity"] == "suspect"]

    score = len(critical) * 3 + len(suspects) * 2 + len(warnings)

    if score == 0:
        verdict = ("REDE LIMPA", "clean",
                   "Não encontrei nada fora do comum. Ou sua rede é impecável, "
                   "ou tem coisa bem escondida. Fico com a segunda.")
    elif score < 5:
        verdict = ("ALGUMAS PISTAS", "warning",
                   "Há pontos de atenção. Nada que grite perigo imediato, "
                   "mas vale investigar antes que alguém o faça por você.")
    elif score < 12:
        verdict = ("CENA COMPROMETIDA", "suspect",
                   "Múltiplos serviços expostos sem necessidade aparente. "
                   "Isso não é descuido — é um padrão. Alguém não revisou isso há tempo demais.")
    else:
        verdict = ("PERIGO REAL", "critical",
                   "Essa rede está aberta como um livro. Serviços críticos expostos, "
                   "protocolos obsoletos ativos. Se um atacante chegou até aqui, já foi longe demais.")

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column(style="dim white", width=18)
    table.add_column()

    table.add_row("Veredicto",    f"[{verdict[1]}]{verdict[0]}[/{verdict[1]}]")
    table.add_row("Críticos",     f"[critical]{len(critical)}[/critical]")
    table.add_row("Suspeitos",    f"[suspect]{len(suspects)}[/suspect]")
    table.add_row("Avisos",       f"[warning]{len(warnings)}[/warning]")
    table.add_row("Pontuação",    f"[clue]{score} pts[/clue]")

    console.print(Panel(table, title="[clue]📁 DOSSIÊ FINAL[/clue]", border_style="white"))
    console.print()
    narrate(verdict[2])
    console.print()


# ─────────────────────────────────────────────
# LÓGICA PRINCIPAL
# ─────────────────────────────────────────────

def scan_network(network: str) -> list[dict]:
    """Varre a rede e encontra hosts ativos."""
    print_scene(1, "Reconhecimento do território")
    narrate(f"Esquadrinhando {network}. Cada endereço é um suspeito em potencial...")
    console.print()

    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        console.print(f"[critical]  Endereço de rede inválido: {network}[/critical]")
        sys.exit(1)

    hosts = list(net.hosts())
    active = []

    table = Table(
        title="Hosts Encontrados",
        box=box.SIMPLE_HEAD,
        border_style="dim white",
        show_lines=False,
    )
    table.add_column("IP",        style="clue",    width=16)
    table.add_column("Hostname",  style="info",    width=30)
    table.add_column("Status",    justify="center", width=10)
    table.add_column("Observação", style="narrator")

    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[info]{task.description}[/info]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Batendo em todas as portas do bairro...", total=len(hosts))

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
        note = ""
        if h["hostname"] != "desconhecido":
            note = "Identificado pelo DNS reverso"
        table.add_row(
            h["ip"],
            h["hostname"],
            "[host_up]● ATIVO[/host_up]",
            note,
        )

    if not active:
        narrate("Nenhum host respondeu. Rede vazia — ou muito bem protegida.")
        return []

    console.print(table)
    narrate(f"{len(active)} suspeito(s) identificado(s). Hora de bater na porta de cada um.")
    return active


def scan_ports(hosts: list[dict], ports: list[int]) -> list[dict]:
    """Analisa portas de cada host e emite veredictos."""
    print_scene(2, "Análise dos suspeitos")
    narrate("Cada porta aberta é uma pista. Cada serviço exposto, uma testemunha.")
    console.print()

    all_findings = []

    for host in hosts:
        ip       = host["ip"]
        hostname = host["hostname"]

        console.print(f"[clue]🔍 Investigando {ip}[/clue] [info]({hostname})[/info]")

        open_ports = []

        with ThreadPoolExecutor(max_workers=32) as ex:
            results = {ex.submit(check_port, ip, p): p for p in ports}
            for future in as_completed(results):
                port = results[future]
                if future.result():
                    open_ports.append(port)

        if not open_ports:
            console.print("   [info]Nenhuma porta respondeu. Host quieto demais — suspeito à sua maneira.[/info]")
            console.print()
            continue

        # Tenta banner nas portas abertas
        banners = {}
        for port in open_ports:
            b = grab_banner(ip, port)
            if b:
                banners[port] = b

        table = Table(box=box.SIMPLE, padding=(0, 1), show_header=True)
        table.add_column("Porta",    style="clue",    width=7, justify="right")
        table.add_column("Serviço",  width=14)
        table.add_column("Nível",    width=10, justify="center")
        table.add_column("Observação do Detetive", style="info")

        for port in sorted(open_ports):
            if port in PORT_VERDICTS:
                svc, severity, comment = PORT_VERDICTS[port]

                # Agrava se for porta incomum em workstation
                if port in UNUSUAL_FOR_WORKSTATION and severity != "critical":
                    severity = "critical"
                    comment += " [Incomum para este tipo de host.]"

                badge = {
                    "clean":    "[clean]✔ OK[/clean]",
                    "warning":  "[warning]⚠ AVISO[/warning]",
                    "suspect":  "[suspect]⚡ SUSPEITO[/suspect]",
                    "critical": "[critical]✖ CRÍTICO[/critical]",
                }.get(severity, severity)

                # Adiciona banner se capturado
                full_comment = comment
                if port in banners:
                    full_comment += f"\n  [dim]  Banner: {banners[port]}[/dim]"

                all_findings.append({
                    "ip":       ip,
                    "port":     port,
                    "service":  svc,
                    "severity": severity,
                    "comment":  comment,
                })

            else:
                badge        = "[warning]? DESCONHECIDA[/warning]"
                svc          = "?"
                full_comment = "Porta sem registro. O que está rodando aqui?"
                all_findings.append({
                    "ip":       ip,
                    "port":     port,
                    "service":  "desconhecido",
                    "severity": "warning",
                    "comment":  full_comment,
                })

            table.add_row(str(port), svc, badge, full_comment)

        console.print(table)
        console.print()

    return all_findings


def detect_anomalies(hosts: list[dict], findings: list[dict]):
    """Busca padrões anômalos entre os hosts."""
    print_scene(3, "Análise de padrões")
    narrate("O detetive recua. Olha o quadro completo. Procura o que não deveria estar lá.")
    console.print()

    anomalies_found = False

    # Hosts com muitas portas abertas
    from collections import Counter
    port_count = Counter(f["ip"] for f in findings)
    for ip, count in port_count.items():
        if count > 8:
            console.print(f"  [suspect]⚡ {ip}[/suspect] [info]tem[/info] [clue]{count} portas abertas[/clue][info]. "
                          f"Servidor legítimo ou máquina comprometida fazendo barulho?[/info]")
            anomalies_found = True

    # Portas de dev esquecidas
    dev_ports = {3000, 8080, 4000, 5000, 8888}
    for f in findings:
        if f["port"] in dev_ports:
            console.print(f"  [warning]⚠ {f['ip']}:{f['port']}[/warning] [info]— Porta de desenvolvimento ativa. "
                          f"Servidor de produção com ambiente de dev rodando?[/info]")
            anomalies_found = True

    # Múltiplos bancos de dados expostos no mesmo host
    db_ports = {3306, 5432, 1433, 27017, 6379, 9200}
    db_per_host: dict[str, list] = {}
    for f in findings:
        if f["port"] in db_ports:
            db_per_host.setdefault(f["ip"], []).append(f["port"])
    for ip, dbs in db_per_host.items():
        if len(dbs) > 1:
            ports_str = ", ".join(str(p) for p in dbs)
            console.print(f"  [critical]✖ {ip}[/critical] [info]tem[/info] [clue]{len(dbs)} bancos de dados expostos[/clue] "
                          f"[info]({ports_str}). Esse host é um banco de dados ou um museu aberto ao público?[/info]")
            anomalies_found = True

    # Telnet + SSH no mesmo host
    for ip in set(f["ip"] for f in findings):
        host_ports = {f["port"] for f in findings if f["ip"] == ip}
        if 22 in host_ports and 23 in host_ports:
            console.print(f"  [critical]✖ {ip}[/critical] [info]— Tem SSH e Telnet abertos. "
                          f"Alguém instalou o cadeado mas deixou a janela aberta.[/info]")
            anomalies_found = True

    if not anomalies_found:
        narrate("Nenhum padrão anômalo detectado entre os hosts. Rede comportada.")

    console.print()


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 1433, 1723, 2049, 3000, 3306, 3389,
    4444, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
]


def main():
    parser = argparse.ArgumentParser(
        description="Net Detective — análise de rede com opinião.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target", "-t",
        default=None,
        help="Rede ou IP alvo (ex: 192.168.1.0/24 ou 192.168.1.1). "
             "Se omitido, detecta automaticamente.",
    )
    parser.add_argument(
        "--ports", "-p",
        default=None,
        help="Portas separadas por vírgula (ex: 22,80,443). "
             "Se omitido, usa lista padrão de portas suspeitas.",
    )
    args = parser.parse_args()

    target = args.target or get_local_network()

    ports = DEFAULT_PORTS
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            console.print("[critical]Portas inválidas. Use o formato: 22,80,443[/critical]")
            sys.exit(1)

    print_intro()
    narrate(f"Alvo: [clue]{target}[/clue]. {len(ports)} portas sob investigação.")
    console.print()

    hosts    = scan_network(target)
    if not hosts:
        console.print("[info]Nenhum host encontrado. Encerrando investigação.[/info]")
        sys.exit(0)

    findings = scan_ports(hosts, ports)
    detect_anomalies(hosts, findings)
    conclude(findings)


if __name__ == "__main__":
    main()
