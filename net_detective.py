#!/usr/bin/env python3
"""
net_detective.py

Scanner de rede local com modo pentest:
  - Descobre hosts ativos via ping
  - Port scanning TCP
  - Banner grabbing
  - Deteccao de versao de servico via nmap (python-nmap)
  - Consulta automatica de CVEs via API NVD
  - Sugestao de ferramentas e comandos por porta aberta

Dependencias:
    pip install rich python-nmap requests scapy
    sudo apt install nmap

Uso:
    python net_detective.py
    python net_detective.py --target 192.168.1.0/24
    python net_detective.py --target 192.168.1.1 --ports 22,80,443
    python net_detective.py --target 192.168.1.1 --pentest
    python net_detective.py --target 192.168.1.1 --pentest --cve
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import nmap as nmap_lib
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False

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
    "pentest":  "bold magenta",
    "cve":      "bold red",
})

console = Console(theme=theme)

# (servico, severidade, descricao, [ferramentas/comandos])
PORT_INFO = {
    21:    ("FTP",           "critical",
            "Transferencia sem criptografia.",
            [
                "nmap --script ftp-anon,ftp-bounce,ftp-syst {ip}",
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{ip}",
                "ftp {ip}  # tente login: anonymous / anonymous",
            ]),
    22:    ("SSH",           "clean",
            "Acesso remoto seguro.",
            [
                "ssh-audit {ip}",
                "nmap --script ssh-auth-methods,ssh-hostkey {ip} -p 22",
                "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{ip}",
            ]),
    23:    ("Telnet",        "critical",
            "Protocolo sem criptografia, credenciais em texto puro.",
            [
                "telnet {ip}",
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://{ip}",
                "nmap --script telnet-encryption,telnet-ntlm-info {ip} -p 23",
            ]),
    25:    ("SMTP",          "warning",
            "Servidor de e-mail exposto, verificar relay aberto.",
            [
                "nmap --script smtp-open-relay,smtp-enum-users {ip} -p 25",
                "nc {ip} 25  # EHLO / VRFY / EXPN",
                "swaks --to test@example.com --server {ip}",
            ]),
    53:    ("DNS",           "warning",
            "Resolver DNS visivel, checar zone transfer e queries externas.",
            [
                "dig axfr @{ip} <dominio>",
                "nmap --script dns-zone-transfer,dns-recursion {ip} -p 53",
                "fierce --dns-servers {ip} --domain <dominio>",
            ]),
    80:    ("HTTP",          "warning",
            "Trafego sem HTTPS.",
            [
                "nikto -h http://{ip}",
                "gobuster dir -u http://{ip} -w /usr/share/wordlists/dirb/common.txt",
                "whatweb http://{ip}",
                "curl -I http://{ip}",
                "nmap --script http-title,http-headers,http-methods {ip} -p 80",
            ]),
    110:   ("POP3",          "warning",
            "E-mail sem criptografia.",
            [
                "nc {ip} 110  # USER admin / PASS password",
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt pop3://{ip}",
            ]),
    135:   ("RPC",           "suspect",
            "RPC exposto, vetor comum em redes Windows.",
            [
                "nmap --script msrpc-enum {ip} -p 135",
                "rpcclient -U '' {ip}",
            ]),
    139:   ("NetBIOS",       "critical",
            "Compartilhamentos Windows visiveis na rede.",
            [
                "nbtscan {ip}",
                "enum4linux -a {ip}",
                "nmap --script nbstat {ip} -p 139",
            ]),
    143:   ("IMAP",          "warning",
            "IMAP sem TLS, credenciais em texto puro.",
            [
                "nc {ip} 143",
                "hydra -l admin -P /usr/share/wordlists/rockyou.txt imap://{ip}",
            ]),
    443:   ("HTTPS",         "clean",
            "Trafego web criptografado.",
            [
                "nikto -h https://{ip} -ssl",
                "sslscan {ip}:443",
                "gobuster dir -u https://{ip} -w /usr/share/wordlists/dirb/common.txt",
                "nmap --script ssl-enum-ciphers,ssl-heartbleed {ip} -p 443",
            ]),
    445:   ("SMB",           "critical",
            "SMB exposto, risco alto. Verifique EternalBlue (MS17-010).",
            [
                "nmap --script smb-vuln-ms17-010,smb-vuln-ms08-067,smb-enum-shares {ip} -p 445",
                "enum4linux -a {ip}",
                "crackmapexec smb {ip}",
                "smbclient -L //{ip} -N",
                "impacket-smbclient {ip}",
            ]),
    1433:  ("MSSQL",         "critical",
            "SQL Server visivel na rede.",
            [
                "nmap --script ms-sql-info,ms-sql-empty-password {ip} -p 1433",
                "hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{ip}",
                "crackmapexec mssql {ip}",
            ]),
    1723:  ("PPTP",          "warning",
            "Protocolo VPN considerado inseguro.",
            [
                "nmap --script pptp-version {ip} -p 1723",
            ]),
    2049:  ("NFS",           "warning",
            "Compartilhamento NFS aberto.",
            [
                "showmount -e {ip}",
                "nmap --script nfs-ls,nfs-showmount,nfs-statfs {ip} -p 2049",
                "mount -t nfs {ip}:/ /mnt/tmp",
            ]),
    3000:  ("Dev/Node",      "warning",
            "Porta tipica de servidor de desenvolvimento.",
            [
                "curl http://{ip}:3000",
                "nikto -h http://{ip}:3000",
                "gobuster dir -u http://{ip}:3000 -w /usr/share/wordlists/dirb/common.txt",
            ]),
    3306:  ("MySQL",         "critical",
            "Banco de dados exposto diretamente na rede.",
            [
                "nmap --script mysql-empty-password,mysql-info,mysql-databases {ip} -p 3306",
                "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{ip}",
                "mysql -h {ip} -u root  # tente sem senha",
            ]),
    3389:  ("RDP",           "suspect",
            "Acesso remoto Windows exposto. Verifique BlueKeep (CVE-2019-0708).",
            [
                "nmap --script rdp-vuln-ms12-020,rdp-enum-encryption {ip} -p 3389",
                "crowbar -b rdp -s {ip}/32 -u administrator -C /usr/share/wordlists/rockyou.txt",
                "xfreerdp /u:administrator /p:password /v:{ip}",
            ]),
    4444:  ("Shell/MSF",     "critical",
            "Porta associada a shells reversos e Metasploit.",
            [
                "nc {ip} 4444  # checar shell ativo",
                "nmap -sV {ip} -p 4444",
            ]),
    5432:  ("PostgreSQL",    "critical",
            "Banco de dados exposto na rede.",
            [
                "nmap --script pgsql-brute {ip} -p 5432",
                "hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://{ip}",
                "psql -h {ip} -U postgres  # tente sem senha",
            ]),
    5900:  ("VNC",           "critical",
            "Acesso remoto de tela sem VPN.",
            [
                "nmap --script vnc-info,vnc-brute {ip} -p 5900",
                "hydra -P /usr/share/wordlists/rockyou.txt vnc://{ip}",
                "vncviewer {ip}",
            ]),
    6379:  ("Redis",         "critical",
            "Redis sem autenticacao por padrao.",
            [
                "redis-cli -h {ip}",
                "redis-cli -h {ip} INFO",
                "redis-cli -h {ip} CONFIG GET *",
                "redis-cli -h {ip} KEYS *",
                "nmap --script redis-info {ip} -p 6379",
            ]),
    8080:  ("HTTP-Alt",      "warning",
            "Porta alternativa HTTP, checar se e painel admin.",
            [
                "nikto -h http://{ip}:8080",
                "gobuster dir -u http://{ip}:8080 -w /usr/share/wordlists/dirb/common.txt",
                "curl -I http://{ip}:8080",
            ]),
    8443:  ("HTTPS-Alt",     "warning",
            "HTTPS alternativo, aplicacao secundaria.",
            [
                "nikto -h https://{ip}:8443 -ssl",
                "sslscan {ip}:8443",
            ]),
    9200:  ("Elasticsearch", "critical",
            "Elasticsearch sem auth, dados possivelmente expostos.",
            [
                "curl http://{ip}:9200",
                "curl http://{ip}:9200/_cat/indices",
                "curl http://{ip}:9200/_cluster/health",
                "nmap --script elasticsearch {ip} -p 9200",
            ]),
    27017: ("MongoDB",       "critical",
            "MongoDB historicamente sem senha por padrao.",
            [
                "mongo {ip}:27017  # conectar sem senha",
                "nmap --script mongodb-info,mongodb-databases {ip} -p 27017",
                "mongosh --host {ip} --port 27017",
            ]),
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


def nmap_service_scan(ip: str, open_ports: list[int]) -> dict:
    """Usa python-nmap para detectar versao de servico e OS."""
    if not HAS_NMAP:
        console.print("  [warning]python-nmap nao instalado. Instale: pip install python-nmap + sudo apt install nmap[/warning]")
        return {}
    try:
        nm = nmap_lib.PortScanner()
        port_str = ",".join(str(p) for p in open_ports)
        console.print(f"  [info]Rodando nmap -sV -O em {ip} nas portas {port_str}...[/info]")
        nm.scan(ip, port_str, arguments="-sV -O --version-intensity 5")
        result = {}
        if ip in nm.all_hosts():
            host_data = nm[ip]
            result["os"] = ""
            if "osmatch" in host_data and host_data["osmatch"]:
                result["os"] = host_data["osmatch"][0].get("name", "")
            result["ports"] = {}
            for proto in host_data.all_protocols():
                for port in host_data[proto]:
                    pdata = host_data[proto][port]
                    result["ports"][port] = {
                        "name":    pdata.get("name", ""),
                        "product": pdata.get("product", ""),
                        "version": pdata.get("version", ""),
                        "extrainfo": pdata.get("extrainfo", ""),
                    }
        return result
    except Exception as e:
        console.print(f"  [warning]Erro no nmap scan: {e}[/warning]")
        return {}


def check_cves(service: str, version: str, max_results: int = 3) -> list[dict]:
    """Consulta CVEs na API publica do NVD (National Vulnerability Database)."""
    if not HAS_REQUESTS:
        return []
    if not service or not version:
        return []
    try:
        query = f"{service} {version}".strip()
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": query, "resultsPerPage": max_results}
        r = requests.get(url, params=params, timeout=8)
        if r.status_code == 200:
            vulns = r.json().get("vulnerabilities", [])
            result = []
            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "")
                desc_list = cve.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "")
                metrics = cve.get("metrics", {})
                score = ""
                if "cvssMetricV31" in metrics:
                    score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "")
                elif "cvssMetricV2" in metrics:
                    score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", "")
                result.append({"id": cve_id, "score": score, "desc": desc[:120]})
            return result
        return []
    except Exception:
        return []


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


def scan_ports(hosts: list[dict], ports: list[int], pentest_mode: bool = False, cve_mode: bool = False) -> list[dict]:
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

        # Nmap service scan (pentest mode)
        nmap_data = {}
        if pentest_mode:
            nmap_data = nmap_service_scan(ip, open_ports)

        table = Table(box=box.SIMPLE, padding=(0, 1))
        table.add_column("Porta",   style="label", width=7, justify="right")
        table.add_column("Servico", width=14)
        table.add_column("Nivel",   width=10, justify="center")
        table.add_column("Observacao", style="info")

        for port in sorted(open_ports):
            svc_version = ""
            if nmap_data and "ports" in nmap_data and port in nmap_data["ports"]:
                pd = nmap_data["ports"][port]
                svc_version = f"{pd['product']} {pd['version']}".strip()

            if port in PORT_INFO:
                svc, severity, comment, tools = PORT_INFO[port]

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
                if svc_version:
                    note += f" | Versao: {svc_version}"
                if port in banners:
                    note += f"\n  Banner: {banners[port]}"

                all_findings.append({
                    "ip": ip, "port": port, "service": svc,
                    "severity": severity, "tools": tools,
                    "version": svc_version,
                })
            else:
                badge = "[warning]DESCONHECIDA[/warning]"
                svc   = "?"
                note  = "Porta sem registro."
                if port in banners:
                    note += f" Banner: {banners[port]}"
                all_findings.append({
                    "ip": ip, "port": port, "service": "desconhecido",
                    "severity": "warning", "tools": [], "version": svc_version,
                })

            table.add_row(str(port), svc, badge, note)

        console.print(table)

        if nmap_data.get("os"):
            console.print(f"  [info]OS detectado: {nmap_data['os']}[/info]")

        # CVE lookup
        if cve_mode and pentest_mode:
            for finding in [f for f in all_findings if f["ip"] == ip]:
                if finding["version"]:
                    cves = check_cves(finding["service"], finding["version"])
                    if cves:
                        console.print(f"  [cve]CVEs encontrados para {finding['service']} {finding['version']}:[/cve]")
                        for c in cves:
                            console.print(f"    [cve]{c['id']}[/cve] [info](Score: {c['score']}) {c['desc']}[/info]")

        console.print()

    return all_findings


def print_pentest_hints(findings: list[dict]):
    """Exibe comandos prontos de pentest para cada porta aberta encontrada."""
    section("Dicas de pentest")

    if not findings:
        console.print("  [info]Nenhuma porta para analisar.[/info]")
        return

    # Agrupa por IP
    by_ip: dict[str, list] = {}
    for f in findings:
        by_ip.setdefault(f["ip"], []).append(f)

    for ip, host_findings in by_ip.items():
        console.print(f"\n[label]>>> {ip}[/label]")
        for f in sorted(host_findings, key=lambda x: x["port"]):
            tools = f.get("tools", [])
            if not tools:
                continue
            severity = f["severity"]
            badge = {
                "clean":    "[clean]OK[/clean]",
                "warning":  "[warning]AVISO[/warning]",
                "suspect":  "[suspect]SUSPEITO[/suspect]",
                "critical": "[critical]CRITICO[/critical]",
            }.get(severity, severity)
            console.print(f"  [label]Porta {f['port']}[/label] ({f['service']}) {badge}")
            for cmd in tools:
                cmd_formatted = cmd.replace("{ip}", ip)
                console.print(f"    [pentest]$[/pentest] [info]{cmd_formatted}[/info]")
        console.print()


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
    parser = argparse.ArgumentParser(
        description="Net Detective: scanner de rede, analise de portas e assistente de pentest."
    )
    parser.add_argument("--target", "-t", default=None,
                        help="Rede ou IP alvo. Ex: 192.168.1.0/24 ou 192.168.1.1")
    parser.add_argument("--ports", "-p", default=None,
                        help="Portas separadas por virgula. Ex: 22,80,443")
    parser.add_argument("--pentest", action="store_true",
                        help="Ativa modo pentest: nmap -sV, deteccao de OS e dicas de ferramentas.")
    parser.add_argument("--cve", action="store_true",
                        help="Consulta CVEs na NVD para cada servico/versao detectado (requer --pentest).")
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

    mode_str = "PENTEST" if args.pentest else "DISCOVERY"
    cve_str  = " + CVE" if args.cve else ""
    console.print(f"[info]Alvo: {target} | {len(ports)} portas | Modo: {mode_str}{cve_str}[/info]\n")

    hosts    = scan_network(target)
    if not hosts:
        console.print("[info]Nenhum host ativo encontrado.[/info]")
        sys.exit(0)

    findings = scan_ports(hosts, ports, pentest_mode=args.pentest, cve_mode=args.cve)
    detect_anomalies(hosts, findings)

    if args.pentest:
        print_pentest_hints(findings)

    print_summary(findings)


if __name__ == "__main__":
    main()
