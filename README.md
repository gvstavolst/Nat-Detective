# Net Detective

Scanner de rede local em Python com modo pentest integrado. Descobre hosts ativos, faz port scanning TCP, classifica riscos por porta, sugere técnicas de exploração com ferramentas específicas e consulta CVEs automaticamente.

Desenvolvido como projeto prático durante os estudos em segurança ofensiva.

> **Aviso legal**: use exclusivamente em ambientes autorizados (lab próprio, CTF, pentest com permissão). O uso não autorizado contra sistemas de terceiros é crime (Lei 12.737/2012).

## Funcionalidades

- Ping sweep para descoberta de hosts ativos na rede
- Port scanning TCP com classificação de risco por porta
- Banner grabbing para identificação de serviços
- Detecção de versão de serviço via `nmap -sV` (modo pentest)
- Detecção de sistema operacional via `nmap -O` (modo pentest)
- Tabela de técnicas de exploração por porta (SQLi, RCE, Brute Force, etc.)
- Comandos prontos para execução por porta aberta
- Consulta automática de CVEs na NVD (modo pentest + cve)
- Detecção de anomalias (múltiplos DBs expostos, SSH+Telnet simultâneo, etc.)

## Requisitos

```bash
pip install rich python-nmap requests scapy
sudo apt install nmap nikto gobuster hydra enum4linux crackmapexec
```

## Modos de uso

### Modo Discovery (padrão)

Scan básico da rede local com classificação de risco:

```bash
python net_detective.py
```

### Especificar rede ou IP alvo

```bash
python net_detective.py --target 192.168.1.0/24
python net_detective.py --target 192.168.1.1
```

### Especificar portas manualmente

```bash
python net_detective.py --target 192.168.1.1 --ports 22,80,443,8080
```

### Modo Pentest

Ativa detecção de versão/OS via nmap, exibe tabela de técnicas de exploração (SQLi, RCE, Brute Force, etc.) e comandos prontos para cada porta aberta:

```bash
python net_detective.py --target 192.168.1.1 --pentest
```

### Modo Pentest + CVE

Além do pentest, consulta automaticamente a base NVD e exibe CVEs encontrados para cada serviço/versão detectado:

```bash
python net_detective.py --target 192.168.1.1 --pentest --cve
```

### Combinação completa

```bash
python net_detective.py --target 192.168.1.0/24 --ports 22,80,443,445,3306,3389 --pentest --cve
```

## Técnicas de exploração mapeadas

No modo `--pentest`, para cada porta aberta é exibida uma tabela com:

| Técnica | Ferramenta | Descrição |
|---|---|---|
| SQL Injection | `sqlmap` | Extração de dados via parâmetros vulneráveis |
| XSS | `XSStrike / Dalfox` | Injeção de scripts em campos de entrada |
| Brute Force | `Hydra / Medusa` | Ataque de dicionário em credenciais |
| EternalBlue (RCE) | `Metasploit` | Exploração do MS17-010 via SMB |
| Pass-the-Hash | `crackmapexec` | Autenticação com hash NTLM capturado |
| Anonymous Access | `redis-cli / mongo` | Acesso sem senha em serviços mal configurados |
| CVE Exploitation | `Metasploit / searchsploit` | Exploração de vulnerabilidades conhecidas |

## Níveis de risco

| Nível | Significado |
|---|---|
| OK | Serviço seguro |
| AVISO | Merece atenção |
| SUSPEITO | Fora do padrão esperado |
| CRITICO | Risco real de exploração |

## Tecnologias

- Python 3.x
- [Rich](https://github.com/Textualize/rich) para formatação de output no terminal
- [python-nmap](https://pypi.org/project/python-nmap/) para detecção de versão e OS
- [Requests](https://pypi.org/project/requests/) para consulta à API NVD
- Scapy para suporte a scanning de rede

## Autor

Gustavo Lemos Souto
[linkedin.com/in/gustavolemossouto](https://linkedin.com/in/gustavolemossouto)
