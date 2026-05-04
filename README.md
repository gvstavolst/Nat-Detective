# Net Detective

Scanner de rede local em Python para enumeração de hosts ativos e análise de portas abertas. Desenvolvido como projeto prático de segurança ofensiva.

## Como funciona

O script utiliza ARP via Scapy para descobrir dispositivos ativos na rede local. Para cada host encontrado, realiza port scanning TCP e classifica as portas abertas por nível de risco:

- **Limpo** — nenhuma porta sensível exposta
- **Aviso** — portas abertas que merecem atenção
- **Suspeito** — serviços fora do padrão esperado
- **Critico** — portas que representam risco real de exposição

Ao final da execução, o script gera um relatório consolidado com todos os hosts e suas classificações.

## Requisitos

- Python 3.x
- Scapy
- Rich

```bash
pip install rich scapy
```

## Uso

```bash
# Escanear a rede local automaticamente
python net_detective.py

# Especificar um range de rede
python net_detective.py --target 192.168.1.0/24

# Escanear host especifico com portas definidas
python net_detective.py --target 192.168.1.1 --ports 22,80,443
```

## Tecnologias

- Python
- Scapy (ARP discovery, TCP scanning)
- Rich (formatacao de output no terminal)

## Autor

Gustavo Lemos Souto
[linkedin.com/in/gustavolemossouto](https://linkedin.com/in/gustavolemossouto)
