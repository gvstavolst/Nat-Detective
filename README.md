# Net Detective


## 🔍 O que é esse projeto?
O **Net Detective** é um script em Python que funciona como um investigador particular para a sua rede local. 

Em vez de ser um programa sem graça, ele veste um sobretudo e analisa os aparelhos conectados à sua rede. Ele vai de "porta em porta" verificando o que está aberto e o que está fechado, e te entrega um dossiê completo avisando se tem alguma janela destrancada que não deveria estar, tudo isso narrado como um filme clássico de detetive.

## 🛠️ O que você precisa para rodar (Dependências)
Antes de chamar o detetive, você precisa ter o Python instalado e instalar as ferramentas que ele usa para trabalhar:

pip install rich scapy

## 🚀 Como usar
Abra o seu terminal e execute um dos comandos abaixo:

**Para investigar toda a sua rede local automaticamente:**
python net_detective.py

**Para apontar a lupa para uma rede específica:**
python net_detective.py --target 192.168.1.0/24

**Para investigar um único aparelho e olhar portas específicas:**
python net_detective.py --target 192.168.1.1 --ports 22,80,443

## 📁 O Dossiê Final
No final da execução, o detetive te entrega um resumo (O Veredicto) classificando o que ele encontrou em níveis como:
* ✔️ **Limpo:** Tudo nos conformes.
* ⚠️ **Aviso:** Vale a pena dar uma olhada.
* ⚡ **Suspeito:** Coisas fora do padrão.
* ✖️ **Crítico:** Portas abertas que podem representar um problema real.

---
Criado por **gvstavolst** ☕
