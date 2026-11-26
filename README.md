<h1 align="center"> Sonarport</h1>

<p align="center">
  <b>Scanner de portas TCP simples, rápido e ético, escrito em Python puro.</b><br>
  Descubra quais portas estão abertas no seu computador, ou em hosts que você tem permissão para testar, e quais serviços rodam nelas.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white">
  <img alt="Dependências" src="https://img.shields.io/badge/depend%C3%AAncias-nenhuma%20obrigat%C3%B3ria-brightgreen">
  <img alt="Plataformas" src="https://img.shields.io/badge/plataformas-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey">
  <img alt="Licença" src="https://img.shields.io/badge/licen%C3%A7a-MIT-yellow">
</p>

---

> [!WARNING]
> **Uso ético e legal**
>
> O sonarport é uma ferramenta **educacional e de diagnóstico**. Use-o **somente**:
> - no **seu próprio computador** (`localhost`);
> - em redes e dispositivos que **são seus**;
> - em sistemas para os quais você tem **autorização explícita** do dono (de preferência por escrito).
>
> Escanear sistemas de terceiros sem permissão pode ser **crime** (no Brasil, por exemplo, a Lei 12.737/2012) e viola os termos de uso da maioria dos provedores. O autor não se responsabiliza pelo mau uso.
> Por isso o sonarport **mira o localhost por padrão** e **pede confirmação** antes de escanear qualquer outro alvo.

---

##  Recursos

| Recurso | Descrição |
|---|---|
|  **Menu interativo** | Escolha tudo digitando um número, sem decorar comandos |
|  **Linha de comando** | Argumentos para automação e scripts (`--alvo`, `--comuns`, `--completo`...) |
|  **Multithread** | Centenas de "trabalhadores" em paralelo, com barra de progresso |
|  **Identificação de serviços** | Mostra o serviço típico de cada porta (22 = SSH, 80 = HTTP, 443 = HTTPS...) |
|  **Leitura de banner** | Tenta ler a "apresentação" do serviço (ex.: versão do SSH, cabeçalho `Server` do HTTP/HTTPS) |
|  **Resolução de DNS** | Digite `exemplo.com` e ele descobre o IP sozinho |
|  **Tabela colorida** | Resultado organizado em porta / estado / serviço / banner |
|  **Relatórios** | Salva em `.txt` (legível) e `.csv` (abre no Excel / Planilhas) |
|  **Trava ética** | Localhost por padrão e confirmação obrigatória para outros alvos |
|  **Zero dependências** | Só a biblioteca padrão (`socket`, `threading`, `queue`...). `colorama` é opcional |

## 📦 Instalação

**Pré-requisito:** [Python 3.8 ou superior](https://www.python.org/downloads/).

```bash
# 1. Baixe o projeto
git clone https://github.com/joaovictorbh2010-max/sonarport.git
cd sonarport

# 2. (Opcional) Instale o colorama para cores em qualquer terminal do Windows
pip install -r requirements.txt
```

Pronto, não precisa de mais nada. Sem o `colorama` as cores continuam funcionando no Windows Terminal, no PowerShell moderno, no Linux e no macOS.

##  Como usar

### Modo 1: menu interativo (mais fácil)

```bash
python sonarport.py
```

```
  sonarport v1.0.0 - scanner de portas ético
  Use apenas em sistemas seus ou com autorização.

  ===== MENU =====
  1) Escanear meu próprio computador (localhost)
  2) Escanear um IP ou site que eu informar
  3) Escanear as portas mais comuns (rápido)
  4) Escaneamento completo (todas as portas 1-65535)
  5) Salvar relatório do último escaneamento
  0) Sair

  Escolha uma opção:
```

| Opção | O que faz |
|---|---|
| **1** | Escaneia o seu próprio PC. Pergunta se é rápido (Enter) ou completo (`c`) |
| **2** | Pede um IP ou site, **confirma a permissão** e pergunta o tipo de escaneamento |
| **3** | Escaneia as ~75 portas mais comuns (Enter = localhost) |
| **4** | Escaneia todas as 65.535 portas (Enter = localhost) |
| **5** | Salva o último resultado em `.txt`, `.csv` ou ambos, na pasta `relatorios/` |
| **0** | Sai do programa |

### Modo 2: linha de comando

```bash
# Portas comuns no seu computador (o alvo padrão é o localhost)
python sonarport.py --comuns

# Portas comuns em um dispositivo da sua rede
python sonarport.py --alvo 192.168.0.1 --comuns

# Todas as portas, salvando o relatório em .txt e .csv
python sonarport.py --completo --salvar ambos

# Portas específicas ou intervalos em um site (o DNS é resolvido sozinho)
python sonarport.py --alvo exemplo.com --portas 20-25,80,443

# Mais velocidade: mais threads e timeout menor
python sonarport.py --completo --threads 1000 --timeout 0.3

# Ajuda completa
python sonarport.py --help
```

| Argumento | Atalho | Descrição | Padrão |
|---|---|---|---|
| `--alvo` | `-a` | IP ou site a escanear | `localhost` |
| `--comuns` | `-c` | Escaneia as portas mais comuns | ✅ |
| `--completo` | `-C` | Escaneia as portas 1-65535 | |
| `--portas` | `-p` | Lista/intervalos, ex.: `22,80,443` ou `1-1024` | |
| `--threads` | `-t` | Quantidade de threads simultâneas (1-2000) | `400` |
| `--timeout` | | Espera máxima por porta, em segundos | `0.5` |
| `--sem-banner` | | Não tenta ler o banner dos serviços | |
| `--salvar` | `-s` | Salva relatório: `txt`, `csv` ou `ambos` | |
| `--pasta` | | Pasta onde os relatórios são salvos | `relatorios` |
| `--sim-tenho-permissao` | | Confirma a autorização sem perguntar (para scripts) | |
| `--sem-cor` | | Desativa as cores | |
| `--versao` | `-v` | Mostra a versão | |

> Ao escanear um alvo que não é o seu computador, o sonarport mostra um aviso, diz se o IP é **público** ou de **rede privada** e pede que você digite `sim`. Em scripts sem terminal, é preciso passar `--sim-tenho-permissao`, de forma consciente.

## 📊 Exemplo de saída

Escaneamento rápido do localhost em um Windows 11:

```
[*] Alvo: localhost (127.0.0.1)
[*] Modo: portas comuns | 74 porta(s) | 400 threads | timeout 0.5s
  [██████████████████████████████] 100.0%  74/74 portas | abertas: 4
[*] Lendo banners de 4 porta(s) aberta(s)...

┌──────────┬────────┬────────────────────────┬──────────────────────────────────────────────────────────────────┐
│ PORTA    │ ESTADO │ SERVIÇO                │ BANNER                                                           │
├──────────┼────────┼────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 135/tcp  │ ABERTA │ MS-RPC                 │ -                                                                │
│ 445/tcp  │ ABERTA │ SMB                    │ -                                                                │
│ 5357/tcp │ ABERTA │ WSDAPI                 │ HTTP/1.1 503 Service Unavailable | Server: Microsoft-HTTPAPI/2.0 │
│ 8080/tcp │ ABERTA │ HTTP proxy/alternativo │ -                                                                │
└──────────┴────────┴────────────────────────┴──────────────────────────────────────────────────────────────────┘

[+] 4 porta(s) aberta(s) de 74 verificada(s) em localhost (127.0.0.1) - 4.6s
```

Relatório `.csv` gerado:

```csv
alvo,ip,porta,protocolo,estado,servico,banner,data
localhost,127.0.0.1,135,tcp,ABERTA,MS-RPC,,2026-11-26 11:10:18
localhost,127.0.0.1,445,tcp,ABERTA,SMB,,2026-11-26 11:10:18
localhost,127.0.0.1,5357,tcp,ABERTA,WSDAPI,HTTP/1.1 503 Service Unavailable | Server: Microsoft-HTTPAPI/2.0,2026-11-26 11:10:18
```

## ⚙️ Como funciona

1. **Resolução do alvo:** `socket.getaddrinfo` converte o nome do site em IP (prefere IPv4). Também aceita URLs como `https://exemplo.com/pagina`.
2. **Trava ética:** se o IP não for do próprio computador, o programa avisa e pede confirmação.
3. **Fila + trabalhadores:** todas as portas vão para uma `queue.Queue`; N threads pegam portas da fila e tentam uma conexão TCP (`connect_ex`). Código `0` = porta **aberta**.
4. **Barra de progresso:** a thread principal só acompanha o contador, protegido por um `threading.Lock`.
5. **Banners:** nas portas abertas, o programa espera o serviço se apresentar (SSH, FTP, SMTP...) ou envia um `HEAD /` (HTTP) ou abre TLS (HTTPS) para ler o cabeçalho `Server`.
6. **Relatórios:** módulos `csv` e escrita de texto em UTF-8.

##  Dúvidas comuns

- **"Nenhuma porta aberta encontrada"**: as portas podem estar fechadas ou **filtradas por um firewall**. Isso é bom sinal de segurança!
- **O escaneamento completo demora**: no Windows, conexões recusadas no localhost são mais lentas que no Linux. Aumente as threads (`--threads 1000`) ou reduza o timeout (`--timeout 0.3`). Em hosts remotos, um timeout muito baixo pode esconder portas abertas.
- **Só TCP?** Sim. O sonarport faz *TCP connect scan*, que não precisa de permissão de administrador. Serviços apenas UDP (DNS sobre UDP, DHCP, SNMP...) não aparecem.
- **Interromper:** aperte `Ctrl+C` a qualquer momento. Os resultados parciais são exibidos.

## 🗂️ Estrutura do projeto

```
sonarport/
├── sonarport.py       # programa principal (tudo em um arquivo)
├── requirements.txt   # dependência opcional (colorama)
├── README.md          # este arquivo
├── LICENSE            # licença MIT
└── .gitignore         # ignora relatórios gerados e cache do Python
```

##  Ideias futuras

- [ ] Escaneamento de faixas de rede (ex.: `192.168.0.0/24`), com confirmação
- [ ] Exportação em JSON e HTML
- [ ] Detecção de versão mais completa por serviço
- [ ] Suporte a UDP

## 📄 Licença

Distribuído sob a licença **MIT**. Veja [LICENSE](LICENSE).

---

<p align="center"><i>Feito para aprender redes e segurança de forma responsável. Escaneie só o que é seu. 🔒</i></p>
