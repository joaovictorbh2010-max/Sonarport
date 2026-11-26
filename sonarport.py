#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sonarport - scanner de portas TCP simples, rápido e ético.

Uso ético: escaneie APENAS a sua própria máquina ou redes/hosts que você
tem permissão explícita para testar. Por padrão o alvo é o localhost, e
qualquer outro alvo exige confirmação.

Modos de uso:
    python sonarport.py                          -> abre o menu interativo
    python sonarport.py --comuns                 -> portas comuns no localhost
    python sonarport.py --alvo 192.168.0.1 --comuns
    python sonarport.py --alvo exemplo.com --portas 20-25,80,443 --salvar ambos
"""

import argparse
import csv
import errno
import ipaddress
import os
import queue
import socket
import ssl
import sys
import threading
import time
from datetime import datetime
from urllib.parse import urlsplit

__version__ = "1.0.0"

# Garante que acentos e caracteres da barra de progresso não quebrem o
# programa em terminais com codificação limitada (troca por "?" se preciso).
for _fluxo in (sys.stdout, sys.stderr):
    if hasattr(_fluxo, "reconfigure"):
        try:
            _fluxo.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass


# =============================================================================
# CORES NO TERMINAL
# =============================================================================
# Usamos códigos ANSI. Se o "colorama" estiver instalado, ele garante que as
# cores funcionem em qualquer terminal do Windows. Sem ele, ativamos o modo
# ANSI nativo do Windows 10+ (que funciona no Windows Terminal e no PowerShell).
try:
    import colorama

    if hasattr(colorama, "just_fix_windows_console"):
        colorama.just_fix_windows_console()
    else:
        colorama.init()
except ImportError:
    if os.name == "nt":
        os.system("")  # truque simples que liga as sequências ANSI no Windows


class Cor:
    """Códigos de cor usados na saída. Ficam vazios se as cores forem desligadas."""

    VERDE = "\033[92m"
    VERMELHO = "\033[91m"
    AMARELO = "\033[93m"
    CIANO = "\033[96m"
    AZUL = "\033[94m"
    CINZA = "\033[90m"
    NEGRITO = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def desativar(cls):
        for nome in ("VERDE", "VERMELHO", "AMARELO", "CIANO", "AZUL",
                     "CINZA", "NEGRITO", "RESET"):
            setattr(cls, nome, "")


# Sem cor quando a saída não é um terminal (ex.: redirecionada para arquivo)
# ou quando o usuário define a variável de ambiente NO_COLOR.
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    Cor.desativar()


def ok(msg):
    print(f"{Cor.VERDE}[+]{Cor.RESET} {msg}")


def info(msg):
    print(f"{Cor.CIANO}[*]{Cor.RESET} {msg}")


def aviso(msg):
    print(f"{Cor.AMARELO}[!]{Cor.RESET} {msg}")


def erro(msg):
    print(f"{Cor.VERMELHO}[x]{Cor.RESET} {msg}")


# =============================================================================
# LISTA DE PORTAS COMUNS E SEUS SERVIÇOS
# =============================================================================
# Portas TCP mais usadas e o serviço que normalmente roda em cada uma.
# Serve tanto para o "escaneamento rápido" quanto para dar nome às portas
# encontradas no escaneamento completo.
PORTAS_COMUNS = {
    20: "FTP (dados)", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCbind",
    135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 179: "BGP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 515: "LPD (impressora)",
    548: "AFP", 554: "RTSP", 587: "SMTP (envio)", 631: "IPP (impressora)",
    636: "LDAPS", 873: "rsync", 902: "VMware", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MS SQL Server",
    1521: "Oracle DB", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel (SSL)", 2181: "ZooKeeper",
    2375: "Docker API", 2376: "Docker API (TLS)", 3000: "Web dev (Node/Grafana)",
    3306: "MySQL", 3389: "RDP (Área de Trabalho Remota)", 3690: "SVN",
    4369: "Erlang EPMD", 5000: "Web dev (Flask)/UPnP", 5037: "ADB (Android)",
    5060: "SIP", 5357: "WSDAPI", 5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC", 5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)", 6379: "Redis",
    6443: "Kubernetes API", 6667: "IRC", 7070: "RealServer/AnyDesk",
    8000: "HTTP alternativo", 8008: "HTTP alternativo", 8080: "HTTP proxy/alternativo",
    8081: "HTTP alternativo", 8443: "HTTPS alternativo", 8888: "HTTP alt./Jupyter",
    9000: "SonarQube/PHP-FPM", 9090: "Prometheus", 9092: "Kafka",
    9100: "Impressora (JetDirect)", 9200: "Elasticsearch", 9418: "Git",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB",
}

# Outras portas conhecidas: não entram no escaneamento rápido, mas ganham
# nome quando aparecem no escaneamento completo.
PORTAS_CONHECIDAS = {
    5040: "Windows CDP", 6463: "Discord RPC", 7680: "Windows Delivery Optimization",
    11434: "Ollama (IA local)", 27036: "Steam", 1900: "SSDP/UPnP",
    5353: "mDNS", 8009: "AJP/Chromecast", 9229: "Node.js debug",
    **{p: "MS-RPC (porta dinâmica)" for p in range(49664, 49680)},
}

# Portas onde enviamos uma requisição HTTP para "provocar" o banner.
PORTAS_HTTP = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200}
# Portas HTTPS: abrimos uma conexão TLS antes de pedir o cabeçalho.
PORTAS_HTTPS = {443, 8443, 6443}

# Códigos de erro que indicam "não há rota até o alvo" (sem conexão/rede).
ERROS_SEM_ROTA = {
    getattr(errno, "ENETUNREACH", -1), getattr(errno, "EHOSTUNREACH", -1),
    10051, 10065,  # equivalentes no Windows (WSAENETUNREACH / WSAEHOSTUNREACH)
}


def nome_servico(porta):
    """Retorna o nome do serviço típico da porta (ou 'desconhecido')."""
    if porta in PORTAS_COMUNS:
        return PORTAS_COMUNS[porta]
    if porta in PORTAS_CONHECIDAS:
        return PORTAS_CONHECIDAS[porta]
    try:
        return socket.getservbyport(porta, "tcp").upper()
    except OSError:
        return "desconhecido"


# =============================================================================
# ALVO: VALIDAÇÃO, RESOLUÇÃO DE NOMES E CONFIRMAÇÃO ÉTICA
# =============================================================================
class ErroAlvo(Exception):
    """Erro com mensagem amigável sobre o alvo informado."""


def normalizar_alvo(texto):
    """Aceita 'exemplo.com', 'https://exemplo.com/pagina' ou '10.0.0.1' e
    devolve só o nome/IP, sem protocolo, caminho ou porta."""
    texto = (texto or "").strip()
    if not texto:
        return ""
    if "://" not in texto:
        texto = "//" + texto  # permite usar urlsplit mesmo sem "http://"
    try:
        return (urlsplit(texto).hostname or "").strip()
    except ValueError:
        return ""


def resolver_alvo(texto):
    """Transforma o nome digitado em IP (resolução DNS automática).
    Retorna (nome_limpo, ip, familia_do_socket)."""
    nome = normalizar_alvo(texto)
    if not nome:
        raise ErroAlvo(f"'{texto}' não parece um IP ou endereço de site válido.")
    try:
        infos = socket.getaddrinfo(nome, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ErroAlvo(
            f"Não consegui encontrar '{nome}'. Confira se o nome está certo "
            "e se você está conectado à internet."
        ) from None
    except (UnicodeError, ValueError):
        raise ErroAlvo(f"'{nome}' contém caracteres inválidos.") from None
    if not infos:
        raise ErroAlvo(f"Nenhum endereço encontrado para '{nome}'.")
    # Prefere IPv4, que é o mais comum e compatível.
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    familia, _, _, _, endereco = infos[0]
    return nome, endereco[0], familia


def ips_desta_maquina():
    """Lista os IPs da própria máquina (para não pedir confirmação neles)."""
    ips = set()
    try:
        for info_ in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info_[4][0])
    except OSError:
        pass
    return ips


def eh_proprio_computador(ip):
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return True
    except ValueError:
        return False
    return ip in ips_desta_maquina()


def confirmar_permissao(nome, ip, ja_confirmado=False):
    """Trava ética: alvos que não são o próprio computador exigem confirmação.
    Retorna True se pode escanear."""
    if eh_proprio_computador(ip):
        return True

    publico = not ipaddress.ip_address(ip).is_private
    tipo = (f"{Cor.VERMELHO}endereço PÚBLICO na internet{Cor.RESET}" if publico
            else "dispositivo da rede local/privada")
    print()
    aviso(f"{Cor.NEGRITO}O alvo {nome} ({ip}) NÃO é o seu computador.{Cor.RESET}")
    aviso(f"Tipo: {tipo}.")
    aviso("Escanear sistemas sem autorização pode ser ilegal e violar termos de uso.")
    if ja_confirmado:
        info("Permissão confirmada pela opção --sim-tenho-permissao.")
        return True
    if not sys.stdin.isatty():
        erro("Sem terminal para confirmar. Use --sim-tenho-permissao se você "
             "tiver autorização para escanear este alvo.")
        return False
    resposta = input(f"    Você é o dono ou tem PERMISSÃO para escanear este alvo? "
                     f"Digite {Cor.NEGRITO}sim{Cor.RESET} para continuar: ")
    if resposta.strip().lower() in ("sim", "s"):
        return True
    info("Escaneamento cancelado. Nenhum pacote foi enviado ao alvo.")
    return False


def interpretar_portas(texto):
    """Converte '20-25,80,443' em uma lista ordenada de portas válidas."""
    portas = set()
    for parte in texto.replace(" ", "").split(","):
        if not parte:
            continue
        try:
            if "-" in parte:
                ini, fim = (int(x) for x in parte.split("-", 1))
            else:
                ini = fim = int(parte)
        except ValueError:
            raise ErroAlvo(f"Intervalo de portas inválido: '{parte}'.") from None
        if not (1 <= ini <= fim <= 65535):
            raise ErroAlvo(f"Portas devem estar entre 1 e 65535 (recebido '{parte}').")
        portas.update(range(ini, fim + 1))
    if not portas:
        raise ErroAlvo("Nenhuma porta informada.")
    return sorted(portas)


# =============================================================================
# LEITURA DE BANNER (identificação do serviço)
# =============================================================================
def limpar_banner(dados):
    """Deixa o banner em uma linha curta e legível."""
    texto = dados.decode("utf-8", errors="replace")
    linhas = [l.strip() for l in texto.splitlines() if l.strip()]
    if not linhas:
        return ""
    if linhas[0].upper().startswith("HTTP/"):
        # Em respostas HTTP, o cabeçalho "Server:" é o que mais interessa.
        servidor = next((l for l in linhas if l.lower().startswith("server:")), "")
        resumo = linhas[0] + (f" | {servidor}" if servidor else "")
    else:
        resumo = linhas[0]
    resumo = "".join(c for c in resumo if c.isprintable())
    return resumo[:70] + ("..." if len(resumo) > 70 else "")


def ler_banner(ip, familia, porta, host, timeout=2.0):
    """Conecta na porta aberta e tenta ler a mensagem de apresentação do serviço.
    Alguns serviços (SSH, FTP, SMTP) falam primeiro; para HTTP/HTTPS enviamos
    um pedido simples 'HEAD /' para obter a resposta do servidor."""
    pedido_http = (f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                   "User-Agent: sonarport\r\n\r\n").encode()
    try:
        with socket.create_connection((ip, porta), timeout=timeout) as s:
            if porta in PORTAS_HTTPS:
                contexto = ssl.create_default_context()
                contexto.check_hostname = False
                contexto.verify_mode = ssl.CERT_NONE  # só queremos ler o banner
                with contexto.wrap_socket(s, server_hostname=host) as tls:
                    tls.sendall(pedido_http)
                    return limpar_banner(tls.recv(1024))
            if porta in PORTAS_HTTP:
                s.sendall(pedido_http)
                return limpar_banner(s.recv(1024))
            try:
                dados = s.recv(1024)  # espera o serviço "se apresentar"
            except socket.timeout:
                # Serviço silencioso: tentamos uma requisição HTTP genérica.
                s.sendall(pedido_http)
                dados = s.recv(1024)
            return limpar_banner(dados)
    except (OSError, ssl.SSLError, ValueError):
        return ""


# =============================================================================
# O SCANNER (multithread)
# =============================================================================
class Scanner:
    """Escaneia uma lista de portas usando vários 'trabalhadores' (threads)
    ao mesmo tempo. Cada trabalhador pega uma porta da fila, tenta conectar e
    anota se ela estava aberta."""

    def __init__(self, ip, familia, portas, threads=400, timeout=0.5):
        self.ip = ip
        self.familia = familia
        self.portas = portas
        self.timeout = timeout
        self.qtd_threads = max(1, min(threads, len(portas)))
        self.fila = queue.Queue()
        self.trava = threading.Lock()   # evita que duas threads escrevam junto
        self.parar = threading.Event()  # sinal para interromper (Ctrl+C)
        self.abertas = []
        self.verificadas = 0
        self.sem_rota = 0

    def _testar_porta(self, porta):
        """Tentativa de conexão TCP completa (connect). 0 = porta aberta."""
        try:
            with socket.socket(self.familia, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                codigo = s.connect_ex((self.ip, porta))
        except OSError as e:
            codigo = e.errno or -1
        if codigo in ERROS_SEM_ROTA:
            with self.trava:
                self.sem_rota += 1
        return codigo == 0

    def _trabalhador(self):
        """Loop de cada thread: pega portas da fila até ela acabar."""
        while not self.parar.is_set():
            try:
                porta = self.fila.get_nowait()
            except queue.Empty:
                return
            aberta = self._testar_porta(porta)
            with self.trava:
                self.verificadas += 1
                if aberta:
                    self.abertas.append(porta)

    def _desenhar_barra(self):
        total = len(self.portas)
        feitas = self.verificadas
        fracao = feitas / total if total else 1
        largura = 30
        cheio = int(largura * fracao)
        barra = "█" * cheio + "░" * (largura - cheio)
        sys.stdout.write(
            f"\r  {Cor.CIANO}[{barra}]{Cor.RESET} {fracao * 100:5.1f}%  "
            f"{feitas}/{total} portas | abertas: {Cor.VERDE}{len(self.abertas)}{Cor.RESET}  "
        )
        sys.stdout.flush()

    def executar(self):
        """Inicia as threads, mostra o progresso e devolve (abertas, interrompido)."""
        for p in self.portas:
            self.fila.put(p)

        threads = [threading.Thread(target=self._trabalhador, daemon=True)
                   for _ in range(self.qtd_threads)]
        for t in threads:
            t.start()

        interrompido = False
        animado = sys.stdout.isatty()
        try:
            # A thread principal só acompanha o progresso enquanto os
            # trabalhadores fazem o serviço pesado.
            while any(t.is_alive() for t in threads):
                if animado:
                    self._desenhar_barra()
                time.sleep(0.1)
        except KeyboardInterrupt:
            interrompido = True
            self.parar.set()
            for t in threads:
                t.join(timeout=self.timeout + 1)
        self._desenhar_barra()
        print()
        return sorted(self.abertas), interrompido


def ler_banners(ip, familia, portas, host):
    """Lê os banners das portas abertas em paralelo (são poucas portas)."""
    banners = {}
    trava = threading.Lock()

    def tarefa(porta):
        b = ler_banner(ip, familia, porta, host)
        with trava:
            banners[porta] = b

    threads = [threading.Thread(target=tarefa, args=(p,), daemon=True) for p in portas]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return banners


def escanear(texto_alvo, portas, modo, threads=400, timeout=0.5,
             com_banner=True, ja_confirmado=False):
    """Fluxo completo: resolve o alvo, confirma permissão, escaneia, lê banners
    e devolve um dicionário com o resultado (ou None se não escaneou)."""
    try:
        nome, ip, familia = resolver_alvo(texto_alvo)
    except ErroAlvo as e:
        erro(str(e))
        return None

    if not confirmar_permissao(nome, ip, ja_confirmado):
        return None

    exibicao = nome if nome == ip else f"{nome} ({ip})"
    print()
    info(f"Alvo: {Cor.NEGRITO}{exibicao}{Cor.RESET}")
    info(f"Modo: {modo} | {len(portas)} porta(s) | {threads} threads | timeout {timeout}s")

    inicio = datetime.now()
    t0 = time.perf_counter()
    scanner = Scanner(ip, familia, portas, threads, timeout)
    abertas, interrompido = scanner.executar()

    if interrompido:
        aviso("Escaneamento interrompido pelo usuário. Mostrando resultados parciais.")

    if not abertas and scanner.sem_rota >= scanner.verificadas > 0:
        erro("Não há rota até o alvo. Verifique sua conexão de rede/internet "
             "ou se o endereço está correto.")

    banners = {}
    if com_banner and abertas and not interrompido:
        info(f"Lendo banners de {len(abertas)} porta(s) aberta(s)...")
        banners = ler_banners(ip, familia, abertas, nome)

    resultado = {
        "alvo": nome,
        "ip": ip,
        "modo": modo,
        "inicio": inicio,
        "duracao": time.perf_counter() - t0,
        "total": scanner.verificadas,
        "interrompido": interrompido,
        "portas": [
            {"porta": p, "estado": "ABERTA", "servico": nome_servico(p),
             "banner": banners.get(p, "")}
            for p in abertas
        ],
    }
    mostrar_resultado(resultado)
    return resultado


# =============================================================================
# SAÍDA: TABELA COLORIDA E RELATÓRIOS
# =============================================================================
def montar_tabela(linhas, colorir=True):
    """Monta uma tabela com bordas. 'linhas' é uma lista de dicts de portas."""
    cabecalho = ["PORTA", "ESTADO", "SERVIÇO", "BANNER"]
    dados = [[f"{l['porta']}/tcp", l["estado"], l["servico"], l["banner"] or "-"]
             for l in linhas]
    larguras = [max(len(cabecalho[i]), *(len(d[i]) for d in dados)) for i in range(4)]

    def cor(texto, codigo):
        return f"{codigo}{texto}{Cor.RESET}" if colorir and codigo else texto

    def linha_borda(esq, meio, dir_):
        return esq + meio.join("─" * (w + 2) for w in larguras) + dir_

    def linha_dados(celulas, cores):
        partes = [f" {cor(c.ljust(w), k)} " for c, w, k in zip(celulas, larguras, cores)]
        return "│" + "│".join(partes) + "│"

    saida = [linha_borda("┌", "┬", "┐"),
             linha_dados(cabecalho, [Cor.NEGRITO] * 4),
             linha_borda("├", "┼", "┤")]
    for d in dados:
        saida.append(linha_dados(d, [Cor.AZUL, Cor.VERDE, Cor.AMARELO, Cor.CINZA]))
    saida.append(linha_borda("└", "┴", "┘"))
    return "\n".join(saida)


def resumo_texto(r):
    exibicao = r["alvo"] if r["alvo"] == r["ip"] else f"{r['alvo']} ({r['ip']})"
    return (f"{len(r['portas'])} porta(s) aberta(s) de {r['total']} verificada(s) "
            f"em {exibicao} - {r['duracao']:.1f}s")


def mostrar_resultado(r):
    print()
    if r["portas"]:
        print(montar_tabela(r["portas"]))
    else:
        info("Nenhuma porta aberta encontrada (todas fechadas ou filtradas por firewall).")
    print()
    ok(resumo_texto(r))


def salvar_relatorio(r, formato="ambos", pasta="relatorios"):
    """Salva o resultado em .txt e/ou .csv. Retorna a lista de arquivos criados."""
    os.makedirs(pasta, exist_ok=True)
    seguro = "".join(c if c.isalnum() or c in "-." else "_" for c in r["alvo"])
    base = os.path.join(pasta, f"sonarport_{seguro}_{r['inicio']:%Y%m%d_%H%M%S}")
    criados = []

    if formato in ("txt", "ambos"):
        caminho = base + ".txt"
        with open(caminho, "w", encoding="utf-8") as f:
            f.write(f"Relatório sonarport v{__version__}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Alvo     : {r['alvo']}\n")
            f.write(f"IP       : {r['ip']}\n")
            f.write(f"Modo     : {r['modo']}\n")
            f.write(f"Data     : {r['inicio']:%d/%m/%Y %H:%M:%S}\n")
            f.write(f"Duração  : {r['duracao']:.1f}s\n")
            f.write(f"Testadas : {r['total']} porta(s)\n")
            if r["interrompido"]:
                f.write("Situação : INTERROMPIDO (resultado parcial)\n")
            f.write("\n")
            if r["portas"]:
                f.write(montar_tabela(r["portas"], colorir=False) + "\n")
            else:
                f.write("Nenhuma porta aberta encontrada.\n")
            f.write("\n" + resumo_texto(r) + "\n")
        criados.append(caminho)

    if formato in ("csv", "ambos"):
        caminho = base + ".csv"
        # utf-8-sig faz o Excel abrir os acentos corretamente.
        with open(caminho, "w", encoding="utf-8-sig", newline="") as f:
            escritor = csv.writer(f)
            escritor.writerow(["alvo", "ip", "porta", "protocolo", "estado",
                               "servico", "banner", "data"])
            for p in r["portas"]:
                escritor.writerow([r["alvo"], r["ip"], p["porta"], "tcp", p["estado"],
                                   p["servico"], p["banner"],
                                   f"{r['inicio']:%Y-%m-%d %H:%M:%S}"])
        criados.append(caminho)

    return criados


# =============================================================================
# MENU INTERATIVO
# =============================================================================
LOGO = r"""
                                               _
   ___  ___  _ __   __ _ _ __ _ __   ___  _ __| |_
  / __|/ _ \| '_ \ / _` | '__| '_ \ / _ \| '__| __|
  \__ \ (_) | | | | (_| | |  | |_) | (_) | |  | |_
  |___/\___/|_| |_|\__,_|_|  | .__/ \___/|_|   \__|
                             |_|
"""

PORTAS_TODAS = list(range(1, 65536))


def pedir(texto):
    """input() que trata Ctrl+C / fim de entrada com elegância."""
    try:
        # Remove o BOM (﻿) que alguns terminais colocam no início da entrada.
        return input(texto).replace("﻿", "")
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)


def pedir_alvo():
    alvo = pedir(f"  Digite o IP ou site (Enter = localhost): ").strip()
    return alvo or "localhost"


def pedir_modo():
    """Pergunta se o escaneamento será rápido (comuns) ou completo."""
    print("  Tipo de escaneamento:")
    print("    [Enter] Portas mais comuns (rápido)")
    print("    c       Completo (1-65535, demora mais)")
    escolha = pedir("  > ").strip().lower()
    if escolha == "c":
        return "completo (1-65535)", PORTAS_TODAS
    return "portas comuns", sorted(PORTAS_COMUNS)


def menu():
    print(f"{Cor.CIANO}{LOGO}{Cor.RESET}")
    print(f"  {Cor.NEGRITO}sonarport v{__version__}{Cor.RESET} - scanner de portas ético")
    print(f"  {Cor.AMARELO}Use apenas em sistemas seus ou com autorização.{Cor.RESET}")

    ultimo = None
    while True:
        print(f"\n{Cor.NEGRITO}  ===== MENU ====={Cor.RESET}")
        print("  1) Escanear meu próprio computador (localhost)")
        print("  2) Escanear um IP ou site que eu informar")
        print("  3) Escanear as portas mais comuns (rápido)")
        print("  4) Escaneamento completo (todas as portas 1-65535)")
        print("  5) Salvar relatório do último escaneamento")
        print("  0) Sair")
        opcao = pedir("\n  Escolha uma opção: ").strip()

        resultado = None
        if opcao == "1":
            modo, portas = pedir_modo()
            resultado = escanear("localhost", portas, modo)
        elif opcao == "2":
            alvo = pedir(f"  Digite o IP ou site (ex.: 192.168.0.1 ou exemplo.com): ").strip()
            if not alvo:
                aviso("Nenhum alvo digitado.")
                continue
            modo, portas = pedir_modo()
            resultado = escanear(alvo, portas, modo)
        elif opcao == "3":
            resultado = escanear(pedir_alvo(), sorted(PORTAS_COMUNS), "portas comuns")
        elif opcao == "4":
            resultado = escanear(pedir_alvo(), PORTAS_TODAS, "completo (1-65535)")
        elif opcao == "5":
            if not ultimo:
                aviso("Nenhum escaneamento feito ainda. Escaneie algo primeiro.")
                continue
            print("  Formato: 1) .txt   2) .csv   [Enter] ambos")
            f = pedir("  > ").strip()
            formato = {"1": "txt", "2": "csv"}.get(f, "ambos")
            try:
                for caminho in salvar_relatorio(ultimo, formato):
                    ok(f"Relatório salvo em: {os.path.abspath(caminho)}")
            except OSError as e:
                erro(f"Não foi possível salvar o relatório: {e}")
        elif opcao == "0":
            info("Até mais!")
            return
        else:
            aviso("Opção inválida. Digite um número de 0 a 5.")
            continue

        if resultado:
            ultimo = resultado
            info("Dica: use a opção 5 para salvar este relatório.")


# =============================================================================
# LINHA DE COMANDO
# =============================================================================
def criar_parser():
    p = argparse.ArgumentParser(
        prog="sonarport",
        description="sonarport - scanner de portas TCP simples, rápido e ético. "
                    "Sem argumentos, abre o menu interativo.",
        epilog="Exemplos:\n"
               "  python sonarport.py --comuns\n"
               "  python sonarport.py --alvo 192.168.0.1 --comuns\n"
               "  python sonarport.py --alvo exemplo.com --portas 20-25,80,443\n"
               "  python sonarport.py --completo --salvar ambos\n\n"
               "Use apenas em sistemas próprios ou com autorização.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-a", "--alvo", default="localhost",
                   help="IP ou site a escanear (padrão: localhost)")
    modo = p.add_mutually_exclusive_group()
    modo.add_argument("-c", "--comuns", action="store_true",
                      help="escaneia as portas mais comuns (padrão)")
    modo.add_argument("-C", "--completo", action="store_true",
                      help="escaneia todas as portas 1-65535")
    modo.add_argument("-p", "--portas", metavar="LISTA",
                      help="portas específicas, ex.: 22,80,443 ou 1-1024")
    p.add_argument("-t", "--threads", type=int, default=400,
                   help="quantidade de threads simultâneas (padrão: 400)")
    p.add_argument("--timeout", type=float, default=0.5,
                   help="tempo máximo por porta em segundos (padrão: 0.5)")
    p.add_argument("--sem-banner", action="store_true",
                   help="não tenta ler o banner dos serviços")
    p.add_argument("-s", "--salvar", choices=["txt", "csv", "ambos"],
                   help="salva o relatório no formato escolhido")
    p.add_argument("--pasta", default="relatorios",
                   help="pasta dos relatórios (padrão: relatorios)")
    p.add_argument("--sim-tenho-permissao", action="store_true",
                   help="confirma que você tem autorização para escanear o alvo "
                        "(pula a pergunta; use com responsabilidade)")
    p.add_argument("--sem-cor", action="store_true", help="desativa as cores")
    p.add_argument("-v", "--versao", action="version",
                   version=f"sonarport {__version__}")
    return p


def linha_de_comando(argv):
    args = criar_parser().parse_args(argv)
    if args.sem_cor:
        Cor.desativar()
    if not 1 <= args.threads <= 2000:
        erro("Use entre 1 e 2000 threads.")
        return 1
    if not 0.05 <= args.timeout <= 30:
        erro("O timeout deve ficar entre 0.05 e 30 segundos.")
        return 1

    if args.completo:
        modo, portas = "completo (1-65535)", PORTAS_TODAS
    elif args.portas:
        try:
            portas = interpretar_portas(args.portas)
        except ErroAlvo as e:
            erro(str(e))
            return 1
        modo = f"portas personalizadas ({args.portas})"
    else:
        modo, portas = "portas comuns", sorted(PORTAS_COMUNS)

    resultado = escanear(args.alvo, portas, modo, args.threads, args.timeout,
                         not args.sem_banner, args.sim_tenho_permissao)
    if resultado is None:
        return 2
    if args.salvar:
        try:
            for caminho in salvar_relatorio(resultado, args.salvar, args.pasta):
                ok(f"Relatório salvo em: {os.path.abspath(caminho)}")
        except OSError as e:
            erro(f"Não foi possível salvar o relatório: {e}")
            return 1
    return 130 if resultado["interrompido"] else 0


def main():
    try:
        if len(sys.argv) == 1:
            menu()
            return 0
        return linha_de_comando(sys.argv[1:])
    except KeyboardInterrupt:
        print()
        aviso("Interrompido pelo usuário.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
