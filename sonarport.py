#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sonarport - a simple, fast and ethical TCP port scanner.

Ethical use: scan ONLY your own machine or networks/hosts you have explicit
permission to test. The default target is localhost, and any other target
requires confirmation.

Usage:
    python sonarport.py                          -> opens the interactive menu
    python sonarport.py --common                 -> common ports on localhost
    python sonarport.py --target 192.168.0.1 --common
    python sonarport.py --target example.com --ports 20-25,80,443 --save both

Commands and flags also accept their Portuguese aliases (--comuns, --alvo,
--completo, --portas, --salvar, --pasta...), so older usage keeps working.
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

# Makes sure accents and the progress-bar characters don't crash the program
# on terminals with a limited encoding (replaces them with "?" if needed).
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass


# =============================================================================
# TERMINAL COLORS
# =============================================================================
# We use ANSI codes. If "colorama" is installed, it makes the colors work on
# any Windows terminal. Without it, we enable the native ANSI mode of
# Windows 10+ (which works on Windows Terminal and PowerShell).
try:
    import colorama

    if hasattr(colorama, "just_fix_windows_console"):
        colorama.just_fix_windows_console()
    else:
        colorama.init()
except ImportError:
    if os.name == "nt":
        os.system("")  # simple trick that turns on ANSI sequences on Windows


class Color:
    """Color codes used in the output. Emptied when colors are turned off."""

    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for name in ("GREEN", "RED", "YELLOW", "CYAN", "BLUE",
                     "GRAY", "BOLD", "RESET"):
            setattr(cls, name, "")


# No color when the output is not a terminal (e.g. redirected to a file)
# or when the user sets the NO_COLOR environment variable.
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    Color.disable()


def ok(msg):
    print(f"{Color.GREEN}[+]{Color.RESET} {msg}")


def info(msg):
    print(f"{Color.CYAN}[*]{Color.RESET} {msg}")


def warn(msg):
    print(f"{Color.YELLOW}[!]{Color.RESET} {msg}")


def error(msg):
    print(f"{Color.RED}[x]{Color.RESET} {msg}")


# =============================================================================
# COMMON PORTS AND THEIR SERVICES
# =============================================================================
# The most used TCP ports and the service that usually runs on each one.
# Used both for the "fast scan" and to name the ports found in a full scan.
COMMON_PORTS = {
    20: "FTP (data)", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPCbind",
    135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 179: "BGP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 515: "LPD (printer)",
    548: "AFP", 554: "RTSP", 587: "SMTP (submission)", 631: "IPP (printer)",
    636: "LDAPS", 873: "rsync", 902: "VMware", 990: "FTPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MS SQL Server",
    1521: "Oracle DB", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel (SSL)", 2181: "ZooKeeper",
    2375: "Docker API", 2376: "Docker API (TLS)", 3000: "Web dev (Node/Grafana)",
    3306: "MySQL", 3389: "RDP (Remote Desktop)", 3690: "SVN",
    4369: "Erlang EPMD", 5000: "Web dev (Flask)/UPnP", 5037: "ADB (Android)",
    5060: "SIP", 5357: "WSDAPI", 5432: "PostgreSQL", 5672: "RabbitMQ",
    5900: "VNC", 5985: "WinRM (HTTP)", 5986: "WinRM (HTTPS)", 6379: "Redis",
    6443: "Kubernetes API", 6667: "IRC", 7070: "RealServer/AnyDesk",
    8000: "HTTP alternative", 8008: "HTTP alternative", 8080: "HTTP proxy/alternative",
    8081: "HTTP alternative", 8443: "HTTPS alternative", 8888: "HTTP alt./Jupyter",
    9000: "SonarQube/PHP-FPM", 9090: "Prometheus", 9092: "Kafka",
    9100: "Printer (JetDirect)", 9200: "Elasticsearch", 9418: "Git",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB",
}

# Other known ports: not part of the fast scan, but named when they show up
# in a full scan.
KNOWN_PORTS = {
    5040: "Windows CDP", 6463: "Discord RPC", 7680: "Windows Delivery Optimization",
    11434: "Ollama (local AI)", 27036: "Steam", 1900: "SSDP/UPnP",
    5353: "mDNS", 8009: "AJP/Chromecast", 9229: "Node.js debug",
    **{p: "MS-RPC (dynamic port)" for p in range(49664, 49680)},
}

# Ports where we send an HTTP request to "provoke" the banner.
HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200}
# HTTPS ports: we open a TLS connection before asking for the header.
HTTPS_PORTS = {443, 8443, 6443}

# Error codes that mean "no route to the target" (no connection/network).
NO_ROUTE_ERRORS = {
    getattr(errno, "ENETUNREACH", -1), getattr(errno, "EHOSTUNREACH", -1),
    10051, 10065,  # Windows equivalents (WSAENETUNREACH / WSAEHOSTUNREACH)
}


def service_name(port):
    """Returns the typical service name of the port (or 'unknown')."""
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    if port in KNOWN_PORTS:
        return KNOWN_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "unknown"


# =============================================================================
# TARGET: VALIDATION, NAME RESOLUTION AND ETHICAL CONFIRMATION
# =============================================================================
class TargetError(Exception):
    """Error with a friendly message about the given target."""


def normalize_target(text):
    """Accepts 'example.com', 'https://example.com/page' or '10.0.0.1' and
    returns just the name/IP, without protocol, path or port."""
    text = (text or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "//" + text  # lets urlsplit work even without "http://"
    try:
        return (urlsplit(text).hostname or "").strip()
    except ValueError:
        return ""


def resolve_target(text):
    """Turns the typed name into an IP (automatic DNS resolution).
    Returns (clean_name, ip, socket_family)."""
    name = normalize_target(text)
    if not name:
        raise TargetError(f"'{text}' does not look like a valid IP or website address.")
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise TargetError(
            f"Could not find '{name}'. Check that the name is correct "
            "and that you are connected to the internet."
        ) from None
    except (UnicodeError, ValueError):
        raise TargetError(f"'{name}' contains invalid characters.") from None
    if not infos:
        raise TargetError(f"No address found for '{name}'.")
    # Prefer IPv4, which is the most common and compatible.
    infos.sort(key=lambda i: 0 if i[0] == socket.AF_INET else 1)
    family, _, _, _, address = infos[0]
    return name, address[0], family


def local_ips():
    """Lists this machine's own IPs (so we don't ask for confirmation on them)."""
    ips = set()
    try:
        for info_ in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(info_[4][0])
    except OSError:
        pass
    return ips


def is_own_computer(ip):
    try:
        if ipaddress.ip_address(ip).is_loopback:
            return True
    except ValueError:
        return False
    return ip in local_ips()


def confirm_permission(name, ip, already_confirmed=False):
    """Ethical guard: targets that are not your own computer require
    confirmation. Returns True if scanning is allowed."""
    if is_own_computer(ip):
        return True

    public = not ipaddress.ip_address(ip).is_private
    kind = (f"{Color.RED}PUBLIC address on the internet{Color.RESET}" if public
            else "device on the local/private network")
    print()
    warn(f"{Color.BOLD}The target {name} ({ip}) is NOT your computer.{Color.RESET}")
    warn(f"Type: {kind}.")
    warn("Scanning systems without authorization may be illegal and violate terms of service.")
    if already_confirmed:
        info("Permission confirmed via the --yes-i-have-permission option.")
        return True
    if not sys.stdin.isatty():
        error("No terminal to confirm. Use --yes-i-have-permission if you "
              "have authorization to scan this target.")
        return False
    answer = input(f"    Are you the owner or do you have PERMISSION to scan this target? "
                   f"Type {Color.BOLD}yes{Color.RESET} to continue: ")
    if answer.strip().lower() in ("yes", "y", "sim", "s"):
        return True
    info("Scan cancelled. No packets were sent to the target.")
    return False


def parse_ports(text):
    """Turns '20-25,80,443' into a sorted list of valid ports."""
    ports = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        try:
            if "-" in part:
                start, end = (int(x) for x in part.split("-", 1))
            else:
                start = end = int(part)
        except ValueError:
            raise TargetError(f"Invalid port range: '{part}'.") from None
        if not (1 <= start <= end <= 65535):
            raise TargetError(f"Ports must be between 1 and 65535 (got '{part}').")
        ports.update(range(start, end + 1))
    if not ports:
        raise TargetError("No ports provided.")
    return sorted(ports)


# =============================================================================
# BANNER GRABBING (service identification)
# =============================================================================
def clean_banner(data):
    """Reduces the banner to a short, readable line."""
    text = data.decode("utf-8", errors="replace")
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return ""
    if lines[0].upper().startswith("HTTP/"):
        # In HTTP responses, the "Server:" header is the most interesting part.
        server = next((l for l in lines if l.lower().startswith("server:")), "")
        summary = lines[0] + (f" | {server}" if server else "")
    else:
        summary = lines[0]
    summary = "".join(c for c in summary if c.isprintable())
    return summary[:70] + ("..." if len(summary) > 70 else "")


def read_banner(ip, family, port, host, timeout=2.0):
    """Connects to the open port and tries to read the service's greeting.
    Some services (SSH, FTP, SMTP) speak first; for HTTP/HTTPS we send a
    simple 'HEAD /' request to get the server's response."""
    http_request = (f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                    "User-Agent: sonarport\r\n\r\n").encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            if port in HTTPS_PORTS:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE  # we only want to read the banner
                with context.wrap_socket(s, server_hostname=host) as tls:
                    tls.sendall(http_request)
                    return clean_banner(tls.recv(1024))
            if port in HTTP_PORTS:
                s.sendall(http_request)
                return clean_banner(s.recv(1024))
            try:
                data = s.recv(1024)  # wait for the service to "introduce itself"
            except socket.timeout:
                # Silent service: try a generic HTTP request.
                s.sendall(http_request)
                data = s.recv(1024)
            return clean_banner(data)
    except (OSError, ssl.SSLError, ValueError):
        return ""


# =============================================================================
# THE SCANNER (multithreaded)
# =============================================================================
class Scanner:
    """Scans a list of ports using several 'workers' (threads) at the same
    time. Each worker takes a port from the queue, tries to connect and
    records whether it was open."""

    def __init__(self, ip, family, ports, threads=400, timeout=0.5):
        self.ip = ip
        self.family = family
        self.ports = ports
        self.timeout = timeout
        self.num_threads = max(1, min(threads, len(ports)))
        self.queue = queue.Queue()
        self.lock = threading.Lock()     # keeps two threads from writing at once
        self.stop = threading.Event()    # signal to interrupt (Ctrl+C)
        self.open_ports = []
        self.checked = 0
        self.no_route = 0

    def _test_port(self, port):
        """Full TCP connection attempt (connect). 0 = open port."""
        try:
            with socket.socket(self.family, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                code = s.connect_ex((self.ip, port))
        except OSError as e:
            code = e.errno or -1
        if code in NO_ROUTE_ERRORS:
            with self.lock:
                self.no_route += 1
        return code == 0

    def _worker(self):
        """Each thread's loop: takes ports from the queue until it is empty."""
        while not self.stop.is_set():
            try:
                port = self.queue.get_nowait()
            except queue.Empty:
                return
            is_open = self._test_port(port)
            with self.lock:
                self.checked += 1
                if is_open:
                    self.open_ports.append(port)

    def _draw_bar(self):
        total = len(self.ports)
        done = self.checked
        fraction = done / total if total else 1
        width = 30
        filled = int(width * fraction)
        bar = "█" * filled + "░" * (width - filled)
        sys.stdout.write(
            f"\r  {Color.CYAN}[{bar}]{Color.RESET} {fraction * 100:5.1f}%  "
            f"{done}/{total} ports | open: {Color.GREEN}{len(self.open_ports)}{Color.RESET}  "
        )
        sys.stdout.flush()

    def run(self):
        """Starts the threads, shows progress and returns (open_ports, interrupted)."""
        for p in self.ports:
            self.queue.put(p)

        threads = [threading.Thread(target=self._worker, daemon=True)
                   for _ in range(self.num_threads)]
        for t in threads:
            t.start()

        interrupted = False
        animated = sys.stdout.isatty()
        try:
            # The main thread only follows the progress while the workers
            # do the heavy lifting.
            while any(t.is_alive() for t in threads):
                if animated:
                    self._draw_bar()
                time.sleep(0.1)
        except KeyboardInterrupt:
            interrupted = True
            self.stop.set()
            for t in threads:
                t.join(timeout=self.timeout + 1)
        self._draw_bar()
        print()
        return sorted(self.open_ports), interrupted


def read_banners(ip, family, ports, host):
    """Reads the banners of the open ports in parallel (few ports)."""
    banners = {}
    lock = threading.Lock()

    def task(port):
        b = read_banner(ip, family, port, host)
        with lock:
            banners[port] = b

    threads = [threading.Thread(target=task, args=(p,), daemon=True) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return banners


def scan(target_text, ports, mode, threads=400, timeout=0.5,
         with_banner=True, already_confirmed=False):
    """Full flow: resolves the target, confirms permission, scans, reads
    banners and returns a dict with the result (or None if it did not scan)."""
    try:
        name, ip, family = resolve_target(target_text)
    except TargetError as e:
        error(str(e))
        return None

    if not confirm_permission(name, ip, already_confirmed):
        return None

    display = name if name == ip else f"{name} ({ip})"
    print()
    info(f"Target: {Color.BOLD}{display}{Color.RESET}")
    info(f"Mode: {mode} | {len(ports)} port(s) | {threads} threads | timeout {timeout}s")

    start = datetime.now()
    t0 = time.perf_counter()
    scanner = Scanner(ip, family, ports, threads, timeout)
    open_ports, interrupted = scanner.run()

    if interrupted:
        warn("Scan interrupted by the user. Showing partial results.")

    if not open_ports and scanner.no_route >= scanner.checked > 0:
        error("No route to the target. Check your network/internet connection "
              "or whether the address is correct.")

    banners = {}
    if with_banner and open_ports and not interrupted:
        info(f"Reading banners from {len(open_ports)} open port(s)...")
        banners = read_banners(ip, family, open_ports, name)

    result = {
        "target": name,
        "ip": ip,
        "mode": mode,
        "start": start,
        "duration": time.perf_counter() - t0,
        "total": scanner.checked,
        "interrupted": interrupted,
        "ports": [
            {"port": p, "state": "OPEN", "service": service_name(p),
             "banner": banners.get(p, "")}
            for p in open_ports
        ],
    }
    show_result(result)
    return result


# =============================================================================
# OUTPUT: COLORED TABLE AND REPORTS
# =============================================================================
def build_table(rows, colorize=True):
    """Builds a table with borders. 'rows' is a list of port dicts."""
    header = ["PORT", "STATE", "SERVICE", "BANNER"]
    data = [[f"{r['port']}/tcp", r["state"], r["service"], r["banner"] or "-"]
            for r in rows]
    widths = [max(len(header[i]), *(len(d[i]) for d in data)) for i in range(4)]

    def paint(text, code):
        return f"{code}{text}{Color.RESET}" if colorize and code else text

    def border_line(left, mid, right):
        return left + mid.join("─" * (w + 2) for w in widths) + right

    def data_line(cells, colors):
        parts = [f" {paint(c.ljust(w), k)} " for c, w, k in zip(cells, widths, colors)]
        return "│" + "│".join(parts) + "│"

    out = [border_line("┌", "┬", "┐"),
           data_line(header, [Color.BOLD] * 4),
           border_line("├", "┼", "┤")]
    for d in data:
        out.append(data_line(d, [Color.BLUE, Color.GREEN, Color.YELLOW, Color.GRAY]))
    out.append(border_line("└", "┴", "┘"))
    return "\n".join(out)


def summary_text(r):
    display = r["target"] if r["target"] == r["ip"] else f"{r['target']} ({r['ip']})"
    return (f"{len(r['ports'])} open port(s) out of {r['total']} checked "
            f"on {display} - {r['duration']:.1f}s")


def show_result(r):
    print()
    if r["ports"]:
        print(build_table(r["ports"]))
    else:
        info("No open ports found (all closed or filtered by a firewall).")
    print()
    ok(summary_text(r))


def save_report(r, fmt="both", folder="reports"):
    """Saves the result to .txt and/or .csv. Returns the list of files created."""
    if fmt == "ambos":          # Portuguese alias for "both"
        fmt = "both"
    os.makedirs(folder, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in "-." else "_" for c in r["target"])
    base = os.path.join(folder, f"sonarport_{safe}_{r['start']:%Y%m%d_%H%M%S}")
    created = []

    if fmt in ("txt", "both"):
        path = base + ".txt"
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"sonarport report v{__version__}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Target   : {r['target']}\n")
            f.write(f"IP       : {r['ip']}\n")
            f.write(f"Mode     : {r['mode']}\n")
            f.write(f"Date     : {r['start']:%Y-%m-%d %H:%M:%S}\n")
            f.write(f"Duration : {r['duration']:.1f}s\n")
            f.write(f"Checked  : {r['total']} port(s)\n")
            if r["interrupted"]:
                f.write("Status   : INTERRUPTED (partial result)\n")
            f.write("\n")
            if r["ports"]:
                f.write(build_table(r["ports"], colorize=False) + "\n")
            else:
                f.write("No open ports found.\n")
            f.write("\n" + summary_text(r) + "\n")
        created.append(path)

    if fmt in ("csv", "both"):
        path = base + ".csv"
        # utf-8-sig makes Excel open accented characters correctly.
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["target", "ip", "port", "protocol", "state",
                             "service", "banner", "date"])
            for p in r["ports"]:
                writer.writerow([r["target"], r["ip"], p["port"], "tcp", p["state"],
                                 p["service"], p["banner"],
                                 f"{r['start']:%Y-%m-%d %H:%M:%S}"])
        created.append(path)

    return created


# =============================================================================
# INTERACTIVE MENU
# =============================================================================
LOGO = r"""
                                               _
   ___  ___  _ __   __ _ _ __ _ __   ___  _ __| |_
  / __|/ _ \| '_ \ / _` | '__| '_ \ / _ \| '__| __|
  \__ \ (_) | | | | (_| | |  | |_) | (_) | |  | |_
  |___/\___/|_| |_|\__,_|_|  | .__/ \___/|_|   \__|
                             |_|
"""

ALL_PORTS = list(range(1, 65536))


def prompt(text):
    """input() that handles Ctrl+C / end of input gracefully."""
    try:
        # Removes the BOM (﻿) that some terminals put at the start of input.
        return input(text).replace("﻿", "")
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit(0)


def prompt_target():
    target = prompt(f"  Enter the IP or website (Enter = localhost): ").strip()
    return target or "localhost"


def prompt_mode():
    """Asks whether the scan will be fast (common) or full."""
    print("  Scan type:")
    print("    [Enter] Most common ports (fast)")
    print("    c       Full (1-65535, takes longer)")
    choice = prompt("  > ").strip().lower()
    if choice == "c":
        return "full (1-65535)", ALL_PORTS
    return "common ports", sorted(COMMON_PORTS)


def menu():
    print(f"{Color.CYAN}{LOGO}{Color.RESET}")
    print(f"  {Color.BOLD}sonarport v{__version__}{Color.RESET} - ethical port scanner")
    print(f"  {Color.YELLOW}Use only on systems you own or are authorized to test.{Color.RESET}")

    last = None
    while True:
        print(f"\n{Color.BOLD}  ===== MENU ====={Color.RESET}")
        print("  1) Scan my own computer (localhost)")
        print("  2) Scan an IP or website I provide")
        print("  3) Scan the most common ports (fast)")
        print("  4) Full scan (all ports 1-65535)")
        print("  5) Save the report of the last scan")
        print("  0) Exit")
        option = prompt("\n  Choose an option: ").strip()

        result = None
        if option == "1":
            mode, ports = prompt_mode()
            result = scan("localhost", ports, mode)
        elif option == "2":
            target = prompt(f"  Enter the IP or website (e.g. 192.168.0.1 or example.com): ").strip()
            if not target:
                warn("No target entered.")
                continue
            mode, ports = prompt_mode()
            result = scan(target, ports, mode)
        elif option == "3":
            result = scan(prompt_target(), sorted(COMMON_PORTS), "common ports")
        elif option == "4":
            result = scan(prompt_target(), ALL_PORTS, "full (1-65535)")
        elif option == "5":
            if not last:
                warn("No scan has been done yet. Scan something first.")
                continue
            print("  Format: 1) .txt   2) .csv   [Enter] both")
            f = prompt("  > ").strip()
            fmt = {"1": "txt", "2": "csv"}.get(f, "both")
            try:
                for path in save_report(last, fmt):
                    ok(f"Report saved to: {os.path.abspath(path)}")
            except OSError as e:
                error(f"Could not save the report: {e}")
        elif option == "0":
            info("See you!")
            return
        else:
            warn("Invalid option. Type a number from 0 to 5.")
            continue

        if result:
            last = result
            info("Tip: use option 5 to save this report.")


# =============================================================================
# COMMAND LINE
# =============================================================================
def build_parser():
    p = argparse.ArgumentParser(
        prog="sonarport",
        description="sonarport - a simple, fast and ethical TCP port scanner. "
                    "With no arguments, it opens the interactive menu.",
        epilog="Examples:\n"
               "  python sonarport.py --common\n"
               "  python sonarport.py --target 192.168.0.1 --common\n"
               "  python sonarport.py --target example.com --ports 20-25,80,443\n"
               "  python sonarport.py --full --save both\n\n"
               "Use only on systems you own or are authorized to test. "
               "Portuguese aliases (--comuns, --alvo, --completo...) also work.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-a", "--target", "--alvo", dest="target", default="localhost",
                   help="IP or website to scan (default: localhost)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("-c", "--common", "--comuns", dest="common", action="store_true",
                      help="scans the most common ports (default)")
    mode.add_argument("-C", "--full", "--completo", dest="full", action="store_true",
                      help="scans all ports 1-65535")
    mode.add_argument("-p", "--ports", "--portas", dest="ports", metavar="LIST",
                      help="specific ports, e.g. 22,80,443 or 1-1024")
    p.add_argument("-t", "--threads", type=int, default=400,
                   help="number of simultaneous threads (default: 400)")
    p.add_argument("--timeout", type=float, default=0.5,
                   help="max wait per port in seconds (default: 0.5)")
    p.add_argument("--no-banner", "--sem-banner", dest="no_banner", action="store_true",
                   help="does not try to read service banners")
    p.add_argument("-s", "--save", "--salvar", dest="save",
                   choices=["txt", "csv", "both", "ambos"],
                   help="saves the report in the chosen format")
    p.add_argument("--folder", "--pasta", dest="folder", default="reports",
                   help="folder for the reports (default: reports)")
    p.add_argument("--yes-i-have-permission", "--sim-tenho-permissao",
                   dest="permission", action="store_true",
                   help="confirms you are authorized to scan the target "
                        "(skips the question; use responsibly)")
    p.add_argument("--no-color", "--sem-cor", dest="no_color", action="store_true",
                   help="disables colors")
    p.add_argument("-v", "--version", "--versao", action="version",
                   version=f"sonarport {__version__}")
    return p


def command_line(argv):
    args = build_parser().parse_args(argv)
    if args.no_color:
        Color.disable()
    if not 1 <= args.threads <= 2000:
        error("Use between 1 and 2000 threads.")
        return 1
    if not 0.05 <= args.timeout <= 30:
        error("The timeout must be between 0.05 and 30 seconds.")
        return 1

    if args.full:
        mode, ports = "full (1-65535)", ALL_PORTS
    elif args.ports:
        try:
            ports = parse_ports(args.ports)
        except TargetError as e:
            error(str(e))
            return 1
        mode = f"custom ports ({args.ports})"
    else:
        mode, ports = "common ports", sorted(COMMON_PORTS)

    result = scan(args.target, ports, mode, args.threads, args.timeout,
                  not args.no_banner, args.permission)
    if result is None:
        return 2
    if args.save:
        try:
            for path in save_report(result, args.save, args.folder):
                ok(f"Report saved to: {os.path.abspath(path)}")
        except OSError as e:
            error(f"Could not save the report: {e}")
            return 1
    return 130 if result["interrupted"] else 0


def main():
    try:
        if len(sys.argv) == 1:
            menu()
            return 0
        return command_line(sys.argv[1:])
    except KeyboardInterrupt:
        print()
        warn("Interrupted by the user.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
