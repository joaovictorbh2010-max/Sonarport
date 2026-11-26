<h1 align="center">Sonarport</h1>

<p align="center">
  <b>A simple, fast and ethical TCP port scanner written in pure Python.</b><br>
  Find out which ports are open on your computer, or on hosts you have permission to test, and which services run on them.
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.8%2B-blue?logo=python&logoColor=white">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-none%20required-brightgreen">
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-yellow">
</p>

---

> [!WARNING]
> **Ethical and legal use**
>
> Sonarport is an **educational and diagnostic** tool. Use it **only**:
> - on your **own computer** (`localhost`);
> - on networks and devices that **belong to you**;
> - on systems for which you have **explicit authorization** from the owner (preferably in writing).
>
> Scanning third-party systems without permission may be a **crime** (in Brazil, for example, Law 12.737/2012) and violates the terms of service of most providers. The author is not responsible for misuse.
> That is why Sonarport **targets localhost by default** and **asks for confirmation** before scanning any other target.

---

## Features

| Feature | Description |
|---|---|
| **Interactive menu** | Do everything by typing a number, no commands to memorize |
| **Command line** | Arguments for automation and scripts (`--target`, `--common`, `--full`...) |
| **Multithreaded** | Hundreds of "workers" in parallel, with a progress bar |
| **Service identification** | Shows the typical service of each port (22 = SSH, 80 = HTTP, 443 = HTTPS...) |
| **Banner grabbing** | Tries to read the service "greeting" (e.g. SSH version, HTTP/HTTPS `Server` header) |
| **DNS resolution** | Type `example.com` and it finds the IP on its own |
| **Colored table** | Results organized by port / state / service / banner |
| **Reports** | Saves to `.txt` (readable) and `.csv` (opens in Excel / Sheets) |
| **Ethical guard** | Localhost by default and mandatory confirmation for other targets |
| **Zero dependencies** | Only the standard library (`socket`, `threading`, `queue`...). `colorama` is optional |

## 📦 Installation

**Requirement:** [Python 3.8 or newer](https://www.python.org/downloads/).

```bash
# 1. Download the project
git clone https://github.com/joaovictorbh2010-max/sonarport.git
cd sonarport

# 2. (Optional) Install colorama for colors on any Windows terminal
pip install -r requirements.txt
```

That's it, nothing else is needed. Without `colorama`, colors still work on Windows Terminal, modern PowerShell, Linux and macOS.

## How to use

### Mode 1: interactive menu (easiest)

```bash
python sonarport.py
```

sonarport v1.0.0 - ethical port scanner
Use only on systems you own or are authorized to test.

===== MENU =====

Scan my own computer (localhost)
Scan an IP or website I provide
Scan the most common ports (fast)
Full scan (all ports 1-65535)
Save the report of the last scan
Exit

Choose an option:


| Option | What it does |
|---|---|
| **1** | Scans your own PC. Asks whether it's fast (Enter) or full (`c`) |
| **2** | Asks for an IP or website, **confirms permission** and asks the scan type |
| **3** | Scans the ~75 most common ports (Enter = localhost) |
| **4** | Scans all 65,535 ports (Enter = localhost) |
| **5** | Saves the last result to `.txt`, `.csv` or both, in the `reports/` folder |
| **0** | Exits the program |

### Mode 2: command line

```bash
# Common ports on your computer (the default target is localhost)
python sonarport.py --common

# Common ports on a device on your network
python sonarport.py --target 192.168.0.1 --common

# All ports, saving the report to .txt and .csv
python sonarport.py --full --save both

# Specific ports or ranges on a website (DNS is resolved automatically)
python sonarport.py --target example.com --ports 20-25,80,443

# More speed: more threads and a lower timeout
python sonarport.py --full --threads 1000 --timeout 0.3

# Full help
python sonarport.py --help
```

| Argument | Shortcut | Description | Default |
|---|---|---|---|
| `--target` | `-a` | IP or website to scan | `localhost` |
| `--common` | `-c` | Scans the most common ports | ✅ |
| `--full` | `-C` | Scans ports 1-65535 | |
| `--ports` | `-p` | List/ranges, e.g. `22,80,443` or `1-1024` | |
| `--threads` | `-t` | Number of simultaneous threads (1-2000) | `400` |
| `--timeout` | | Max wait per port, in seconds | `0.5` |
| `--no-banner` | | Does not try to read service banners | |
| `--save` | `-s` | Save report: `txt`, `csv` or `both` | |
| `--folder` | | Folder where reports are saved | `reports` |
| `--yes-i-have-permission` | | Confirms authorization without asking (for scripts) | |
| `--no-color` | | Disables colors | |
| `--version` | `-v` | Shows the version | |

> When scanning a target that is not your own computer, Sonarport shows a warning, states whether the IP is **public** or on a **private network**, and asks you to type `yes`. In scripts without a terminal, you must pass `--yes-i-have-permission`, consciously.

## 📊 Example output

Fast scan of localhost on Windows 11:

[] Target: localhost (127.0.0.1)
[] Mode: common ports | 74 port(s) | 400 threads | timeout 0.5s
[██████████████████████████████] 100.0% 74/74 ports | open: 4
[*] Reading banners from 4 open port(s)...

┌──────────┬────────┬────────────────────────┬──────────────────────────────────────────────────────────────────┐
│ PORT │ STATE │ SERVICE │ BANNER │
├──────────┼────────┼────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ 135/tcp │ OPEN │ MS-RPC │ - │
│ 445/tcp │ OPEN │ SMB │ - │
│ 5357/tcp │ OPEN │ WSDAPI │ HTTP/1.1 503 Service Unavailable | Server: Microsoft-HTTPAPI/2.0 │
│ 8080/tcp │ OPEN │ HTTP proxy/alternative │ - │
└──────────┴────────┴────────────────────────┴──────────────────────────────────────────────────────────────────┘

[+] 4 open port(s) out of 74 checked on localhost (127.0.0.1) - 4.6s


Generated `.csv` report:

```csv
target,ip,port,protocol,state,service,banner,date
localhost,127.0.0.1,135,tcp,OPEN,MS-RPC,,2026-11-26 11:10:18
localhost,127.0.0.1,445,tcp,OPEN,SMB,,2026-11-26 11:10:18
localhost,127.0.0.1,5357,tcp,OPEN,WSDAPI,HTTP/1.1 503 Service Unavailable | Server: Microsoft-HTTPAPI/2.0,2026-11-26 11:10:18
```

## ⚙️ How it works

1. **Target resolution:** `socket.getaddrinfo` turns the website name into an IP (prefers IPv4). It also accepts URLs like `https://example.com/page`.
2. **Ethical guard:** if the IP is not your own computer, the program warns you and asks for confirmation.
3. **Queue + workers:** all ports go into a `queue.Queue`; N threads take ports from the queue and try a TCP connection (`connect_ex`). Code `0` = **open** port.
4. **Progress bar:** the main thread only follows the counter, protected by a `threading.Lock`.
5. **Banners:** on open ports, the program waits for the service to introduce itself (SSH, FTP, SMTP...) or sends a `HEAD /` (HTTP) or opens TLS (HTTPS) to read the `Server` header.
6. **Reports:** the `csv` module and UTF-8 text writing.

## FAQ

- **"No open ports found"**: the ports may be closed or **filtered by a firewall**. That's a good security sign!
- **The full scan is slow**: on Windows, refused connections on localhost are slower than on Linux. Increase the threads (`--threads 1000`) or lower the timeout (`--timeout 0.3`). On remote hosts, a very low timeout can hide open ports.
- **TCP only?** Yes. Sonarport does a *TCP connect scan*, which does not require administrator rights. UDP-only services (DNS over UDP, DHCP, SNMP...) do not show up.
- **Stop it:** press `Ctrl+C` at any time. Partial results are shown.

## 🗂️ Project structure

sonarport/
├── sonarport.py # main program (all in one file)
├── requirements.txt # optional dependency (colorama)
├── README.md # this file
├── LICENSE # MIT license
└── .gitignore # ignores generated reports and Python cache


## Future ideas

- [ ] Network range scanning (e.g. `192.168.0.0/24`), with confirmation
- [ ] Export to JSON and HTML
- [ ] More complete per-service version detection
- [ ] UDP support

## 📄 License

Distributed under the **MIT** license. See [LICENSE](LICENSE).

---

<p align="center"><i>Made to learn networking and security responsibly. Scan only what is yours. 🔒</i></p>
