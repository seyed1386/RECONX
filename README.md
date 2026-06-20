# ReconX

Automated recon and exploit suggestion tool for ethical hacking labs.
Built by Seyed. Tested on Kali Linux against live targets in a home lab.

---

## What it does

- Scans the top 15 most targeted TCP ports
- Detects OS via TTL from a single ping
- Maps every open port to real attack commands with CVEs
- Grabs service banners concurrently
- Assigns risk levels: CRITICAL, HIGH, MEDIUM
- Saves a full report in both TXT and JSON format

---

## Ports scanned

| Port | Service   | Risk     |
|------|-----------|----------|
| 21   | FTP       | HIGH     |
| 22   | SSH       | MEDIUM   |
| 23   | Telnet    | CRITICAL |
| 25   | SMTP      | MEDIUM   |
| 53   | DNS       | HIGH     |
| 80   | HTTP      | HIGH     |
| 110  | POP3      | MEDIUM   |
| 139  | NetBIOS   | HIGH     |
| 443  | HTTPS     | MEDIUM   |
| 445  | SMB       | CRITICAL |
| 1433 | MSSQL     | CRITICAL |
| 3306 | MySQL     | HIGH     |
| 3389 | RDP       | CRITICAL |
| 8080 | HTTP-Alt  | MEDIUM   |
| 8443 | HTTPS-Alt | MEDIUM   |

---

## Install
pip install rich

Requires nmap installed and sudo access.
sudo apt install nmap

---

## Usage
sudo python3 recon.py <target>
sudo python3 recon.py 192.168.1.130
sudo python3 recon.py 192.168.1.130 --stealth

---

## Output

Each open port prints:

- CVE reference
- What the vulnerability does
- Exact nmap check command
- Full attack command ready to run

Reports are saved automatically:
recon_192.168.1.130_20260619_002200.txt
recon_192.168.1.130_20260619_002200.json

---

## Phases
[1] HOST CHECK      ping + DNS resolution
[2] PORT SCAN       nmap -sS -T4 across 15 ports
[3] OS DETECTION    TTL-based OS guess
[4] EXPLOIT CHAIN   CVE-mapped attack commands per open port
[5] BANNER GRAB     concurrent socket banner pull

---

## Legal

For use on systems you own or have written permission to test.
Do not run this against targets you do not control.

---

## Author

Seyed
github.com/seyedebrahimhashemi
