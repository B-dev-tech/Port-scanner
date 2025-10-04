🛡️ Port‑scanner (APScan) — By B‑dev

🙏This is beta version something might wrong.

Advanced asynchronous TCP port scanner for educational use.
Fast connect-scanning, banner grabbing, lightweight fingerprinting, JSON/CSV export, and beautiful table output using rich 🌈

> ⚠️ Legal / Ethical: Use this tool only on hosts/networks you own or have explicit permission to test. Unauthorized scanning may be illegal. The author is not responsible for misuse.




---

📂 Repository layout (important files)

advanced_port_scanner.py — main CLI program (Click-based) 🐍

pocan — shell wrapper to run from the repo folder (chmod +x pocan) 💻

pocan.bat — Windows wrapper 🪟

requirements.txt — Python dependencies 📦

install.sh — copies pocan to ~/.local/bin ⚡

LICENSE — MIT License 📄

README.md — this file 📘



---

🚀 Quick start

1️⃣ Clone the repo

git clone https://github.com/B-dev-tech/Port-scanner.git
cd Port-scanner

2️⃣ Create and activate a Python virtual environment (recommended)

python3 -m venv venv
source venv/bin/activate      # macOS / Linux / Termux
# venv\Scripts\activate       # Windows (PowerShell / cmd)

3️⃣ Install dependencies

pip install -r requirements.txt
# or manually:
pip install click rich dnspython requests


---

4️⃣ Run (examples)

💡 Interactive quick scan (prompt for IP if omitted)

./pocan pocan ip --ip 192.168.1.5 --rich --top 30
# or
python advanced_port_scanner.py pocan ip --ip 192.168.1.5 --rich --top 30

⚡ Non-interactive scan (pretty table)

python advanced_port_scanner.py scan --target example.com --top 100 --pretty

🔢 Scan specific port ranges

python advanced_port_scanner.py scan --target 10.0.0.5 --ports 1-1024,3306 --concurrency 300 --timeout 0.8 --output result.json

🌐 Install pocan globally (per user)

./install.sh
# Make sure ~/.local/bin is in your PATH
pocan pocan ip --ip 192.168.1.5 --rich

🛠️ Install as editable package (dev)

pip install -e .
# then
pocan pocan ip --ip 127.0.0.1 --rich


---

📊 What this tool outputs

Each scanned port produces a structured record with fields:

port — port number 🔢 (e.g. 22, 80)

open — boolean; true ✅ if connection succeeded

service — guessed service 📝 (from banner or common-port fallback)

banner — raw banner/text read from service 📬 (if any)

protocol — currently TCP 🌐

ssl — whether TLS handshake was attempted/succeeded 🔒

time — seconds required to scan that port ⏱️

notes — helpful statuses: closed, timeout/filtered, open-no-banner, ssl-handshake-failed, etc 🛑


Outputs can be printed as a rich table (if rich installed), plain text, JSON or CSV (--output result.json or --output result.csv).


---

✨ Example (rich table preview)

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                          Scan results — 192.168.1.5                 ┃
┡━━━━━━┯━━━━━━┯━━━━━━━┯━━━━━━━━━━┯━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━┯━━━━━━┯━━━━━━━┩
│ Ip   │ Port │ Open  │ Service  │ Banner               │ Proto │ SSL  │ Time  │
├──────┼──────┼───────┼──────────┼──────────────────────┼───────┼──────┼───────┤
│ ...  │ 22   │ yes   │ ssh      │ SSH-2.0-OpenSSH...   │ TCP   │ No   │ 0.045 │
│ ...  │ 80   │ yes   │ http     │ HTTP/1.1 200 OK      │ TCP   │ No   │ 0.110 │
│ ...  │ 443  │ yes   │ https    │ TLS handshake succ.  │ TCP   │ Yes  │ 0.200 │
└──────┴──────┴───────┴──────────┴──────────────────────┴───────┴──────┴───────┘


---

⚙️ Configuration & options

--top N : scan top N common ports (fast) 🔝

--ports SPEC : explicit ports (e.g. 1-1024,3306,8080) 🧮

--concurrency : number of parallel connection attempts 🔄

--timeout : per-connection timeout in seconds ⏳

--output FILE : save results to JSON or CSV 💾

--pretty / --rich : enable rich table UI 🌈



---

🔍 Extending fingerprints

Fingerprints are implemented using regex rules inside the scanner. To add or tune fingerprints:

1. Edit the FINGERPRINTS list in advanced_port_scanner.py ✏️


2. Or add a signatures.json loader for more rules 📂




---

🛠️ Development notes

Uses async asyncio.open_connection() (connect scan) — no root needed 🚫

UDP and SYN scan not implemented ⚠️

Educational & easy-to-read code for learning Python and pentesting basics 🐍



---

⚠️ Security & Responsible Disclosure

Do not scan third-party networks without permission

Report vulnerabilities via GitHub issues or SECURITY.md 🔐



---

🤝 Contributing

1. Fork the repo 🍴


2. Create a branch for your feature/fix 🌿


3. Open a pull request with description & optional tests 📝




---

📜 License

This project is licensed under MIT License. See LICENSE for details 🆓


---

ถ้าคุณต้องการ ผมสามารถทำ เวอร์ชัน Markdown พร้อม emoji แบบสวยเต็ม GitHub และใส่ ตัวอย่างผลลัพธ์ JSON/CSV พร้อม emoji ให้ดูง่ายและน่ารันขึ้นได้ 💥

คุณอยากให้ผมทำเวอร์ชันนั้นไหม?

