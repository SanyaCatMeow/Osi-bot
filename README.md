# OSINT Telegram Bot

A Telegram bot for open-source intelligence automation. All data is gathered exclusively from **public, open sources** — no illegal access, no private databases.

---

## Features

| Command | Description |
|---------|-------------|
| `/ip <address>` | Geolocation, ISP, ASN, VPN/Proxy/Tor detection, AbuseIPDB score |
| `/domain <domain>` | WHOIS, DNS records (A/MX/NS/TXT/SOA), VirusTotal reputation |
| `/email <address>` | Format validation, MX check, optional breach check (HIBP) |
| `/user <username>` | Username search across 28+ platforms in parallel |
| `/phone <number>` | Country, carrier, line type, timezone (via libphonenumber) |
| `/url <link>` | Redirect chain, page metadata, VirusTotal, Google Safe Browsing |
| `/file` | Upload a file → EXIF metadata (GPS!), MD5/SHA1/SHA256, VirusTotal |
| `/history` | Last 10 queries stored in local SQLite |

---

## Setup

### 1. Clone & install

```bash
git clone <repo-url>
cd osi_bot
pip install -r requirements.txt
```

### 2. Configure

```bash
cp config.env.example config.env
```

Edit `config.env` and fill in at minimum:

```env
TELEGRAM_TOKEN=your_bot_token_from_BotFather
```

Optional API keys (all have free tiers):

| Key | Service | Free limit |
|-----|---------|------------|
| `VIRUSTOTAL_API_KEY` | File / URL / domain scans | 4 req/min |
| `ABUSEIPDB_API_KEY` | IP blacklist check | 1 000/day |
| `NUMVERIFY_API_KEY` | Phone enrichment | 100/month |
| `GOOGLE_SAFE_BROWSING_KEY` | URL threat check | Free |
| `HIBP_API_KEY` | Email breach check | $3.5/month |

### 3. Run

```bash
python main.py
```

---

## Project Structure

```
osi_bot/
├── main.py                  # Entry point
├── config.py                # Settings (loads config.env)
├── config.env.example       # Template — copy to config.env
├── database.py              # SQLite query history
├── handlers.py              # Telegram command handlers
├── keyboards.py             # Inline keyboards
├── utils.py                 # Validators & HTML formatting helpers
├── analyzers/
│   ├── ip_scanner.py        # ip-api.com + AbuseIPDB
│   ├── domain_scanner.py    # WHOIS + DNS + VirusTotal
│   ├── email_scanner.py     # MX check + HIBP
│   ├── username_scanner.py  # 28+ platform check
│   ├── phone_scanner.py     # libphonenumber + Numverify
│   ├── url_scanner.py       # Redirect + metadata + VT + GSB
│   └── file_analyzer.py     # EXIF + hashes + VirusTotal
├── requirements.txt
└── README.md
```

---

## Legal note

This tool uses only public APIs and publicly accessible web pages. It does not perform port scanning, network intrusion, or access any private/paid databases without a valid key. Users are responsible for complying with the terms of service of each third-party API.

---

## Tech stack

- Python 3.11+
- [python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot) v21 (async)
- [httpx](https://www.python-httpx.org/) — async HTTP
- [dnspython](https://www.dnspython.org/) — DNS queries
- [python-whois](https://pypi.org/project/python-whois/) — WHOIS
- [phonenumbers](https://github.com/daviddrysdale/python-phonenumbers) — Google libphonenumber
- [Pillow](https://pillow.readthedocs.io/) + EXIF — image metadata
- [aiosqlite](https://github.com/omnilib/aiosqlite) — async SQLite
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) — HTML parsing
