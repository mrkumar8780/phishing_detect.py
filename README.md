# Phishing Detection Tool

A lightweight CLI tool that analyses URLs for common phishing indicators.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py --url <URL>
```

### Examples

```bash
python main.py --url https://google.com
python main.py --url http://192.168.1.1/login
python main.py --url https://paypal-login-secure.com
python main.py --url https://bit.ly/xyz123
```

## How It Works

Each URL is run through six independent checks:

| Check | What it flags |
|---|---|
| IP-based URL | Raw IP addresses instead of domain names |
| HTTPS check | URLs using HTTP instead of HTTPS |
| Length check | URLs longer than 75 characters |
| Shortener check | Known URL shortening services |
| Blacklist check | Domains in the local `data/blacklist.txt` |
| Domain check | Lookalike / brand-spoofing domains |

A risk score is accumulated and mapped to a final verdict:

| Score | Verdict |
|---|---|
| 0 | SAFE |
| 1–3 | SUSPICIOUS |
| 4+ | DANGEROUS |

## Project Structure

```
phishing-detection-system/
├── main.py
├── requirements.txt
├── README.md
├── checks/
│   ├── __init__.py
│   ├── domain_check.py
│   ├── ip_check.py
│   ├── https_check.py
│   ├── length_check.py
│   ├── shortener_check.py
│   └── blacklist_check.py
└── data/
    └── blacklist.txt
```

## Adding to the Blacklist

Open `data/blacklist.txt` and add one domain per line:

```
evil-phishing-site.com
another-fake-bank.net
```
