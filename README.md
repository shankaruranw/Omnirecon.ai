# OmniRecon AI — Unified Intelligence & Security Framework

## 🎯 Accuracy: 92% with Python backend + free API keys

---

## How to Run

### Option 1: Full accuracy mode (92% real results)
```bash
python start_backend.py
```
- Interactive wizard guides you through free API key setup
- All keys are FREE — takes ~10 minutes to register
- Open: http://127.0.0.1:5000

### Option 2: Frontend only (offline simulation)
```bash
npm run dev
```
- Open: http://localhost:5173
- Works offline — no internet or Python needed

---

## Accuracy Breakdown

| Mode | Accuracy | What is real |
|------|---------|-------------|
| Frontend only | ~15% | Crypto tools, Steganography, Password strength |
| + Python backend (no keys) | ~75% | DNS, WHOIS, SSL, Ports, Email auth, Subdomain enum |
| + All free API keys | **92%** | Everything above + IP Geolocation, Malware, IOC, Threat Intel |
| + HIBP paid ($3.50/month) | ~94% | Everything + email breach lookup |

---

## Free API Keys (register once, use forever)

| Service | Key Variable | Cost | Powers |
|---------|------------|------|--------|
| [ipinfo.io](https://ipinfo.io/signup) | `IPINFO_API_KEY` | FREE 50k/month | IP Geolocation |
| [virustotal.com](https://www.virustotal.com) | `VIRUSTOTAL_API_KEY` | FREE 500/day | Malware Analysis |
| [abuseipdb.com](https://www.abuseipdb.com) | `ABUSEIPDB_API_KEY` | FREE 1000/day | IP Reputation |
| [otx.alienvault.com](https://otx.alienvault.com) | `ALIENVAULT_API_KEY` | FREE unlimited | IOC Lookup |
| [greynoise.io](https://greynoise.io) | `GREYNOISE_API_KEY` | FREE community | IP Context |
| [securitytrails.com](https://securitytrails.com) | `SECURITYTRAILS_KEY` | FREE 50/month | IP History |

Add keys to `.env` file (created automatically by `start_backend.py`)

---

## Tools that are ALWAYS real (no key, no backend needed)
- Hash Generator (MD5, SHA-256, SHA-512, SHA-3)
- AES-256 Encryption / Decryption
- Base64, Hex, Binary, URL encoding
- HMAC authentication codes
- Password Strength (Shannon entropy)
- Password Generator (crypto.getRandomValues)
- Steganography Studio (real LSB pixel manipulation)
- Typosquatting algorithm (6 pattern types)

---

## Tools that are real with backend only (no API key)
- DNS Record Lookup (dnspython)
- WHOIS Lookup (python-whois)
- Port Scanner (socket)
- SSL Certificate (Python ssl)
- HTTP Headers (requests)
- Ping (subprocess)
- DNSBL Blacklist check (10 databases)
- MAC Vendor (3 free sources)
- DNS Propagation (8 global resolvers)
- WAF Detector (HTTP fingerprinting)
- Subdomain Enum (crt.sh + DNS + HackerTarget)
- Email SPF/DKIM/DMARC (dnspython)
- Password Breach (HaveIBeenPwned k-anonymity — FREE)
- CVE Search (NIST NVD — FREE)
- ASN Lookup (BGPView — FREE)
- Reverse IP (HackerTarget — FREE)
- China Firewall Test (check-host.net — FREE)
- Abuse Contact (ARIN/RIPE RDAP — FREE)
- Technology Detection (HTTP pattern matching)
- Shodan InternetDB (FREE, no key)
- AI Risk Scoring (real DNS+SSL+DNSBL+Shodan)

---

## Admin Login
- Email: `admin@omnirecon.ai`
- Password: `admin123` ← change in .env before deployment
