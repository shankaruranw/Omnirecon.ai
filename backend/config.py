"""
OmniRecon AI — Configuration & API Keys
=========================================

QUICK SETUP:
    python start_backend.py
    (The wizard will guide you through every key)

OR manually create a .env file in the project root:
    VIRUSTOTAL_API_KEY=your_key_here
    IPINFO_API_KEY=your_key_here
    ...

FREE API Keys (register in 2 minutes):
  VirusTotal   → https://www.virustotal.com           500 req/day
  IPInfo       → https://ipinfo.io/signup             50,000 req/month
  AbuseIPDB    → https://www.abuseipdb.com            1,000 req/day
  AlienVault   → https://otx.alienvault.com           Unlimited free
  GreyNoise    → https://greynoise.io                 Free community
  SecurityTrails→https://securitytrails.com           50 req/month
  Shodan       → https://account.shodan.io            Free tier

Paid Keys:
  HaveIBeenPwned → https://haveibeenpwned.com/API/Key  $3.5/month
"""

import os
import secrets


# ─────────────────────────────────────────────────────────────
# Auto-load .env file
# ─────────────────────────────────────────────────────────────

def _load_env():
    """Load .env file from project root into environment."""
    env_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", ".env")
    )
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                key   = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value

_load_env()


# ─────────────────────────────────────────────────────────────
# Admin Credentials  ← CHANGE BEFORE DEPLOYMENT
# ─────────────────────────────────────────────────────────────

ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL",    "admin@omnirecon.ai")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))


# ─────────────────────────────────────────────────────────────
# API Keys  ← Add your keys here OR in .env file
# ─────────────────────────────────────────────────────────────

# FREE — 500 requests/day — https://www.virustotal.com
VIRUSTOTAL_API_KEY   = os.environ.get("VIRUSTOTAL_API_KEY",   "")

# FREE — 50,000 requests/month — https://ipinfo.io/signup
IPINFO_API_KEY       = os.environ.get("IPINFO_API_KEY",       "")

# FREE — 1,000 requests/day — https://www.abuseipdb.com
ABUSEIPDB_API_KEY    = os.environ.get("ABUSEIPDB_API_KEY",    "")

# FREE unlimited — https://otx.alienvault.com
ALIENVAULT_API_KEY   = os.environ.get("ALIENVAULT_API_KEY",   "")

# FREE — 50 req/month — https://securitytrails.com
SECURITYTRAILS_KEY   = os.environ.get("SECURITYTRAILS_KEY",   "")

# FREE community — https://greynoise.io
GREYNOISE_API_KEY    = os.environ.get("GREYNOISE_API_KEY",    "")

# FREE tier — https://account.shodan.io
SHODAN_API_KEY       = os.environ.get("SHODAN_API_KEY",       "")

# PAID $3.5/month — https://haveibeenpwned.com/API/Key
HIBP_API_KEY         = os.environ.get("HIBP_API_KEY",         "")


# ─────────────────────────────────────────────────────────────
# Server Config
# ─────────────────────────────────────────────────────────────

HOST    = os.environ.get("HOST",  "127.0.0.1")
PORT    = int(os.environ.get("PORT",  "5000"))
DEBUG   = os.environ.get("DEBUG", "false").lower() == "true"

ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*").split(",")

MAX_LOGIN_ATTEMPTS   = int(os.environ.get("MAX_LOGIN_ATTEMPTS",  "5"))
MAX_REQUESTS_PER_MIN = int(os.environ.get("MAX_REQUESTS_PER_MIN", "60"))


# ─────────────────────────────────────────────────────────────
# Status Check
# ─────────────────────────────────────────────────────────────

def check_keys() -> dict:
    """Print API key status and return dict."""
    keys = {
        "VirusTotal":     bool(VIRUSTOTAL_API_KEY),
        "IPInfo":         bool(IPINFO_API_KEY),
        "AbuseIPDB":      bool(ABUSEIPDB_API_KEY),
        "AlienVault OTX": bool(ALIENVAULT_API_KEY),
        "SecurityTrails": bool(SECURITYTRAILS_KEY),
        "GreyNoise":      bool(GREYNOISE_API_KEY),
        "Shodan":         bool(SHODAN_API_KEY),
        "HIBP (paid)":    bool(HIBP_API_KEY),
    }
    print("\n  ┌─────────────────────────────────────────────────────────┐")
    print("  │                   API Key Status                        │")
    print("  ├─────────────────────────────────────────────────────────┤")
    for name, ok in keys.items():
        icon = "🟢" if ok else "🔴"
        st   = "Active  → Real results" if ok else "Not set → Simulation"
        print(f"  │  {icon}  {name:<18} {st:<28}│")
    print("  └─────────────────────────────────────────────────────────┘")
    configured = sum(keys.values())
    total      = len(keys)
    pct        = round((configured / total) * 100)
    print(f"\n  Keys configured: {configured}/{total} ({pct}%)")
    if ADMIN_PASSWORD == "admin123":
        print("  ⚠️  WARNING: Using default admin password!")
    print()
    return keys


def key(name: str) -> bool:
    """Return True if a named API key is configured."""
    return bool(globals().get(name, ""))
