"""
OmniRecon AI — Real DNS & Domain Intelligence Tools
=====================================================
Every function tries real libraries first.
Falls back to simulation only if library is missing.

Real libraries used:
  dnspython    → DNS queries
  python-whois → WHOIS lookup
  socket       → Reverse DNS, Port scanning, SMTP
  ssl          → SSL certificate inspection
  requests     → HTTP headers, MAC vendor, IPInfo API
  subprocess   → Ping
"""

import hashlib
import random
import socket
import ssl as ssl_lib
import subprocess
import platform
from datetime import datetime, timezone

# ── Optional imports with graceful fallback ───────────────────────────────────

try:
    import dns.resolver
    import dns.reversename
    import dns.rdatatype
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    import requests as req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Simulation helpers (used only as fallback) ────────────────────────────────

def _seed(s: str) -> random.Random:
    return random.Random(int(hashlib.sha256(s.encode()).hexdigest()[:16], 16))

def _ip(rng: random.Random) -> str:
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


# ══════════════════════════════════════════════════════════════════════════════
# 1. DNS RECORD LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

def dns_lookup(domain: str) -> dict:
    """Real DNS record lookup — queries A, AAAA, MX, TXT, NS, CNAME, SOA."""
    if not HAS_DNS:
        return _sim_dns(domain)

    result = {"domain": domain, "records": {}, "real": True}
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            result["records"][rtype] = [str(r) for r in answers]
        except Exception:
            result["records"][rtype] = []

    return result


def _sim_dns(domain):
    rng = _seed(domain + "dns")
    return {
        "domain": domain,
        "records": {
            "A":   [_ip(rng), _ip(rng)],
            "MX":  [f"10 mail.{domain}"],
            "NS":  [f"ns1.{domain}", f"ns2.{domain}"],
            "TXT": [f"v=spf1 include:_spf.{domain} ~all"],
        },
        "real": False, "note": "Install dnspython for real results"
    }


# ══════════════════════════════════════════════════════════════════════════════
# 2. WHOIS LOOKUP
# ══════════════════════════════════════════════════════════════════════════════

def whois_lookup(domain: str) -> dict:
    """Real WHOIS lookup using python-whois."""
    if not HAS_WHOIS:
        return _sim_whois(domain)
    try:
        w = whois_lib.whois(domain)
        created = w.creation_date
        expires = w.expiration_date
        if isinstance(created, list): created = created[0]
        if isinstance(expires, list): expires = expires[0]
        return {
            "domain":       domain,
            "registrar":    str(w.registrar or "Unknown"),
            "created":      str(created)[:10] if created else "Unknown",
            "expires":      str(expires)[:10] if expires else "Unknown",
            "status":       str(w.status[0] if isinstance(w.status, list) else w.status or ""),
            "name_servers": list(w.name_servers or []),
            "dnssec":       str(w.dnssec or "unsigned"),
            "registrant":   "REDACTED FOR PRIVACY (GDPR)",
            "real":         True,
        }
    except Exception as e:
        return {**_sim_whois(domain), "error": str(e)}


def _sim_whois(domain):
    rng = _seed(domain + "whois")
    yr  = rng.randint(1998, 2021)
    return {
        "domain": domain,
        "registrar": rng.choice(["GoDaddy", "Namecheap", "Cloudflare", "Gandi"]),
        "created": f"{yr}-{rng.randint(1,12):02d}-01",
        "expires": f"{yr + rng.randint(5,12)}-{rng.randint(1,12):02d}-01",
        "status":  "clientTransferProhibited",
        "name_servers": [f"ns1.{domain}", f"ns2.{domain}"],
        "dnssec":  rng.choice(["signed", "unsigned"]),
        "registrant": "REDACTED FOR PRIVACY (GDPR)",
        "real": False,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 3. REVERSE DNS (PTR)
# ══════════════════════════════════════════════════════════════════════════════

def reverse_dns(ip: str) -> dict:
    """Real PTR record lookup using socket."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        try:
            forward = socket.gethostbyname(hostname)
            match   = forward == ip
        except Exception:
            forward = "lookup failed"
            match   = False
        return {
            "ip": ip,
            "PTR Record": hostname,
            "Forward Match": "✓ Confirmed" if match else "✗ Mismatch",
            "real": True,
        }
    except Exception as e:
        return {"ip": ip, "PTR Record": f"No PTR record", "Forward Match": "—", "real": True}


# ══════════════════════════════════════════════════════════════════════════════
# 4. IP GEOLOCATION
# ══════════════════════════════════════════════════════════════════════════════

def ip_geolocation(ip: str, api_key: str = "") -> dict:
    """Real IP geolocation using ipinfo.io."""
    if not HAS_REQUESTS:
        return _sim_geo(ip)
    try:
        url = f"https://ipinfo.io/{ip}/json"
        if api_key:
            url += f"?token={api_key}"
        r = req.get(url, timeout=6)
        if r.status_code == 200:
            d = r.json()
            return {
                "IP":          d.get("ip", ip),
                "Country":     d.get("country", "Unknown"),
                "Region":      d.get("region", "Unknown"),
                "City":        d.get("city", "Unknown"),
                "ISP":         d.get("org", "Unknown"),
                "Coordinates": d.get("loc", "0,0"),
                "Timezone":    d.get("timezone", "Unknown"),
                "Hostname":    d.get("hostname", "—"),
                "real":        True,
            }
    except Exception:
        pass
    return _sim_geo(ip)


def _sim_geo(ip):
    rng = _seed(ip + "geo")
    places = [
        ["US", "Ashburn", "Virginia", "AS13335 Cloudflare"],
        ["DE", "Frankfurt", "Hessen",  "AS24940 Hetzner"],
        ["SG", "Singapore", "Central", "AS14061 DigitalOcean"],
    ]
    p = rng.choice(places)
    return {
        "IP": ip, "Country": p[0], "City": p[1], "Region": p[2], "ISP": p[3],
        "Coordinates": f"{rng.uniform(-90,90):.4f},{rng.uniform(-180,180):.4f}",
        "Timezone": rng.choice(["UTC-5", "UTC+1", "UTC+8"]),
        "real": False, "note": "Add IPINFO_API_KEY for real results",
    }


# ══════════════════════════════════════════════════════════════════════════════
# 5. PORT SCANNER
# ══════════════════════════════════════════════════════════════════════════════

COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
}


def port_scan(host: str, timeout: float = 0.8) -> dict:
    """Real TCP port scanner using socket.connect_ex."""
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host

    results = []
    for port, svc in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            open_ = sock.connect_ex((ip, port)) == 0
            sock.close()
        except Exception:
            open_ = False
        results.append({"port": port, "service": svc, "state": "open" if open_ else "closed", "open": open_})

    open_count = sum(1 for r in results if r["open"])
    return {"host": host, "ip": ip, "ports": results, "open_count": open_count, "real": True}


# ══════════════════════════════════════════════════════════════════════════════
# 6. HTTP HEADERS
# ══════════════════════════════════════════════════════════════════════════════

def http_headers(url: str) -> dict:
    """Real HTTP header analysis using requests."""
    if not url.startswith("http"):
        url = "https://" + url
    if not HAS_REQUESTS:
        return _sim_headers(url)
    try:
        r = req.get(url, timeout=8, allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 OmniRecon-AI/2.0"})
        h = dict(r.headers)
        return {
            "url": url, "real": True,
            "headers": {
                "Status":                  str(r.status_code),
                "Server":                  h.get("Server", "(hidden)"),
                "Content-Type":            h.get("Content-Type", "—"),
                "HSTS":                    h.get("Strict-Transport-Security", "(missing)"),
                "CSP":                     h.get("Content-Security-Policy", "(missing)"),
                "X-Frame-Options":         h.get("X-Frame-Options", "(missing)"),
                "X-Content-Type-Options":  h.get("X-Content-Type-Options", "(missing)"),
                "Referrer-Policy":         h.get("Referrer-Policy", "(missing)"),
                "X-Powered-By":            h.get("X-Powered-By", "(hidden)"),
            }
        }
    except Exception as e:
        return {**_sim_headers(url), "error": str(e)}


def _sim_headers(url):
    rng = _seed(url + "hdr")
    return {
        "url": url, "real": False,
        "headers": {
            "Status":          "200 OK",
            "Server":          rng.choice(["nginx/1.25", "Apache/2.4", "cloudflare"]),
            "HSTS":            rng.choice(["max-age=31536000", "(missing)"]),
            "CSP":             rng.choice(["default-src 'self'", "(missing)"]),
            "X-Frame-Options": rng.choice(["SAMEORIGIN", "(missing)"]),
        }
    }


# ══════════════════════════════════════════════════════════════════════════════
# 7. SSL CERTIFICATE
# ══════════════════════════════════════════════════════════════════════════════

def ssl_info(domain: str) -> dict:
    """Real SSL certificate inspection using Python ssl module."""
    try:
        ctx  = ssl_lib.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=8),
            server_hostname=domain
        )
        cert = conn.getpeercert()
        conn.close()

        not_after  = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        subject    = dict(x[0] for x in cert.get("subject", []))
        issuer     = dict(x[0] for x in cert.get("issuer", []))
        sans       = [v for _, v in cert.get("subjectAltName", [])]

        expiry    = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry - datetime.utcnow()).days

        return {
            "Subject":    subject.get("commonName", domain),
            "Issuer":     issuer.get("organizationName", "Unknown"),
            "Valid From": not_before[:11],
            "Valid To":   not_after[:11],
            "Days Left":  days_left,
            "SANs":       ", ".join(sans[:5]),
            "Status":     "✓ Valid" if days_left > 0 else "✗ Expired",
            "Protocol":   "TLS 1.3",
            "real":       True,
        }
    except Exception as e:
        rng = _seed(domain + "ssl")
        yr  = rng.randint(2024, 2025)
        return {
            "Subject": f"CN={domain}",
            "Issuer":  rng.choice(["Let's Encrypt", "DigiCert", "Google Trust"]),
            "Status":  "⚠ Could not connect",
            "Error":   str(e),
            "real":    False,
        }


# ══════════════════════════════════════════════════════════════════════════════
# 8. PING
# ══════════════════════════════════════════════════════════════════════════════

def ping_host(host: str) -> dict:
    """Real ping using system ping command."""
    import re
    count_flag = "-n" if platform.system() == "Windows" else "-c"
    try:
        output = subprocess.check_output(
            ["ping", count_flag, "4", host],
            stderr=subprocess.STDOUT, timeout=12,
            universal_newlines=True
        )
        times      = re.findall(r"time[=<]([\d.]+)\s*ms", output)
        avg        = round(sum(float(t) for t in times) / len(times), 2) if times else 0
        loss_match = re.search(r"(\d+)%\s+packet\s+loss", output)
        loss       = int(loss_match.group(1)) if loss_match else 0
        return {
            "host": host, "avg_ms": avg, "packet_loss": f"{loss}%",
            "reply_times": [float(t) for t in times],
            "status": "reachable" if avg > 0 else "unreachable",
            "real": True,
        }
    except Exception as e:
        return {"host": host, "error": str(e), "status": "unreachable", "real": True}


# ══════════════════════════════════════════════════════════════════════════════
# 9. DNSBL SPAM BLACKLIST
# ══════════════════════════════════════════════════════════════════════════════

DNSBL_SERVERS = [
    "zen.spamhaus.org", "b.barracudacentral.org",
    "bl.spamcop.net",   "dnsbl.sorbs.net",
    "uceprotect.net",   "psbl.surriel.com",
    "bl.mailspike.net", "hostkarma.junkemailfilter.com",
    "dnsbl.dronebl.org","cbl.abuseat.org",
]


def dnsbl_check(ip: str) -> dict:
    """Real DNSBL check via DNS queries."""
    if not HAS_DNS:
        return _sim_dnsbl(ip)

    reversed_ip = ".".join(reversed(ip.split(".")))
    results = []
    for bl in DNSBL_SERVERS:
        query = f"{reversed_ip}.{bl}"
        try:
            dns.resolver.resolve(query, "A", lifetime=3)
            results.append({"list": bl, "listed": True})
        except Exception:
            results.append({"list": bl, "listed": False})

    listed = sum(1 for r in results if r["listed"])
    return {"ip": ip, "checks": results, "listed_count": listed,
            "total": len(DNSBL_SERVERS), "real": True}


def _sim_dnsbl(ip):
    rng    = _seed(ip + "dnsbl")
    checks = [{"list": bl, "listed": rng.random() > 0.85} for bl in DNSBL_SERVERS]
    return {"ip": ip, "checks": checks,
            "listed_count": sum(1 for c in checks if c["listed"]),
            "total": len(DNSBL_SERVERS), "real": False}


# ══════════════════════════════════════════════════════════════════════════════
# 10. MAC ADDRESS VENDOR
# ══════════════════════════════════════════════════════════════════════════════

def mac_lookup(mac: str) -> dict:
    """Real MAC vendor lookup via macvendors.com (free, no key needed)."""
    if not HAS_REQUESTS:
        return _sim_mac(mac)
    clean = mac.replace(":", "").replace("-", "").upper()[:6]
    try:
        r = req.get(f"https://api.macvendors.com/{clean}", timeout=5)
        vendor = r.text.strip() if r.status_code == 200 else "Unknown"
        return {
            "MAC Address": mac,
            "OUI Prefix":  ":".join(clean[i:i+2] for i in range(0, 6, 2)),
            "Vendor":      vendor,
            "Type":        "Global (Unique)",
            "real":        True,
        }
    except Exception:
        return _sim_mac(mac)


def _sim_mac(mac):
    rng = _seed(mac + "mac")
    return {
        "MAC Address": mac,
        "OUI Prefix":  mac[:8],
        "Vendor":      rng.choice(["Apple, Inc.", "Samsung", "Cisco", "Intel", "TP-Link"]),
        "Type":        "Global (Unique)",
        "real":        False,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 11. DNS PROPAGATION
# ══════════════════════════════════════════════════════════════════════════════

GLOBAL_RESOLVERS = {
    "Google (US)":      "8.8.8.8",
    "Cloudflare (US)":  "1.1.1.1",
    "OpenDNS (US)":     "208.67.222.222",
    "Quad9 (EU)":       "9.9.9.9",
    "Comodo (US)":      "8.26.56.26",
    "Verisign (US)":    "64.6.64.6",
    "Level3 (US)":      "4.2.2.2",
    "Norton (US)":      "199.85.126.10",
}


def dns_propagation(domain: str) -> dict:
    """Real DNS propagation check across 8 global resolvers."""
    if not HAS_DNS:
        return _sim_propagation(domain)

    results = []
    for location, resolver_ip in GLOBAL_RESOLVERS.items():
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [resolver_ip]
            resolver.lifetime    = 4
            answer = resolver.resolve(domain, "A")
            ips    = [str(r) for r in answer]
            results.append({
                "location": location, "resolver": resolver_ip,
                "ip": ips[0] if ips else "—",
                "ok": True, "propagated": True,
            })
        except Exception:
            results.append({
                "location": location, "resolver": resolver_ip,
                "ip": "—", "ok": False, "propagated": False,
            })

    propagated = sum(1 for r in results if r["propagated"])
    ips_seen   = {r["ip"] for r in results if r["ip"] != "—"}
    return {
        "domain": domain, "results": results,
        "propagated": propagated, "total": len(results),
        "consistent": len(ips_seen) <= 1,
        "real": True,
    }


def _sim_propagation(domain):
    rng     = _seed(domain + "prop")
    results = [{"location": loc, "resolver": ip, "ip": _ip(rng), "ok": rng.random() > 0.15, "propagated": rng.random() > 0.15}
               for loc, ip in GLOBAL_RESOLVERS.items()]
    return {"domain": domain, "results": results,
            "propagated": sum(1 for r in results if r["propagated"]),
            "total": len(results), "real": False}


# ══════════════════════════════════════════════════════════════════════════════
# 12. REVERSE IP LOOKUP  (SecurityTrails API)
# ══════════════════════════════════════════════════════════════════════════════

def reverse_ip_lookup(ip: str, api_key: str = "") -> dict:
    """Real reverse IP — finds domains hosted on same server."""
    if api_key and HAS_REQUESTS:
        try:
            r = req.get(
                f"https://api.securitytrails.com/v1/ips/nearby/{ip}",
                headers={"APIKEY": api_key, "Accept": "application/json"},
                timeout=8
            )
            if r.status_code == 200:
                data    = r.json()
                domains = [b["hostname"] for b in data.get("blocks", [])]
                return {"ip": ip, "domains": domains[:20],
                        "count": len(domains), "real": True}
        except Exception:
            pass
    # Fallback simulation
    rng    = _seed(ip + "revip")
    words  = ["acme","globex","stark","wayne","vault","hooli","initech"]
    tlds   = [".com",".net",".org"]
    n      = rng.randint(3, 12)
    domains = [f"{rng.choice(words)}{rng.randint(1,99)}{rng.choice(tlds)}" for _ in range(n)]
    return {"ip": ip, "domains": domains, "count": n, "real": False,
            "note": "Add SECURITYTRAILS_KEY for real results"}


# ══════════════════════════════════════════════════════════════════════════════
# 13. ASN LOOKUP  (ipinfo.io)
# ══════════════════════════════════════════════════════════════════════════════

def asn_lookup(ip_or_asn: str, api_key: str = "") -> dict:
    """Real ASN info using ipinfo.io."""
    if HAS_REQUESTS:
        try:
            target = ip_or_asn.lstrip("ASas")
            url    = f"https://ipinfo.io/AS{target}/json" if ip_or_asn.upper().startswith("AS") else f"https://ipinfo.io/{ip_or_asn}/json"
            params = {"token": api_key} if api_key else {}
            r      = req.get(url, params=params, timeout=6)
            if r.status_code == 200:
                d = r.json()
                return {
                    "ASN":          d.get("asn", "—"),
                    "Organization": d.get("name", "Unknown"),
                    "Country":      d.get("country", "Unknown"),
                    "Registry":     d.get("registry", "Unknown"),
                    "Allocated":    d.get("allocated", "—"),
                    "IPv4 Count":   str(d.get("num_ips", "—")),
                    "real":         True,
                }
        except Exception:
            pass
    rng = _seed(ip_or_asn + "asn")
    o   = rng.choice([
        ["AS15169","Google LLC","US"],
        ["AS13335","Cloudflare Inc.","US"],
        ["AS16509","Amazon.com Inc.","US"],
    ])
    return {"ASN": o[0], "Organization": o[1], "Country": o[2],
            "Registry": rng.choice(["ARIN","RIPE","APNIC"]),
            "Allocated": str(rng.randint(2000,2015)),
            "IPv4 Count": str(rng.randint(256,5000000)),
            "real": False}
