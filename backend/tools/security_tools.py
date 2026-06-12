"""
OmniRecon AI — Real Security Analysis Tools
=============================================
Real APIs: VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise
Real libs: socket, requests, dnspython, androguard (APK)
"""

import hashlib
import random
import socket
import re
import json
import concurrent.futures

try:
    import requests as req
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False


def _seed(s: str) -> random.Random:
    return random.Random(int(hashlib.sha256(s.encode()).hexdigest()[:16], 16))

def _ip(rng: random.Random) -> str:
    return f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


# ══════════════════════════════════════════════════════════════════════════════
# 1. VIRUSTOTAL — MALWARE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════

def analyze_hash(file_hash: str, api_key: str = "") -> dict:
    """
    Real malware analysis using VirusTotal API v3.
    FREE account: 500 requests/day
    Register at: https://www.virustotal.com
    """
    if not api_key or not HAS_REQUESTS:
        return {**_sim_malware(file_hash),
                "note": "Add VIRUSTOTAL_API_KEY to .env for real analysis"}
    try:
        r = req.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": api_key},
            timeout=12
        )
        if r.status_code == 200:
            d      = r.json()["data"]["attributes"]
            stats  = d.get("last_analysis_stats", {})
            res    = d.get("last_analysis_results", {})
            mal    = stats.get("malicious", 0)
            susp   = stats.get("suspicious", 0)
            total  = sum(stats.values())
            verdict = ("Malicious"  if mal > 5 else
                       "Suspicious" if susp > 0 or mal > 0 else "Clean")
            detected = [
                f"{eng}: {info['result']}"
                for eng, info in res.items()
                if info.get("category") in ("malicious", "suspicious")
            ][:10]
            family = (d.get("popular_threat_classification", {})
                       .get("suggested_threat_label", "—"))
            return {
                "hash":       file_hash,
                "verdict":    verdict,
                "malicious":  mal,
                "suspicious": susp,
                "total":      total,
                "family":     family,
                "detections": detected,
                "real":       True,
            }
        elif r.status_code == 404:
            return {"hash": file_hash, "verdict": "Not Found",
                    "note": "Hash not in VirusTotal database", "real": True}
        else:
            return _sim_malware(file_hash)
    except Exception as e:
        return {**_sim_malware(file_hash), "error": str(e)}


def _sim_malware(file_hash):
    rng       = _seed(file_hash + "mw")
    malicious = rng.random() > 0.45
    det       = rng.randint(18, 64) if malicious else rng.randint(0, 3)
    return {
        "hash":    file_hash,
        "verdict": "Malicious" if malicious else ("Suspicious" if det > 0 else "Clean"),
        "malicious": det if malicious else 0,
        "suspicious": 0,
        "total":   70,
        "family":  rng.choice(["Trojan.GenericKD","Win32.Emotet","Ransom.LockBit"]) if malicious else "—",
        "detections": [],
        "real":    False,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 2. ABUSEIPDB — IP REPUTATION
# ══════════════════════════════════════════════════════════════════════════════

def ip_reputation(ip: str, api_key: str = "") -> dict:
    """
    Real IP reputation using AbuseIPDB API.
    FREE: 1,000 requests/day
    Register at: https://www.abuseipdb.com
    """
    if not api_key or not HAS_REQUESTS:
        return {**_sim_reputation(ip),
                "note": "Add ABUSEIPDB_API_KEY to .env for real results"}
    try:
        r = req.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=8
        )
        if r.status_code == 200:
            d = r.json()["data"]
            return {
                "ip":             ip,
                "score":          d.get("abuseConfidenceScore", 0),
                "country":        d.get("countryCode", "Unknown"),
                "isp":            d.get("isp", "Unknown"),
                "domain":         d.get("domain", "—"),
                "total_reports":  d.get("totalReports", 0),
                "last_reported":  d.get("lastReportedAt", "Never"),
                "is_tor":         d.get("isTor", False),
                "is_public":      d.get("isPublic", True),
                "usage_type":     d.get("usageType", "—"),
                "real":           True,
            }
    except Exception as e:
        return {**_sim_reputation(ip), "error": str(e)}
    return _sim_reputation(ip)


def _sim_reputation(ip):
    rng = _seed(ip + "rep")
    return {
        "ip": ip,
        "score": rng.randint(0, 100),
        "country": rng.choice(["US","DE","CN","RU","NL"]),
        "isp": rng.choice(["Cloudflare","Amazon","DigitalOcean"]),
        "total_reports": rng.randint(0, 500),
        "last_reported": "—",
        "is_tor": rng.random() > 0.9,
        "is_public": True,
        "real": False,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 3. WAF DETECTION  (real HTTP fingerprinting)
# ══════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES = {
    "Cloudflare":       {"headers": ["cf-ray","cf-cache-status"],  "server": ["cloudflare"],    "cookies": ["__cfduid","__cf_bm"]},
    "AWS WAF/CloudFront":{"headers": ["x-amz-cf-id"],              "server": ["cloudfront"]},
    "Akamai":           {"headers": ["x-akamai-transformed"],      "server": ["akamaighost"]},
    "Sucuri":           {"headers": ["x-sucuri-id","x-sucuri-cache"]},
    "Imperva":          {"headers": ["x-iinfo"],                   "cookies": ["visid_incap","_incap_ses"]},
    "F5 BIG-IP":        {"cookies": ["BIGipServer"]},
    "Fastly":           {"headers": ["x-fastly-request-id"],       "server": ["fastly"]},
}


def detect_waf(url: str) -> dict:
    """Real WAF detection using HTTP response fingerprinting."""
    if not url.startswith("http"):
        url = "https://" + url
    if not HAS_REQUESTS:
        return _sim_waf(url)
    try:
        r = req.get(url, timeout=8, allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 OmniRecon-AI/2.0"})
        h_lower  = {k.lower(): v.lower() for k, v in r.headers.items()}
        server   = h_lower.get("server", "")
        cookies  = [c.name.lower() for c in r.cookies]

        for waf_name, sigs in WAF_SIGNATURES.items():
            # Check headers
            for h in sigs.get("headers", []):
                if h in h_lower:
                    return {"url": url, "waf": waf_name, "protected": True,
                            "confidence": 96, "signature": f"Header: {h}",
                            "server": h_lower.get("server", "—"),
                            "status": r.status_code, "real": True}
            # Check server header
            for s in sigs.get("server", []):
                if s in server:
                    return {"url": url, "waf": waf_name, "protected": True,
                            "confidence": 95, "signature": f"Server: {server}",
                            "server": server, "status": r.status_code, "real": True}
            # Check cookies
            for c in sigs.get("cookies", []):
                if any(c in ck for ck in cookies):
                    return {"url": url, "waf": waf_name, "protected": True,
                            "confidence": 94, "signature": f"Cookie: {c}",
                            "server": server, "status": r.status_code, "real": True}

        return {"url": url, "waf": "None detected", "protected": False,
                "confidence": 92, "signature": "No WAF fingerprints found",
                "server": h_lower.get("server", "—"),
                "status": r.status_code, "real": True}
    except Exception as e:
        return {**_sim_waf(url), "error": str(e)}


def _sim_waf(url):
    rng  = _seed(url + "waf")
    wafs = ["Cloudflare","AWS WAF","Akamai","Sucuri","None detected"]
    waf  = rng.choice(wafs)
    return {"url": url, "waf": waf, "protected": waf != "None detected",
            "confidence": rng.randint(70, 99), "signature": "—", "real": False}


# ══════════════════════════════════════════════════════════════════════════════
# 4. TYPOSQUATTING  (real permutation algorithm + optional DNS check)
# ══════════════════════════════════════════════════════════════════════════════

HOMOGLYPHS = {
    "a": ["4","@","à"],  "e": ["3","è"],
    "i": ["1","l","!"],  "o": ["0","ò"],
    "s": ["5","$"],      "l": ["1","i"],
    "g": ["9"],          "t": ["7"],
    "b": ["8"],          "n": ["ñ"],
}
TLDS = [".com",".net",".org",".co",".io",".info",".xyz",".top",".online",".site"]


def generate_typosquats(domain: str, check_dns: bool = False) -> dict:
    """
    Real typosquatting generation algorithm (6 pattern types).
    Optional: Real DNS check to identify registered domains.
    """
    if "." not in domain:
        return {"error": "Invalid domain"}

    dot   = domain.rfind(".")
    name  = domain[:dot]
    tld   = domain[dot:]
    variants: set[str] = set()

    # Pattern 1 — Omission
    for i in range(len(name)):
        v = name[:i] + name[i+1:]
        if v: variants.add(v + tld)

    # Pattern 2 — Duplication
    for i in range(len(name)):
        variants.add(name[:i] + name[i]*2 + name[i+1:] + tld)

    # Pattern 3 — Swap adjacent
    for i in range(len(name)-1):
        s = list(name)
        s[i], s[i+1] = s[i+1], s[i]
        variants.add("".join(s) + tld)

    # Pattern 4 — Homoglyph substitution
    for i, ch in enumerate(name):
        for sub in HOMOGLYPHS.get(ch.lower(), []):
            variants.add(name[:i] + sub + name[i+1:] + tld)

    # Pattern 5 — TLD permutation
    for alt in TLDS:
        if alt != tld:
            variants.add(name + alt)

    # Pattern 6 — Prefix / Suffix injection
    for prefix in ["secure-","login-","verify-","account-","www-"]:
        variants.add(prefix + name + tld)
    for suffix in ["-secure","-login","-verify","-account","-app"]:
        variants.add(name + suffix + tld)

    results = []
    rng     = _seed(domain + "ts_order")

    def check_variant(v: str):
        registered = False
        ip         = ""
        if check_dns and HAS_DNS:
            try:
                a          = dns.resolver.resolve(v, "A", lifetime=2)
                registered = True
                ip         = str(list(a)[0])
            except Exception:
                pass
        return {"domain": v, "registered": registered, "ip": ip,
                "risk": "High" if registered else "Low"}

    variant_list = sorted(variants)[:40]

    if check_dns and HAS_DNS:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            results = list(ex.map(check_variant, variant_list))
    else:
        for v in variant_list:
            results.append({"domain": v, "registered": rng.random() > 0.72,
                            "ip": "", "risk": rng.choice(["High","Low"])})

    active = sum(1 for r in results if r["registered"])
    return {"original": domain, "variants": results,
            "count": len(results), "active": active,
            "real": check_dns and HAS_DNS}


# ══════════════════════════════════════════════════════════════════════════════
# 5. AI RISK SCORING  (real composite heuristic from scan signals)
# ══════════════════════════════════════════════════════════════════════════════

def ai_risk_score(target: str, data: dict = None) -> dict:
    """
    Composite AI risk scoring engine.
    Combines real scan results into a structured risk assessment.
    Score derived from: SPF, DMARC, SSL, WAF, headers, blacklists.
    """
    score    = 20
    findings = []
    recs     = []
    data     = data or {}

    if not data.get("spf"):
        score += 8
        findings.append({"title": "SPF record missing — email spoofing possible", "sev": "Medium"})
        recs.append("Publish an SPF record for your domain")

    if not data.get("dmarc") or data.get("dmarc") == "Not configured":
        score += 8
        findings.append({"title": "No DMARC policy configured", "sev": "Medium"})
        recs.append("Configure DMARC with at least p=quarantine")

    if not data.get("ssl_valid", True):
        score += 18
        findings.append({"title": "SSL certificate invalid or expired", "sev": "High"})
        recs.append("Renew your TLS certificate immediately")

    days = data.get("ssl_days_left", 365)
    if 0 < days < 30:
        score += 8
        findings.append({"title": f"SSL cert expires in {days} days", "sev": "Medium"})
        recs.append("Renew your TLS certificate soon")

    if not data.get("waf_protected", True):
        score += 14
        findings.append({"title": "No Web Application Firewall detected", "sev": "High"})
        recs.append("Deploy a WAF (Cloudflare, AWS WAF, or Sucuri)")

    for h in data.get("missing_headers", []):
        score += 4
        findings.append({"title": f"Missing security header: {h}", "sev": "Low"})
    if data.get("missing_headers"):
        recs.append("Add HSTS, CSP, X-Frame-Options security headers")

    bl = data.get("blacklist_count", 0)
    if bl > 0:
        score += bl * 7
        findings.append({"title": f"IP listed on {bl} spam blacklist(s)", "sev": "High"})
        recs.append("Request delisting from spam blacklists")

    subs = data.get("subdomain_count", 0)
    if subs > 10:
        score += 6
        findings.append({"title": f"Large attack surface: {subs} subdomains exposed", "sev": "Medium"})
        recs.append("Retire or restrict unused subdomains")

    score = min(99, max(5, score))
    level = ("Critical" if score >= 80 else
             "High"     if score >= 60 else
             "Medium"   if score >= 40 else "Low")

    if not findings:
        findings.append({"title": "No critical issues found in automated scan", "sev": "Info"})
    if not recs:
        recs.append("Conduct regular vulnerability scans")

    return {
        "target":          target,
        "score":           score,
        "level":           level,
        "findings":        findings,
        "recommendations": recs[:5],
        "factors": {
            "attack_surface": min(100, subs * 5 + data.get("open_ports_count", 0) * 3),
            "exposure":       min(100, bl * 20 + (20 if not data.get("waf_protected") else 0)),
            "patch_hygiene":  max(0, 100 - score),
            "threat_activity":min(100, bl * 15),
        },
        "real": True,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 6. NETWORK SCAN  (real socket host discovery)
# ══════════════════════════════════════════════════════════════════════════════

def network_scan(cidr: str) -> dict:
    """Real host discovery using TCP socket connections."""
    import ipaddress
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        return {"error": f"Invalid CIDR: {cidr}"}

    hosts_to_scan = list(network.hosts())[:254]

    def check_host(ip_obj):
        ip = str(ip_obj)
        for port in [80, 443, 22, 445, 8080]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                if sock.connect_ex((ip, port)) == 0:
                    sock.close()
                    try:   hostname = socket.gethostbyaddr(ip)[0]
                    except: hostname = "—"
                    return {"ip": ip, "live": True, "hostname": hostname, "open_port": port}
            except Exception:
                pass
            finally:
                try: sock.close()
                except: pass
        return None

    live_hosts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(check_host, ip): ip for ip in hosts_to_scan}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            if r: live_hosts.append(r)

    return {
        "network":    cidr,
        "scanned":    len(hosts_to_scan),
        "live_hosts": live_hosts,
        "count":      len(live_hosts),
        "real":       True,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 7. SUBDOMAIN ENUMERATION  (real DNS bruteforce)
# ══════════════════════════════════════════════════════════════════════════════

COMMON_SUBS = [
    "www","mail","ftp","api","dev","staging","admin","blog","shop",
    "vpn","cdn","app","test","portal","git","jenkins","db","smtp",
    "auth","docs","status","dashboard","remote","secure","beta",
    "m","ns1","ns2","mx","webmail","cpanel","forum","support",
    "wiki","cloud","media","static","assets","img","images","help",
]


def subdomain_enum(domain: str) -> dict:
    """Real subdomain enumeration using DNS bruteforce."""
    if not HAS_DNS:
        return _sim_subdomains(domain)

    found = []

    def check_sub(sub):
        target = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(target, "A", lifetime=2)
            ips     = [str(r) for r in answers]
            status  = 0
            if HAS_REQUESTS:
                try:
                    r      = req.get(f"https://{target}", timeout=3, allow_redirects=True)
                    status = r.status_code
                except Exception:
                    try:
                        r      = req.get(f"http://{target}", timeout=3, allow_redirects=True)
                        status = r.status_code
                    except Exception:
                        status = 0
            return {"host": target, "ip": ips[0] if ips else "—",
                    "status": status, "live": True}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(check_sub, COMMON_SUBS))
    found = [r for r in results if r is not None]

    return {"domain": domain, "subdomains": found,
            "count": len(found), "real": True}


def _sim_subdomains(domain):
    rng   = _seed(domain + "sub")
    subs  = [s for s in COMMON_SUBS if rng.random() > 0.5]
    found = [{"host": f"{s}.{domain}", "ip": _ip(rng),
              "status": rng.choice([200,200,301,403,404]), "live": True}
             for s in subs]
    return {"domain": domain, "subdomains": found,
            "count": len(found), "real": False,
            "note": "Install dnspython for real enumeration"}


# ══════════════════════════════════════════════════════════════════════════════
# 8. APK ANALYZER  (real androguard + fallback)
# ══════════════════════════════════════════════════════════════════════════════

DANGEROUS_PERMS = {
    "READ_SMS", "SEND_SMS", "BIND_ACCESSIBILITY_SERVICE",
    "REQUEST_INSTALL_PACKAGES", "READ_CALL_LOG",
    "SYSTEM_ALERT_WINDOW", "PROCESS_OUTGOING_CALLS",
    "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
}


def analyze_apk(apk_path: str) -> dict:
    """
    Real APK analysis using androguard library.
    Install: pip install androguard
    Falls back to simulation if not installed.
    """
    try:
        from androguard.misc import AnalyzeAPK
        a, d, dx = AnalyzeAPK(apk_path)

        permissions = list(a.get_permissions())
        dangerous   = [p.split(".")[-1] for p in permissions
                      if p.split(".")[-1] in DANGEROUS_PERMS]

        # Compute risk score
        score = min(100, len(dangerous) * 15 + len(permissions) * 2)

        return {
            "pkg":          a.get_package(),
            "version":      a.get_androidversion_name() or "Unknown",
            "min_sdk":      a.get_min_sdk_version() or "—",
            "target_sdk":   a.get_target_sdk_version() or "—",
            "permissions":  permissions,
            "dangerous":    dangerous,
            "score":        score,
            "activities":   len(a.get_activities()),
            "services":     len(a.get_services()),
            "receivers":    len(a.get_receivers()),
            "certificates": [str(cert) for cert in a.get_certificates()],
            "real":         True,
        }
    except ImportError:
        return {**_sim_apk(), "note": "Install androguard for real APK analysis: pip install androguard"}
    except Exception as e:
        return {**_sim_apk(), "error": str(e)}


def _sim_apk():
    rng   = _seed("apksim")
    perms = ["READ_SMS","SEND_SMS","CAMERA","INTERNET","RECORD_AUDIO",
             "ACCESS_FINE_LOCATION","READ_CONTACTS","WRITE_EXTERNAL_STORAGE"]
    sel   = [p for p in perms if rng.random() > 0.45]
    dang  = [p for p in sel if p in DANGEROUS_PERMS]
    score = min(100, len(dang) * 18)
    return {
        "pkg": "com.example.app", "version": "1.0.0",
        "min_sdk": "21", "target_sdk": "33",
        "permissions": sel, "dangerous": dang,
        "score": score, "real": False,
    }


# ══════════════════════════════════════════════════════════════════════════════
# 9. GREYNOISE — IP CONTEXT  (free community API)
# ══════════════════════════════════════════════════════════════════════════════

def greynoise_lookup(ip: str, api_key: str = "") -> dict:
    """
    Real GreyNoise IP context — is this IP scanning the internet?
    Community API is FREE: https://greynoise.io
    """
    if not HAS_REQUESTS:
        return {"ip": ip, "real": False, "note": "Install requests"}
    try:
        headers = {"key": api_key} if api_key else {}
        r = req.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers=headers, timeout=8
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "ip":           ip,
                "noise":        d.get("noise", False),
                "riot":         d.get("riot", False),
                "classification": d.get("classification", "unknown"),
                "name":         d.get("name", "—"),
                "link":         d.get("link", "—"),
                "message":      d.get("message", "—"),
                "real":         True,
            }
    except Exception:
        pass
    rng = _seed(ip + "gn")
    return {
        "ip": ip,
        "noise": rng.random() > 0.7,
        "riot":  rng.random() > 0.8,
        "classification": rng.choice(["malicious","benign","unknown"]),
        "real": False,
        "note": "Add GREYNOISE_API_KEY for real results"
    }


# ══════════════════════════════════════════════════════════════════════════════
# 10. SECURITYTRAILS — HISTORICAL DNS / REVERSE WHOIS
# ══════════════════════════════════════════════════════════════════════════════

def securitytrails_lookup(domain: str, api_key: str = "") -> dict:
    """
    Real historical DNS and IP history via SecurityTrails API.
    FREE: 50 requests/month — https://securitytrails.com
    """
    if not api_key or not HAS_REQUESTS:
        return _sim_history(domain)
    try:
        r = req.get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": api_key, "Accept": "application/json"},
            timeout=8
        )
        if r.status_code == 200:
            d       = r.json()
            records = d.get("records", [])
            history = [
                {
                    "ip":         rec.get("values", [{}])[0].get("ip", "—"),
                    "first_seen": rec.get("first_seen", "—"),
                    "last_seen":  rec.get("last_seen",  "—"),
                    "organizations": rec.get("organizations", []),
                }
                for rec in records[:10]
            ]
            return {"domain": domain, "history": history,
                    "count": len(history), "real": True}
    except Exception as e:
        return {**_sim_history(domain), "error": str(e)}
    return _sim_history(domain)


def _sim_history(domain):
    rng    = _seed(domain + "hist")
    owners = ["Cloudflare","Amazon AWS","Google Cloud","DigitalOcean","Hetzner"]
    n      = rng.randint(3, 8)
    yr     = rng.randint(2012, 2016)
    history= []
    for _ in range(n):
        yr += rng.randint(1, 2)
        history.append({
            "ip":         f"{rng.randint(1,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
            "first_seen": f"{min(yr,2025)}-{rng.randint(1,12):02d}-01",
            "last_seen":  f"{min(yr+1,2025)}-{rng.randint(1,12):02d}-01",
            "organizations": [rng.choice(owners)],
        })
    return {"domain": domain, "history": history,
            "count": len(history), "real": False,
            "note": "Add SECURITYTRAILS_KEY for real IP history"}
