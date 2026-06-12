/**
 * OmniRecon AI — Module & Tool Registry
 * =======================================
 * This file is the single source of truth for all modules and tools.
 * Every module shown in the sidebar and every tool in the tabs
 * is defined here.
 *
 * Structure:
 *   MODULES → array of ModuleDef
 *     each ModuleDef → has a tools array of ToolDef
 *
 * The slug fields are used in the URL routing:
 *   /module/viewdns/dns-lookup
 *   /module/passwords/strength
 *
 * The registry.tsx file maps these slugs to actual React components.
 */

// ── Type Definitions ──────────────────────────────────────────────────────────

/**
 * ToolDef
 * -------
 * Defines a single security tool inside a module.
 * The slug must match a key in registry.tsx TOOL_COMPONENTS.
 */
export type ToolDef = {
  slug: string;  // URL segment: /module/viewdns/[slug]
  name: string;  // Display name shown in tabs
  desc: string;  // Short description shown in sidebar and tool panel
};

/**
 * ModuleDef
 * ---------
 * Defines a complete security module with its set of tools.
 */
export type ModuleDef = {
  slug:  string;     // URL segment: /module/[slug]
  name:  string;     // Display name shown in sidebar
  icon:  string;     // Lucide icon name (e.g. "Globe", "KeyRound")
  color: string;     // Tailwind color key for the icon background
  desc:  string;     // Module description shown on the module page
  tools: ToolDef[];  // All tools belonging to this module
};

// ── Module Definitions ────────────────────────────────────────────────────────

export const MODULES: ModuleDef[] = [

  // ── Module 1: SOC Dashboard ─────────────────────────────────────────────
  // START HERE — Live overview of all activity, alerts and statistics.
  {
    slug:  "soc",
    name:  "SOC Dashboard",
    icon:  "MonitorDot",
    color: "teal",
    desc:  "Security Operations Center — live scans, high-risk targets, alerts and statistics.",
    tools: [
      { slug: "soc-dashboard", name: "SOC Overview", desc: "Live view of recent scans, high-risk targets, alerts and statistics." },
    ],
  },

  // ── Module 2: AI Recon Workspace ────────────────────────────────────────
  // STEP 1 — Automated 10-stage recon from a single domain input.
  {
    slug:  "workspace",
    name:  "AI Recon Workspace",
    icon:  "Sparkles",
    color: "emerald",
    desc:  "Enter one domain — auto-runs the full recon pipeline & writes an AI security report.",
    tools: [
      {
        slug: "recon",
        name: "Automated Recon",
        desc: "DNS, WHOIS, subdomains, SSL, headers, WAF, reputation, tech, AI scoring & report.",
      },
    ],
  },

  // ── Module 3: DNS / Domain Intel ────────────────────────────────────────
  // STEP 2 — Manual deep-dive into domain and IP infrastructure (20 tools).
  {
    slug:  "viewdns",
    name:  "DNS / Domain Intel",
    icon:  "Globe",
    color: "blue",
    desc:  "ViewDNS-style domain & network reconnaissance toolkit — 20 tools.",
    tools: [
      { slug: "dns-lookup",       name: "DNS Record Lookup",      desc: "A, AAAA, MX, TXT, NS, CNAME, SOA records." },
      { slug: "whois",            name: "WHOIS Lookup",           desc: "Registrar, registrant & expiry data." },
      { slug: "reverse-whois",    name: "Reverse WHOIS",          desc: "Find domains by registrant name/email." },
      { slug: "reverse-ip",       name: "Reverse IP Lookup",      desc: "Domains hosted on the same server." },
      { slug: "reverse-mx",       name: "Reverse MX Lookup",      desc: "Domains using the same mail server." },
      { slug: "reverse-ns",       name: "Reverse NS Lookup",      desc: "Domains using the same name server." },
      { slug: "reverse-dns",      name: "Reverse DNS (PTR)",      desc: "Resolve an IP back to a hostname." },
      { slug: "ip-location",      name: "IP Geolocation",         desc: "Country, ISP, ASN & coordinates." },
      { slug: "ip-history",       name: "IP History",             desc: "Historical IP addresses of a domain." },
      { slug: "asn-lookup",       name: "ASN Lookup",             desc: "Autonomous System & network ranges." },
      { slug: "dns-report",       name: "DNS Health Report",      desc: "Full configuration audit & grading." },
      { slug: "dnsbl",            name: "Spam Blacklist (DNSBL)", desc: "Check IP across spam databases." },
      { slug: "firewall-test",    name: "China Firewall Test",    desc: "Test if a site is GFW-blocked." },
      { slug: "abuse-contact",    name: "Abuse Contact Lookup",   desc: "Find abuse reporting addresses." },
      { slug: "mac-lookup",       name: "MAC Address Lookup",     desc: "Identify hardware vendor (OUI)." },
      { slug: "ssl-info",         name: "SSL Certificate Info",   desc: "Issuer, validity & TLS details." },
      { slug: "port-scan",        name: "Port Scanner",           desc: "Common open TCP ports." },
      { slug: "http-headers",     name: "HTTP Headers",           desc: "Inspect server response headers." },
      { slug: "ping",             name: "Ping / Traceroute",      desc: "Latency & route hops." },
      { slug: "dns-propagation",  name: "DNS Propagation",        desc: "Global resolver check." },
    ],
  },

  // ── Module 4: Network Scanner ────────────────────────────────────────────
  // STEP 3 — Discover live hosts, subdomains and WAF protection.
  {
    slug:  "network",
    name:  "Network Scanner",
    icon:  "Network",
    color: "indigo",
    desc:  "Host discovery, subdomain enumeration & WAF detection.",
    tools: [
      { slug: "scan",      name: "Network Scan",         desc: "Live hosts & service detection." },
      { slug: "subdomain", name: "Subdomain Enumerator", desc: "Discover subdomains." },
      { slug: "waf",       name: "WAF Detector",         desc: "Cloudflare, AWS, Akamai, Sucuri." },
    ],
  },

  // ── Module 5: Threat Intelligence ───────────────────────────────────────
  // STEP 4 — Check CVEs, IOCs, IP reputation and file hashes.
  {
    slug:  "threat-intel",
    name:  "Threat Intelligence",
    icon:  "Radar",
    color: "rose",
    desc:  "CVE search, IOC lookup, IP reputation and hash threat intelligence.",
    tools: [
      { slug: "cve",        name: "CVE Search",    desc: "Search Common Vulnerabilities and Exposures database." },
      { slug: "ioc",        name: "IOC Lookup",    desc: "Indicator of Compromise — IP, domain, hash lookup." },
      { slug: "ip-rep",     name: "IP Reputation", desc: "Threat score, abuse reports and geolocation." },
      { slug: "hash-check", name: "Hash Lookup",   desc: "Check file hash against threat intelligence feeds." },
    ],
  },

  // ── Module 6: Security Scorecard ────────────────────────────────────────
  // STEP 5 — Grade the target across DNS, SSL, Email and Reputation.
  {
    slug:  "scorecard",
    name:  "Security Scorecard",
    icon:  "BarChart3",
    color: "amber",
    desc:  "Grade your domain across DNS, SSL, Email and Reputation dimensions.",
    tools: [
      { slug: "dns-score",   name: "DNS Score",        desc: "Grade DNS configuration — SPF, DMARC, DNSSEC." },
      { slug: "ssl-score",   name: "SSL Score",        desc: "Grade TLS/SSL security — protocol, cipher, expiry." },
      { slug: "email-score", name: "Email Score",      desc: "Grade email security — SPF, DKIM, DMARC, BIMI." },
      { slug: "rep-score",   name: "Reputation Score", desc: "Grade domain reputation — blacklists, malware, age." },
    ],
  },

  // ── Module 7: Intelligence Graph ────────────────────────────────────────
  // STEP 6 — Visualize all discovered relationships in one graph.
  {
    slug:  "intel-graph",
    name:  "Intelligence Graph",
    icon:  "GitFork",
    color: "emerald",
    desc:  "Visual relationship graph: Domain ↔ IP ↔ ASN ↔ SSL ↔ Subdomains.",
    tools: [
      { slug: "graph", name: "Relationship Graph", desc: "Visualize connections between domain, IP, ASN, SSL and subdomains." },
    ],
  },

  // ── Module 8: AI Analysis Center ────────────────────────────────────────
  // STEP 7 — AI-powered risk scoring, vulnerability and malware analysis.
  {
    slug:  "ai-analysis",
    name:  "AI Analysis Center",
    icon:  "BrainCircuit",
    color: "emerald",
    desc:  "AI-driven risk scoring, attack-vector prediction & recommendation engine.",
    tools: [
      { slug: "risk",    name: "AI Risk Analyzer",         desc: "Rate risk & next attack vectors." },
      { slug: "vuln",    name: "AI Vulnerability Scanner",  desc: "Detect & prioritize weaknesses." },
      { slug: "malware", name: "AI Malware Analyzer",      desc: "File / hash threat verdict." },
      { slug: "apk",     name: "APK Analyzer",             desc: "Permissions & risk of Android apps." },
    ],
  },

  // ── Module 9: Email Testing Suite ───────────────────────────────────────
  // STEP 8 — Email forensics, validation and exposure analysis.
  {
    slug:  "email",
    name:  "Email Testing Suite",
    icon:  "Mail",
    color: "rose",
    desc:  "Validate email syntax, verify MX records, check SPF/DMARC/DKIM, detect disposable domains and look up breach exposure.",
    tools: [
      { slug: "validate", name: "Full Suite Analysis", desc: "Single email → complete investigation." },
      { slug: "header",   name: "Header Analyzer",     desc: "Parse received chain & auth." },
      { slug: "spf",      name: "SPF / DKIM / DMARC", desc: "Mail auth records." },
      { slug: "breach",   name: "Account Exposure",    desc: "Linked accounts & breaches." },
    ],
  },

  // ── Module 10: Password Lab ──────────────────────────────────────────────
  // STEP 9 — Password strength, generation and breach verification.
  {
    slug:  "passwords",
    name:  "Password Lab",
    icon:  "KeyRound",
    color: "amber",
    desc:  "Strength analysis, secure generation & breach verification.",
    tools: [
      { slug: "strength",   name: "Strength Checker",     desc: "Entropy, crack-time & feedback." },
      { slug: "generator",  name: "Password Generator",   desc: "Customizable secure passwords." },
      { slug: "passphrase", name: "Passphrase Generator", desc: "Memorable diceware phrases." },
      { slug: "breach",     name: "Breach Check",         desc: "Check if password appeared in known data breaches." },
    ],
  },

  // ── Module 11: Crypto Lab ────────────────────────────────────────────────
  // STEP 10 — Cryptographic operations, hashing and encoding (all 100% real).
  {
    slug:  "crypto",
    name:  "Crypto Lab",
    icon:  "Binary",
    color: "indigo",
    desc:  "Encoders, decoders, hashing & cipher tools — all 100% real results.",
    tools: [
      { slug: "base64", name: "Base64",         desc: "Encode / decode Base64." },
      { slug: "hex",    name: "Hex",            desc: "Text ↔ hexadecimal." },
      { slug: "url",    name: "URL Encode",     desc: "Percent encoding." },
      { slug: "binary", name: "Binary",         desc: "Text ↔ binary." },
      { slug: "rot",    name: "ROT13 / Caesar", desc: "Classic shift cipher." },
      { slug: "morse",  name: "Morse Code",     desc: "Text ↔ morse." },
      { slug: "hash",   name: "Hash Generator", desc: "MD5, SHA-1/256/512, SHA-3." },
      { slug: "hmac",   name: "HMAC",           desc: "Keyed hash auth codes." },
      { slug: "aes",    name: "AES Encrypt",    desc: "AES-256 symmetric crypto." },
    ],
  },

  // ── Module 12: Offensive Suite ──────────────────────────────────────────
  // STEP 11 — Steganography and phishing/typosquatting detection.
  {
    slug:  "offensive",
    name:  "Offensive Suite",
    icon:  "ShieldAlert",
    color: "rose",
    desc:  "Real LSB steganography & phishing/typosquatting domain detection.",
    tools: [
      { slug: "stego",    name: "Steganography Studio",     desc: "Hide/extract text via LSB pixel manipulation." },
      { slug: "phishing", name: "Phishing & Typosquatting", desc: "Generate malicious domain variants (6 patterns)." },
    ],
  },

  // ── Module 13: Reporting System ─────────────────────────────────────────
  // STEP 13 — Generate final professional reports and export data.
  {
    slug:  "reports",
    name:  "Reporting System",
    icon:  "FileClock",
    color: "teal",
    desc:  "Generate PDF, Executive, Technical & AI reports — export CSV/JSON.",
    tools: [],
  },
];

/**
 * getModule(slug)
 * ---------------
 * Finds and returns a module definition by its URL slug.
 * Returns undefined if the slug doesn't match any module.
 *
 * Used by ModulePage.tsx to load the correct module.
 */
export function getModule(slug: string) {
  return MODULES.find((m) => m.slug === slug);
}
