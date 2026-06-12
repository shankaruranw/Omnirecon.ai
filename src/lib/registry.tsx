/**
 * OmniRecon AI — Tool Component Registry
 * ========================================
 * Maps module/tool slugs to their React component implementations.
 *
 * This is the bridge between the URL routing system and the
 * actual tool UI components.
 *
 * How it works:
 *   1. User navigates to /module/viewdns/dns-lookup
 *   2. ModulePage.tsx reads moduleSlug="viewdns", toolSlug="dns-lookup"
 *   3. It looks up TOOL_COMPONENTS["viewdns"]["dns-lookup"]
 *   4. It renders the DnsLookup component inside a Panel
 *
 * To add a new tool:
 *   1. Create the component in src/tools/
 *   2. Add the module+slug entry to MODULES in modules.ts
 *   3. Import and add the component here
 */

import * as Dns  from "../tools/dns";           // DNS & domain intelligence tools
import * as Pw   from "../tools/passwords";    // Password strength, generator, breach
import * as Cr   from "../tools/crypto";       // Encoding, hashing, encryption
import * as Em   from "../tools/email";        // Email validation and forensics
import * as Ai   from "../tools/ai";           // AI risk, vuln scanner, malware, APK
import * as Net  from "../tools/network";      // Network scan, subdomains, WAF
import * as Off  from "../tools/offensive";    // Steganography, typosquatting
import * as Ws   from "../tools/workspace";    // AI Recon Workspace pipeline
import * as Ti   from "../tools/threat_intel"; // Threat Intelligence Center
import * as Sc   from "../tools/scorecard";    // Security Scorecard

import * as Ig   from "../tools/intel_graph";  // Intelligence Graph
import * as Soc  from "../tools/soc";          // SOC Dashboard

/**
 * TOOL_COMPONENTS
 * ---------------
 * Two-level map: module slug → tool slug → React FC component.
 *
 * Structure:
 *   {
 *     "viewdns": {
 *       "dns-lookup": DnsLookup,  ← renders when /module/viewdns/dns-lookup
 *       "whois": Whois,           ← renders when /module/viewdns/whois
 *       ...
 *     },
 *     "passwords": { ... },
 *     ...
 *   }
 */
export const TOOL_COMPONENTS: Record<string, Record<string, React.FC>> = {

  // ── AI Recon Workspace ───────────────────────────────────────────────────
  // Single automated pipeline tool — the flagship feature
  workspace: {
    recon: Ws.AiReconWorkspace,
  },

  // ── DNS / Domain Intelligence (20 tools) ────────────────────────────────
  viewdns: {
    "dns-lookup":      Dns.DnsLookup,       // Real-time DNS record resolution
    whois:             Dns.Whois,           // Domain registration & expiry
    "reverse-whois":   Dns.ReverseWhois,    // Find domains by registrant
    "reverse-ip":      Dns.ReverseIp,       // Domains sharing same server
    "reverse-mx":      Dns.ReverseMx,       // Domains sharing mail server
    "reverse-ns":      Dns.ReverseNs,       // Domains sharing name server
    "reverse-dns":     Dns.ReverseDns,      // IP → hostname (PTR record)
    "ip-location":     Dns.IpLocation,      // IP geolocation (country, ISP)
    "ip-history":      Dns.IpHistory,       // Historical IPs for a domain
    "asn-lookup":      Dns.AsnLookup,       // Autonomous system & prefixes
    "dns-report":      Dns.DnsReport,       // Full DNS health audit with grade
    dnsbl:             Dns.Dnsbl,           // Spam blacklist check (10 lists)
    "firewall-test":   Dns.FirewallTest,    // GFW China firewall test
    "abuse-contact":   Dns.AbuseContact,   // Abuse reporting email/phone
    "mac-lookup":      Dns.MacLookup,       // MAC address vendor identification
    "ssl-info":        Dns.SslInfo,         // SSL/TLS certificate inspection
    "port-scan":       Dns.PortScan,        // TCP port scanner (15 ports)
    "http-headers":    Dns.HttpHeaders,     // HTTP response header analysis
    ping:              Dns.Ping,            // ICMP ping latency test
    "dns-propagation": Dns.DnsPropagation, // Global DNS propagation check
  },

  // ── Password Lab (4 tools) ───────────────────────────────────────────────
  passwords: {
    strength:   Pw.StrengthChecker, // Shannon entropy + crack time estimate
    generator:  Pw.Generator,       // Cryptographically secure password gen
    passphrase: Pw.Passphrase,      // Diceware-style passphrase generator
    breach:     Pw.BreachCheck,     // HIBP k-anonymity breach verification
  },

  // ── Crypto Lab (9 tools) ─────────────────────────────────────────────────
  // All tools are 100% real — no simulation used here
  crypto: {
    base64: Cr.Base64,    // Base64 encode/decode
    hex:    Cr.Hex,       // Text ↔ hexadecimal
    url:    Cr.UrlEncode, // URL percent encoding/decoding
    binary: Cr.Binary,   // Text ↔ binary bitstring
    rot:    Cr.Rot,       // ROT13 / Caesar shift cipher
    morse:  Cr.Morse,     // Morse code encode/decode
    hash:   Cr.Hash,      // MD5, SHA-1, SHA-256, SHA-512, SHA-3, RIPEMD-160
    hmac:   Cr.Hmac,      // HMAC authentication codes
    aes:    Cr.Aes,       // AES-256 symmetric encryption/decryption
  },

  // ── Email Testing Suite (4 tools) ───────────────────────────────────────
  email: {
    validate: Em.EmailValidator,  // Full 5-check email analysis suite
    header:   Em.HeaderAnalyzer,  // Email header chain & auth analysis
    spf:      Em.SpfDkim,         // SPF, DKIM, DMARC record lookup
    breach:   Em.AccountExposure, // Account breach & linked service check
  },

  // ── AI Analysis Center (4 tools) ────────────────────────────────────────
  "ai-analysis": {
    risk:    Ai.RiskAnalyzer,    // Composite risk score + attack vectors
    vuln:    Ai.VulnScanner,     // CVE-based vulnerability prioritization
    malware: Ai.MalwareAnalyzer, // File/hash verdict (VirusTotal integration)
    apk:     Ai.ApkAnalyzer,     // Android APK permission risk analysis
  },

  // ── Network Scanner (3 tools) ───────────────────────────────────────────
  network: {
    scan:      Net.NetworkScan,    // Live host discovery in CIDR subnet
    subdomain: Net.SubdomainEnum,  // DNS bruteforce subdomain enumeration
    waf:       Net.WafDetector,    // WAF fingerprinting via HTTP headers
  },

  // ── Offensive Suite (2 tools) ───────────────────────────────────────────
  offensive: {
    stego:    Off.StegoStudio,
    phishing: Off.Phishing,
  },

  // ── Threat Intelligence Center (4 tools) ────────────────────────────────
  "threat-intel": {
    cve:        Ti.CveSearch,
    ioc:        Ti.IocLookup,
    "ip-rep":   Ti.IpReputation,
    "hash-check":Ti.HashLookup,
  },

  // ── Security Scorecard (4 tools) ────────────────────────────────────────
  scorecard: {
    "dns-score":   Sc.DnsScore,
    "ssl-score":   Sc.SslScore,
    "email-score": Sc.EmailScore,
    "rep-score":   Sc.RepScore,
  },

  // ── Intelligence Graph (1 tool) ─────────────────────────────────────────
  "intel-graph": {
    graph: Ig.IntelGraph,
  },

  // ── SOC Dashboard (1 tool) ──────────────────────────────────────────────
  soc: {
    "soc-dashboard": Soc.SocDashboard,
  },
};
