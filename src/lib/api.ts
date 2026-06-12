/**
 * OmniRecon AI — Real API Client
 * ================================
 * This file connects the React frontend to the Python Flask backend.
 * If the backend is offline, tools automatically fall back to simulation mode.
 *
 * Architecture:
 *   Browser (React) → fetch() → Python Flask (/api/...)
 *
 * Every exported function here maps to a real Python backend endpoint.
 */

// Base URL of the Python Flask backend server
const BACKEND = "http://127.0.0.1:5000/api";

// Tracks whether the Python backend is currently reachable
let backendOnline = false;

/**
 * checkBackend()
 * --------------
 * Pings the backend /health endpoint on app load.
 * Sets backendOnline = true if the server responds within 2 seconds.
 * Dispatches a "backend-status" event so the Layout can update the badge.
 */
export async function checkBackend(): Promise<boolean> {
  try {
    const r = await fetch(`${BACKEND}/health`, {
      signal: AbortSignal.timeout(2000), // 2-second timeout
    });
    backendOnline = r.ok;
  } catch {
    // Backend is offline or unreachable — use simulation fallback
    backendOnline = false;
  }
  // Notify Layout component to update the "Real Mode / Simulation" badge
  window.dispatchEvent(
    new CustomEvent("backend-status", { detail: { online: backendOnline } })
  );
  return backendOnline;
}

/**
 * isBackendOnline()
 * -----------------
 * Returns current backend availability status.
 * Used by tool components to decide real API vs simulation.
 */
export function isBackendOnline() {
  return backendOnline;
}

/**
 * get(path, params)
 * -----------------
 * Internal helper — makes a GET request to the backend.
 * Automatically appends query parameters to the URL.
 * Times out after 15 seconds.
 */
async function get(path: string, params?: Record<string, string>) {
  const url = new URL(`${BACKEND}${path}`);
  if (params) {
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  }
  const r = await fetch(url.toString(), {
    signal: AbortSignal.timeout(15000), // 15-second timeout for network tools
  });
  return r.json();
}

/**
 * post(path, body)
 * ----------------
 * Internal helper — makes a POST request with a JSON body.
 * Times out after 20 seconds (longer for analysis tools).
 */
async function post(path: string, body: object) {
  const r = await fetch(`${BACKEND}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000), // 20-second timeout
  });
  return r.json();
}

/**
 * api object
 * ----------
 * Central API client used by all tool components.
 * Each function maps to a specific Python Flask route.
 *
 * Usage example in a tool:
 *   const data = await api.dns.lookup("example.com");
 */
export const api = {

  // ── DNS / Domain Intelligence ─────────────────────────────
  dns: {
    lookup:      (domain: string) => get("/dns/lookup",      { domain }),
    whois:       (domain: string) => get("/dns/whois",       { domain }),
    reverseDns:  (ip: string)     => get("/dns/reverse",     { ip }),
    geo:         (ip: string)     => get("/dns/geo",         { ip }),
    ports:       (host: string)   => get("/dns/ports",       { host }),
    headers:     (url: string)    => get("/dns/headers",     { url }),
    ssl:         (domain: string) => get("/dns/ssl",         { domain }),
    ping:        (host: string)   => get("/dns/ping",        { host }),
    blacklist:   (ip: string)     => get("/dns/blacklist",   { ip }),
    mac:         (mac: string)    => get("/dns/mac",         { mac }),
    propagation: (domain: string) => get("/dns/propagation", { domain }),
  },

  // ── Password Lab ─────────────────────────────────────────
  password: {
    strength:   (password: string) => post("/password/strength",   { password }),
    generate:   (length: number)   => post("/password/generate",   { length }),
    breach:     (password: string) => post("/password/breach",     { password }),
  },

  // ── Crypto Lab ───────────────────────────────────────────
  crypto: {
    hash:   (text: string)               => post("/crypto/hash",   { text }),
    hmac:   (text: string, key: string)  => post("/crypto/hmac",   { text, key }),
    base64: (text: string, mode: string) => post("/crypto/base64", { text, mode }),
  },

  // ── Email Testing Suite ──────────────────────────────────
  email: {
    analyze: (email: string)  => post("/email/analyze", { email }),
    auth:    (domain: string) => get("/email/auth",     { domain }),
  },

  // ── Security / AI / Network Tools ────────────────────────
  security: {
    malware:      (hash: string)                   => post("/security/malware",      { hash }),
    waf:          (url: string)                    => get("/security/waf",           { url }),
    typosquat:    (domain: string)                 => get("/security/typosquat",     { domain }),
    risk:         (target: string, data?: object)  => post("/security/risk",         { target, data }),
    subdomains:   (domain: string)                 => get("/security/subdomains",    { domain }),
    network:      (cidr: string)                   => post("/security/network",      { cidr }),
    ipReputation: (ip: string)                     => get("/security/ip-reputation", { ip }),
  },

  // ── Threat Intelligence (Module 10) ──────────────────────
  // CVE uses free NIST NVD API  (no key needed)
  // IOC uses AlienVault OTX API (free key — ALIENVAULT_API_KEY)
  // Scorecard uses real DNS + SSL + DNSBL checks
  threat: {
    cve:       (q: string)      => get("/threat/cve",       { q }),
    ioc:       (ioc: string)    => get("/threat/ioc",       { ioc }),
    scorecard: (domain: string) => get("/threat/scorecard", { domain }),
  },
};

// Start backend check when the app loads
checkBackend();
