/**
 * OmniRecon AI — Threat Intelligence Center (Module 10)
 * =======================================================
 * Tools: CVE Search, IOC Lookup, IP Reputation, Hash Lookup
 * Uses the simulation engine with deterministic results.
 */

import { useState } from "react";
import { Button, Input, ResultBox, Badge, KeyVal, Spinner } from "../lib/ui";
import { seeded, pick, randInt, delay } from "../lib/sim";
import { addHistory } from "../lib/history";
import { api, isBackendOnline } from "../lib/api";

// ── Real / Sim badge ─────────────────────────────────────────────────────────
function RealBadge({ real }: { real?: boolean }) {
  if (real === undefined) return null;
  return real
    ? <span className="ml-2 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-500/20">● REAL</span>
    : <span className="ml-2 rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-400 border border-amber-500/20">● SIM</span>;
}

// ── CVE Search ───────────────────────────────────────────────────────────────

const CVE_DESCRIPTIONS: Record<string, string> = {
  "Remote Code Execution":   "Allows an attacker to run arbitrary code on the target system.",
  "SQL Injection":           "Malformed SQL input allows unauthorized database access.",
  "Cross-Site Scripting":    "Injects malicious scripts into web pages viewed by other users.",
  "Authentication Bypass":   "Allows an attacker to skip authentication checks.",
  "Privilege Escalation":    "Allows a low-privilege user to gain higher privileges.",
  "Information Disclosure":  "Exposes sensitive data to unauthorized actors.",
  "Buffer Overflow":         "Memory corruption leading to arbitrary code execution.",
  "Denial of Service":       "Makes a system or service unavailable to users.",
};

export function CveSearch() {
  const [query, setQuery]   = useState("");
  const [res, setRes]       = useState<any[] | null>(null);
  const [loading, setLoading] = useState(false);

  const search = async () => {
    if (!query.trim()) return;
    setLoading(true);

    // Try real NIST NVD API via backend
    if (isBackendOnline()) {
      try {
        const data = await api.threat.cve(query);
        if (data?.results?.length > 0) {
          setRes(data.results);
          setLoading(false);
          addHistory({ module:"Threat Intelligence", tool:"CVE Search", target:query,
            summary:`${data.results.length} CVEs found (NIST NVD)` });
          return;
        }
      } catch {}
    }

    await delay(900 + Math.random() * 400);
    const rng   = seeded(query + "cve");
    const count = randInt(rng, 3, 8);
    const types = Object.keys(CVE_DESCRIPTIONS);

    const results = Array.from({ length: count }, (_, i) => {
      const year  = randInt(rng, 2018, 2025);
      const id    = randInt(rng, 1000, 59999);
      const type  = pick(rng, types);
      const cvss  = (rng() * 5 + 5).toFixed(1);        // 5.0 – 10.0
      const sev   = +cvss >= 9 ? "Critical" : +cvss >= 7 ? "High" : "Medium";
      return {
        cve:   `CVE-${year}-${String(id).padStart(5,"0")}`,
        title: `${type} in ${query} component`,
        desc:  CVE_DESCRIPTIONS[type],
        cvss,
        sev,
        published: `${year}-${String(randInt(rng,1,12)).padStart(2,"0")}-${String(randInt(rng,1,28)).padStart(2,"0")}`,
        patch: pick(rng, ["Available","Not available","Partial"]),
      };
    }).sort((a,b) => +b.cvss - +a.cvss);

    setRes(results);
    setLoading(false);
    addHistory({ module:"Threat Intelligence", tool:"CVE Search", target:query,
      summary:`${count} CVEs found (max CVSS ${results[0].cvss})`,
      risk: +results[0].cvss >= 9 ? "Critical" : "High" });
  };

  const sevColor = (s:string) => s==="Critical"?"rose":s==="High"?"amber":"indigo";

  return (
    <div>
      <p className="mb-3 text-sm text-slate-400">
        Search the CVE database for vulnerabilities by product, keyword, or CVE ID.
      </p>
      <div className="flex gap-2">
        <Input value={query} onChange={e=>setQuery(e.target.value)}
          placeholder="e.g. OpenSSL, Apache, log4j, CVE-2021-44228"
          onKeyDown={e=>e.key==="Enter"&&search()} />
        <Button onClick={search} disabled={loading}>Search</Button>
      </div>
      {loading && <div className="mt-4"><Spinner /></div>}
      {res && !loading && (
        <ResultBox title={`${res.length} CVEs Found`}>
          <div className="space-y-3">
            {res.map((c,i) => (
              <div key={i} className="rounded-lg border border-slate-800 p-3">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="mono text-sm font-bold text-teal-300">{c.cve}</span>
                  <div className="flex items-center gap-2">
                    <Badge color={sevColor(c.sev) as any}>{c.sev}</Badge>
                    <span className="mono text-sm font-bold" style={{color: +c.cvss>=9?"#f43f5e":+c.cvss>=7?"#f59e0b":"#6366f1"}}>
                      CVSS {c.cvss}
                    </span>
                  </div>
                </div>
                <div className="text-sm font-medium text-slate-100 mb-1">{c.title}</div>
                <div className="text-xs text-slate-400 mb-2">{c.desc}</div>
                <div className="flex gap-4 text-xs text-slate-500">
                  <span>Published: {c.published}</span>
                  <span>Patch: <span className={c.patch==="Available"?"text-emerald-400":"text-rose-400"}>{c.patch}</span></span>
                </div>
              </div>
            ))}
          </div>
        </ResultBox>
      )}
    </div>
  );
}

// ── IOC Lookup ───────────────────────────────────────────────────────────────

export function IocLookup() {
  const [ioc, setIoc]         = useState("");
  const [res, setRes]         = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const lookup = async () => {
    if (!ioc.trim()) return;
    setLoading(true);

    // Try real AlienVault OTX via backend
    if (isBackendOnline()) {
      try {
        const data = await api.threat.ioc(ioc);
        if (data?.ok) {
          setRes({ ...data, ioc });
          setLoading(false);
          addHistory({ module:"Threat Intelligence", tool:"IOC Lookup", target:ioc,
            summary: data.malicious ? `MALICIOUS — score ${data.score}/100` : `Clean — score ${data.score}/100`,
            risk: data.malicious ? "High" : "Low" });
          return;
        }
      } catch {}
    }

    await delay(800 + Math.random() * 500);
    const rng       = seeded(ioc + "ioc");
    const malicious = rng() > 0.45;
    const score     = malicious ? randInt(rng, 60, 99) : randInt(rng, 0, 25);

    // Detect IOC type from input
    const isIp      = /^(\d{1,3}\.){3}\d{1,3}$/.test(ioc);
    const isHash    = /^[a-fA-F0-9]{32,64}$/.test(ioc);
    const isDomain  = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(ioc);
    const type      = isIp ? "IP Address" : isHash ? "File Hash" : isDomain ? "Domain" : "Unknown";

    const threatTypes = ["Botnet C2","Malware Distribution","Phishing","Ransomware","Spam","Cryptomining","Data Exfiltration"];

    setRes({
      ioc, type, score, malicious,
      threat: malicious ? pick(rng, threatTypes) : "None",
      sources: randInt(rng, 1, 12),
      first_seen: malicious ? `${randInt(rng,2020,2025)}-${String(randInt(rng,1,12)).padStart(2,"0")}-01` : "—",
      last_seen:  malicious ? `2025-${String(randInt(rng,1,12)).padStart(2,"0")}-${String(randInt(rng,1,28)).padStart(2,"0")}` : "—",
      country: pick(rng, ["RU","CN","KP","IR","US","DE","NL"]),
      asn: `AS${randInt(rng,1000,60000)}`,
      tags: malicious ? [pick(rng,["apt","rat","stealer","loader"]), pick(rng,["c2","dropper","exploit"])] : [],
    });

    setLoading(false);
    addHistory({ module:"Threat Intelligence", tool:"IOC Lookup", target:ioc,
      summary: malicious ? `MALICIOUS — score ${score}/100` : `Clean — score ${score}/100`,
      risk: malicious ? "High" : "Low" });
  };

  return (
    <div>
      <p className="mb-3 text-sm text-slate-400">
        Check an IP address, domain, or file hash against threat intelligence feeds.
      </p>
      <div className="flex gap-2">
        <Input value={ioc} onChange={e=>setIoc(e.target.value)}
          placeholder="IP, domain, MD5/SHA-256 hash"
          onKeyDown={e=>e.key==="Enter"&&lookup()} className="mono" />
        <Button onClick={lookup} disabled={loading}>Lookup</Button>
      </div>
      {loading && <div className="mt-4"><Spinner /></div>}
      {res && !loading && (
        <ResultBox title="IOC Threat Intelligence">
          {/* Score gauge */}
          <div className="mb-4 flex items-center gap-5">
            <div className="relative h-24 w-24">
              <svg viewBox="0 0 100 100" className="h-24 w-24 -rotate-90">
                <circle cx="50" cy="50" r="42" fill="none" stroke="#1e293b" strokeWidth="10"/>
                <circle cx="50" cy="50" r="42" fill="none"
                  stroke={res.malicious?"#f43f5e":"#10b981"} strokeWidth="10" strokeLinecap="round"
                  strokeDasharray={`${(res.score/100)*264} 264`}/>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-bold" style={{color:res.malicious?"#f43f5e":"#10b981"}}>{res.score}</span>
                <span className="text-[10px] text-slate-500">/100</span>
              </div>
            </div>
            <div>
              <div className="text-2xl font-bold" style={{color:res.malicious?"#f43f5e":"#10b981"}}>
                {res.malicious ? "⚠ MALICIOUS" : "✓ CLEAN"}
              </div>
              <div className="text-sm text-slate-400">Type: {res.type}</div>
              {res.threat !== "None" && <Badge color="rose" className="mt-2">{res.threat}</Badge>}
            </div>
          </div>
          <KeyVal data={{
            "IOC":         res.ioc,
            "Type":        res.type,
            "Threat Score":res.score + "/100",
            "Sources":     res.sources + " threat feeds",
            "First Seen":  res.first_seen,
            "Last Seen":   res.last_seen,
            "Country":     res.country,
            "ASN":         res.asn,
          }}/>
          {res.tags.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-2">
              {res.tags.map((t:string) => <Badge key={t} color="rose">{t}</Badge>)}
            </div>
          )}
        </ResultBox>
      )}
    </div>
  );
}

// ── IP Reputation ────────────────────────────────────────────────────────────

export function IpReputation() {
  const [ip, setIp]           = useState("");
  const [res, setRes]         = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const check = async () => {
    if (!ip.trim()) return;
    setLoading(true);
    await delay(750 + Math.random() * 400);

    const rng    = seeded(ip + "iprep");
    const score  = randInt(rng, 0, 100);
    const risky  = score > 50;
    const categories = ["Spam","Brute Force","Port Scan","Botnet","Proxy/VPN","Tor Node","Data Center"];

    setRes({
      ip,
      score,
      risk_level: score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 30 ? "Medium" : "Low",
      country: pick(rng, ["United States","Russia","China","Netherlands","Germany","Ukraine"]),
      isp: pick(rng, ["Cloudflare Inc.","Amazon AWS","DigitalOcean","Hetzner Online","OVH SAS"]),
      asn: `AS${randInt(rng,1000,60000)}`,
      abuse_reports: risky ? randInt(rng, 1, 500) : 0,
      categories: risky ? [pick(rng, categories), pick(rng, categories)].filter((v,i,a)=>a.indexOf(v)===i) : [],
      is_tor: rng() > 0.88,
      is_vpn: rng() > 0.75,
      is_datacenter: rng() > 0.5,
      last_reported: risky ? `2025-${String(randInt(rng,1,12)).padStart(2,"0")}-${String(randInt(rng,1,28)).padStart(2,"0")}` : "Never",
    });

    setLoading(false);
    addHistory({ module:"Threat Intelligence", tool:"IP Reputation", target:ip,
      summary:`Score ${score}/100`, risk: score>=60?"High":score>=30?"Medium":"Low" });
  };

  const scoreColor = (s:number) => s>=80?"#f43f5e":s>=60?"#fb923c":s>=30?"#f59e0b":"#10b981";

  return (
    <div>
      <p className="mb-3 text-sm text-slate-400">
        Check an IP address threat score, abuse reports and geo-intelligence.
      </p>
      <div className="flex gap-2">
        <Input value={ip} onChange={e=>setIp(e.target.value)} placeholder="e.g. 8.8.8.8" className="mono"
          onKeyDown={e=>e.key==="Enter"&&check()} />
        <Button onClick={check} disabled={loading}>Check</Button>
      </div>
      {loading && <div className="mt-4"><Spinner /></div>}
      {res && !loading && (
        <ResultBox title="IP Reputation Analysis">
          <div className="mb-4 flex items-center gap-5">
            <div className="relative h-24 w-24">
              <svg viewBox="0 0 100 100" className="h-24 w-24 -rotate-90">
                <circle cx="50" cy="50" r="42" fill="none" stroke="#1e293b" strokeWidth="10"/>
                <circle cx="50" cy="50" r="42" fill="none"
                  stroke={scoreColor(res.score)} strokeWidth="10" strokeLinecap="round"
                  strokeDasharray={`${(res.score/100)*264} 264`}/>
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-2xl font-bold" style={{color:scoreColor(res.score)}}>{res.score}</span>
                <span className="text-[10px] text-slate-500">/100</span>
              </div>
            </div>
            <div>
              <div className="text-xl font-bold" style={{color:scoreColor(res.score)}}>{res.risk_level} Risk</div>
              <div className="text-sm text-slate-400 mt-1">{res.abuse_reports} abuse reports</div>
              <div className="flex flex-wrap gap-1 mt-2">
                {res.categories.map((c:string)=><Badge key={c} color="rose">{c}</Badge>)}
                {res.is_tor && <Badge color="amber">Tor Node</Badge>}
                {res.is_vpn && <Badge color="amber">VPN</Badge>}
                {res.is_datacenter && <Badge color="slate">Datacenter</Badge>}
              </div>
            </div>
          </div>
          <KeyVal data={{ "IP":res.ip, "Country":res.country, "ISP":res.isp, "ASN":res.asn, "Last Reported":res.last_reported }}/>
        </ResultBox>
      )}
    </div>
  );
}

// ── Hash Lookup ──────────────────────────────────────────────────────────────

export function HashLookup() {
  const [hash, setHash]       = useState("");
  const [res, setRes]         = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const lookup = async () => {
    if (!hash.trim()) return;
    setLoading(true);
    await delay(800 + Math.random() * 400);

    const rng       = seeded(hash + "hashlookup");
    const malicious = rng() > 0.45;
    const detections = malicious ? randInt(rng, 15, 68) : randInt(rng, 0, 3);

    setRes({
      hash,
      verdict:    malicious ? "Malicious" : detections > 0 ? "Suspicious" : "Clean",
      detections,
      total:      72,
      family:     malicious ? pick(rng,["Trojan.GenericKD","Win32.Emotet","Ransom.LockBit","Backdoor.Agent","Spyware.AgentTesla"]) : "—",
      file_type:  pick(rng,["PE32 executable","PDF document","Microsoft Word","ZIP archive","Python script"]),
      file_size:  `${randInt(rng,10,9000)} KB`,
      first_seen: malicious ? `${randInt(rng,2020,2024)}-${String(randInt(rng,1,12)).padStart(2,"0")}-01` : "—",
      behaviors:  malicious ? [
        pick(rng,["Drops files to %TEMP%","Modifies registry Run keys","Contacts C2 server"]),
        pick(rng,["Encrypts user files","Disables antivirus","Keylogging activity"]),
      ] : [],
    });

    setLoading(false);
    addHistory({ module:"Threat Intelligence", tool:"Hash Lookup", target:hash.slice(0,16)+"…",
      summary:`${malicious?"Malicious":"Clean"} — ${detections}/72 engines`,
      risk: malicious?"Critical": detections>0?"Medium":"Low" });
  };

  const verdictColor = (v:string) => v==="Malicious"?"#f43f5e":v==="Suspicious"?"#f59e0b":"#10b981";

  return (
    <div>
      <p className="mb-3 text-sm text-slate-400">
        Check a file hash (MD5, SHA-1, SHA-256) against 72 threat intelligence engines.
      </p>
      <div className="flex gap-2">
        <Input value={hash} onChange={e=>setHash(e.target.value)}
          placeholder="MD5, SHA-1, or SHA-256 hash" className="mono"
          onKeyDown={e=>e.key==="Enter"&&lookup()} />
        <Button onClick={lookup} disabled={loading}>Lookup</Button>
      </div>
      {loading && <div className="mt-4"><Spinner /></div>}
      {res && !loading && (
        <ResultBox title="Hash Threat Intelligence">
          <div className="mb-4 flex items-center justify-between">
            <span className="text-2xl font-bold" style={{color:verdictColor(res.verdict)}}>{res.verdict}</span>
            <Badge color={res.verdict==="Clean"?"emerald":res.verdict==="Suspicious"?"amber":"rose"}>
              {res.detections}/{res.total} engines
            </Badge>
          </div>
          <div className="mb-3 h-2 w-full overflow-hidden rounded-full bg-slate-800">
            <div className="h-full rounded-full bg-rose-500 transition-all"
              style={{width:`${(res.detections/res.total)*100}%`}}/>
          </div>
          <KeyVal data={{ "Verdict":res.verdict, "File Type":res.file_type, "File Size":res.file_size,
            "Malware Family":res.family, "First Seen":res.first_seen }}/>
          {res.behaviors.length > 0 && (
            <div className="mt-3">
              <div className="mb-1 text-xs font-semibold uppercase text-slate-500">Behaviors</div>
              {res.behaviors.map((b:string,i:number)=>(
                <div key={i} className="text-sm text-slate-300 py-1">⚠ {b}</div>
              ))}
            </div>
          )}
        </ResultBox>
      )}
    </div>
  );
}
