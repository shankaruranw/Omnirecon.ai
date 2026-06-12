import { useState } from "react";
import { Button, Input, ResultBox, Badge, Spinner } from "../lib/ui";
import { seeded, pick, randInt, randIp, delay } from "../lib/sim";
import { addHistory } from "../lib/history";
import { api, isBackendOnline } from "../lib/api";

function RealBadge({ real }: { real?: boolean }) {
  if (real === undefined) return null;
  return real
    ? <span className="ml-2 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-500/20">● REAL</span>
    : <span className="ml-2 rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-400 border border-amber-500/20">● SIM</span>;
}

async function tryReal<T>(realCall: () => Promise<T>, simCall: () => T): Promise<T> {
  if (isBackendOnline()) {
    try { const d = await realCall(); if (d) return d; } catch {}
  }
  await delay(700 + Math.random() * 500);
  return simCall();
}

export function NetworkScan() {
  const [range, setRange] = useState("192.168.1.0/24"); const [res, setRes] = useState<any>(null); const [loading, setLoading] = useState(false);
  const go = async () => {
    setLoading(true);
    const data = await tryReal(
      () => api.security.network(range),
      () => { const rng = seeded(range + "net"); const n = randInt(rng, 4, 12); const base = range.split("/")[0].split(".").slice(0,3).join("."); return { live_hosts: Array.from({length:n},()=>({ip:`${base}.${randInt(rng,1,254)}`,hostname:"—",mac:Array.from({length:6},()=>randInt(rng,0,255).toString(16).padStart(2,"0")).join(":"),os:pick(rng,["Linux 5.x","Windows 11","macOS 14","Android"])})), count: n, real: false }; }
    );
    setRes(data); setLoading(false);
    addHistory({ module: "Network Scanner", tool: "Network Scan", target: range, summary: `${data.count||0} live hosts discovered` });
  };
  const hosts = res?.live_hosts || [];
  return <div><div className="flex gap-2"><Input value={range} onChange={e=>setRange(e.target.value)} placeholder="CIDR e.g. 192.168.1.0/24" className="mono"/><Button onClick={go}>Scan</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>{hosts.length} Live Hosts <RealBadge real={res.real}/></span> as any}><div className="space-y-2">{hosts.map((h:any)=><div key={h.ip} className="rounded-md border border-slate-800 p-3"><div className="flex items-center justify-between"><span className="mono text-slate-100">{h.ip}</span>{h.hostname&&h.hostname!=="—"&&<span className="text-xs text-slate-400">{h.hostname}</span>}</div>{h.mac&&<div className="mt-1 text-xs text-slate-500 mono">{h.mac}</div>}</div>)}</div></ResultBox>}</div>;
}

export function SubdomainEnum() {
  const [domain, setDomain] = useState("example.com"); const [res, setRes] = useState<any>(null); const [loading, setLoading] = useState(false);
  const SUBS = "www mail ftp api dev staging admin blog shop vpn cdn app test portal git jenkins db smtp auth docs status dashboard".split(" ");
  const go = async () => {
    setLoading(true);
    const data = await tryReal(
      () => api.security.subdomains(domain),
      () => { const rng = seeded(domain + "sub"); const found = SUBS.filter(()=>rng()>0.5).map(s=>({host:`${s}.${domain}`,ip:randIp(rng),status:pick(rng,[200,200,301,403,404]),live:true})); return{subdomains:found,count:found.length,real:false}; }
    );
    setRes(data); setLoading(false);
    addHistory({ module: "Network Scanner", tool: "Subdomain Enumerator", target: domain, summary: `${data.count||0} subdomains found` });
  };
  const subs = res?.subdomains || [];
  return <div><div className="flex gap-2"><Input value={domain} onChange={e=>setDomain(e.target.value)}/><Button onClick={go}>Enumerate</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>{subs.length} Subdomains <RealBadge real={res.real}/></span> as any}><div className="space-y-1">{subs.map((s:any)=><div key={s.host||s.sub} className="mono flex items-center justify-between rounded border border-slate-800 px-3 py-1.5 text-sm"><span className="text-teal-300">{s.host||s.sub}</span><span className="text-slate-500">{s.ip}</span>{s.status&&<Badge color={s.status<300?"emerald":s.status<400?"amber":"rose"}>{s.status}</Badge>}</div>)}</div></ResultBox>}</div>;
}

export function WafDetector() {
  const [url, setUrl] = useState("https://example.com"); const [res, setRes] = useState<any>(null); const [loading, setLoading] = useState(false);
  const go = async () => {
    setLoading(true);
    const data = await tryReal(
      () => api.security.waf(url),
      () => { const rng = seeded(url + "waf"); const WAFS = [{name:"Cloudflare",sig:"cf-ray header"},{name:"AWS WAF",sig:"x-amz-cf-id"},{name:"Akamai",sig:"x-akamai-transformed"},{name:"Sucuri",sig:"x-sucuri-id"},{name:"None detected",sig:"no WAF fingerprints"}]; const waf = pick(rng,WAFS); return{...waf,waf:waf.name,protected:waf.name!=="None detected",confidence:randInt(rng,70,99),real:false}; }
    );
    setRes(data); setLoading(false);
    addHistory({ module: "Network Scanner", tool: "WAF Detector", target: url, summary: `WAF: ${data.waf||data.name||"Unknown"}`, risk: (data.protected)?undefined:"Medium" });
  };
  const wafName = res?.waf || res?.name || "Unknown";
  const protected_ = res?.protected;
  return <div><p className="mb-3 text-sm text-slate-400">Analyzes HTTP responses to fingerprint Web Application Firewalls.</p><div className="flex gap-2"><Input value={url} onChange={e=>setUrl(e.target.value)}/><Button onClick={go}>Detect</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>WAF Detection <RealBadge real={res.real}/></span> as any}><div className="mb-3 flex items-center justify-between"><span className="text-lg font-bold" style={{color:!protected_?"#f59e0b":"#10b981"}}>{wafName}</span><Badge color="teal">confidence {res.confidence}%</Badge></div><div className="mono rounded border border-slate-800 p-2 text-xs"><span className="text-slate-500">Signatures: </span><span className="text-slate-300">{res.sig||res.signature||"—"}</span></div></ResultBox>}</div>;
}
