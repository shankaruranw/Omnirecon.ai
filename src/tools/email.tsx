import { useState } from "react";
import { Button, Input, Textarea, ResultBox, KeyVal, Badge, Spinner } from "../lib/ui";
import { seeded, pick, randInt, randIp, delay } from "../lib/sim";
import { addHistory } from "../lib/history";
import { api, isBackendOnline } from "../lib/api";

function RealBadge({ real }: { real?: boolean }) {
  if (real === undefined) return null;
  return real
    ? <span className="ml-2 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-500/20">● REAL</span>
    : <span className="ml-2 rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-400 border border-amber-500/20">● SIM</span>;
}

const DISPOSABLE = ["mailinator.com", "tempmail.com", "guerrillamail.com", "10minutemail.com", "trashmail.com", "yopmail.com"];
const BREACHES_LIST = ["LinkedIn 2021", "Adobe 2013", "Collection #1", "Dropbox 2012", "Canva 2019", "Twitter 2022", "MyFitnessPal", "Facebook 2019"];

export function EmailValidator() {
  const [email, setEmail] = useState(""); const [res, setRes] = useState<any>(null); const [loading, setLoading] = useState(false);
  const go = async () => {
    const e = email.trim(); if (!e) return; setLoading(true);
    let data: any;
    if (isBackendOnline()) {
      try { data = await api.email.analyze(e); } catch {}
    }
    if (!data) {
      await delay(1200);
      const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); const domain = e.split("@")[1]||"";
      const rng = seeded(e + "suite"); const disposable = DISPOSABLE.includes(domain);
      const n = randInt(rng,0,4); const breaches = [...BREACHES_LIST].sort(()=>rng()-0.5).slice(0,n);
      data = { valid, domain, disposable, role_account: /^(admin|info|support|noreply|sales)@/.test(e), mx_records: valid?[`mx1.${domain} (10)`,`mx2.${domain} (20)`]:[], spf: valid?`v=spf1 include:_spf.${domain} ~all`:"None", dmarc: valid?`v=DMARC1; p=${pick(rng,["none","quarantine","reject"])};`:"None", dkim: valid?"v=DKIM1; k=rsa; p=MIGfM...":"None", breaches, breach_count: n, risk: (disposable||n>1)?"High":n>0?"Medium":"Low", real: false };
    }
    setRes(data); setLoading(false);
    addHistory({ module:"Email Testing Suite", tool:"Full Suite Analysis", target:e, summary:`${data.valid?"Valid":"Invalid"} · ${data.breach_count||0} breaches found`, risk:data.risk||"Low" });
  };
  if (!res) return <div className="space-y-4"><div className="flex gap-2"><Input value={email} onChange={e=>setEmail(e.target.value)} placeholder="Enter email for full analysis…"/><Button onClick={go} disabled={loading}>Run Analysis</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}</div>;
  const validation: Record<string,string> = {"Syntax Valid":res.valid?"✓ Yes":"✗ No","Domain":res.domain||"—","Disposable":res.disposable?"⚠ Yes (Disposable)":"✓ No (Legit)","Role Account":res.role_account?"Yes":"No","SMTP Reachable":res.smtp_reachable!=null?(res.smtp_reachable?"✓ Yes":"✗ No"):"—"};
  const dnsRec: Record<string,string> = {"MX Records":(res.mx_records||[]).join(", ")||"None","SPF Record":res.spf||"None","DMARC Policy":res.dmarc||"None","DKIM Signature":res.dkim||"None"};
  return <div className="space-y-4"><div className="flex gap-2"><Input value={email} onChange={e=>setEmail(e.target.value)} placeholder="Enter email for full analysis…"/><Button onClick={go} disabled={loading}>Run Analysis</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<div className="grid gap-4 lg:grid-cols-2"><ResultBox title={<span>1. Validation & DNS <RealBadge real={res.real}/></span> as any}><KeyVal data={validation}/><div className="my-3 border-t border-slate-800"/><KeyVal data={dnsRec}/></ResultBox><ResultBox title="2. Breach & Account Exposure"><div className="mb-4"><div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Known Breaches ({res.breach_count||0})</div>{(res.breaches||[]).length>0?<div className="flex flex-wrap gap-2">{(res.breaches||[]).map((b:string)=><Badge key={b} color="rose">{b}</Badge>)}</div>:<div className="text-sm text-emerald-400">✓ No known breaches</div>}</div><div className="rounded-lg bg-slate-950/50 p-3"><div className="text-xs text-slate-400">Exposure Risk</div><div className={`text-lg font-bold ${res.risk==="High"?"text-rose-400":res.risk==="Medium"?"text-amber-400":"text-emerald-400"}`}>{res.risk||"Low"}</div></div></ResultBox></div>}</div>;
}

export function HeaderAnalyzer() {
  const [raw, setRaw] = useState(""); const [res, setRes] = useState<any>(null);
  const go = () => { const rng = seeded(raw || "h"); const hops = randInt(rng, 2, 5); setRes({ hops: Array.from({ length: hops }, (_, i) => ({ ip: randIp(rng), host: `mx${i + 1}.relay.net`, ms: randInt(rng, 50, 800) })), spf: pick(rng, ["pass", "fail", "softfail"]), dkim: pick(rng, ["pass", "fail", "none"]), dmarc: pick(rng, ["pass", "fail"]), spam: (rng() * 9).toFixed(1) }); addHistory({ module: "Email Testing Suite", tool: "Header Analyzer", target: "email headers", summary: "Mail header parsed" }); };
  return <div><Textarea rows={5} value={raw} onChange={e => setRaw(e.target.value)} placeholder="Paste raw email headers…" /><Button className="mt-3" onClick={go}>Analyze</Button>{res && <ResultBox title="Auth & Route"><div className="mb-3 flex flex-wrap gap-2"><Badge color={res.spf === "pass" ? "emerald" : "rose"}>SPF: {res.spf}</Badge><Badge color={res.dkim === "pass" ? "emerald" : "rose"}>DKIM: {res.dkim}</Badge><Badge color={res.dmarc === "pass" ? "emerald" : "rose"}>DMARC: {res.dmarc}</Badge><Badge color={+res.spam > 5 ? "rose" : "emerald"}>Spam: {res.spam}</Badge></div><div className="space-y-1">{res.hops.map((h: any, i: number) => <div key={i} className="mono flex justify-between rounded border border-slate-800 px-3 py-1.5 text-xs"><span className="text-slate-400">Hop {i + 1}</span><span className="text-slate-200">{h.host}</span><span className="text-slate-500">{h.ip}</span><span className="text-teal-400">{h.ms}ms</span></div>)}</div></ResultBox>}</div>;
}

export function SpfDkim() {
  const [domain, setDomain] = useState("example.com"); const [res, setRes] = useState<any>(null);
  const go = () => { const rng = seeded(domain + "spf"); setRes({ SPF: `v=spf1 include:_spf.${domain} ip4:${randIp(rng)} ~all`, "DKIM (default._domainkey)": `v=DKIM1; k=rsa; p=MIGfMA0GCSq...${randInt(rng, 1000, 9999)}`, DMARC: `v=DMARC1; p=${pick(rng, ["none", "quarantine", "reject"])}; rua=mailto:dmarc@${domain}`, BIMI: pick(rng, [`v=BIMI1; l=https://${domain}/logo.svg`, "(not configured)"]) }); addHistory({ module: "Email Testing Suite", tool: "SPF / DKIM / DMARC", target: domain, summary: "Mail auth records fetched" }); };
  return <div><div className="flex gap-2"><Input value={domain} onChange={e => setDomain(e.target.value)} /><Button onClick={go}>Lookup</Button></div>{res && <ResultBox title="Mail Auth Records">{Object.entries(res).map(([k, v]) => <div key={k} className="border-b border-slate-800 py-2 last:border-0"><div className="text-xs font-semibold text-teal-400">{k}</div><code className="mono break-all text-xs text-slate-200">{v as string}</code></div>)}</ResultBox>}</div>;
}

export function AccountExposure() {
  const [email, setEmail] = useState(""); const [res, setRes] = useState<any>(null); const [loading, setLoading] = useState(false);
  const go = async () => { setLoading(true); await delay(900); const rng = seeded(email + "exp"); const n = randInt(rng, 0, 5); const breaches = [...BREACHES_LIST].sort(() => rng() - 0.5).slice(0, n); const services = ["GitHub", "Spotify", "Steam", "Gravatar", "Twitter", "Pinterest"].filter(() => rng() > 0.5); setRes({ breaches, services }); setLoading(false); addHistory({ module: "Email Testing Suite", tool: "Account Exposure", target: email, summary: `${n} breaches found`, risk: n > 2 ? "High" : n > 0 ? "Medium" : "Low" }); };
  return <div><div className="flex gap-2"><Input value={email} onChange={e => setEmail(e.target.value)} placeholder="target@email.com" /><Button onClick={go}>Investigate</Button></div>{loading && <div className="mt-4"><Spinner /></div>}{res && !loading && <ResultBox title="Exposure Report"><div className="mb-3"><div className="mb-1 text-xs font-semibold uppercase text-slate-500">Data Breaches ({res.breaches.length})</div>{res.breaches.length ? <div className="flex flex-wrap gap-2">{res.breaches.map((b: string) => <Badge key={b} color="rose">{b}</Badge>)}</div> : <span className="text-sm text-emerald-300">✓ No breaches found</span>}</div><div><div className="mb-1 text-xs font-semibold uppercase text-slate-500">Linked Accounts</div><div className="flex flex-wrap gap-2">{res.services.length ? res.services.map((s: string) => <Badge key={s} color="indigo">{s}</Badge>) : <span className="text-sm text-slate-500">None detected</span>}</div></div></ResultBox>}</div>;
}
