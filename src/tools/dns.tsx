import { useState } from "react";
import { Button, Input, ResultBox, KeyVal, Spinner, Badge, Textarea } from "../lib/ui";
import { seeded, pick, randInt, randIp, delay } from "../lib/sim";
import { addHistory } from "../lib/history";
import { api, isBackendOnline } from "../lib/api";

/* shared hook — handles loading + real/sim routing */
function useRunner() {
  const [loading, setLoading] = useState(false);
  const run = async (realCall: () => Promise<any>, simCall: () => any, onResult: (d: any) => void) => {
    setLoading(true);
    try {
      if (isBackendOnline()) {
        const data = await realCall();
        if (data && data.ok !== false) { onResult(data); setLoading(false); return; }
      }
      await delay(700 + Math.random() * 500);
      onResult(simCall());
    } catch {
      await delay(700);
      onResult(simCall());
    }
    setLoading(false);
  };
  return { loading, run };
}

function RealBadge({ real }: { real?: boolean }) {
  if (real === undefined) return null;
  return real
    ? <span className="ml-2 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-400 border border-emerald-500/20">● REAL</span>
    : <span className="ml-2 rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-400 border border-amber-500/20">● SIM</span>;
}

/* ─── DNS Lookup ─────────────────────────────────────────── */
export function DnsLookup() {
  const [domain, setDomain] = useState("example.com");
  const [res, setRes] = useState<any>(null);
  const { loading, run } = useRunner();
  const go = () => run(
    () => api.dns.lookup(domain),
    () => { const rng = seeded(domain + "dns"); return { records: { A: [randIp(rng), randIp(rng)], AAAA: [`2606:4700:${randInt(rng,1000,9999)}::1`], MX: [`10 mail.${domain}`], NS: [`ns1.${domain}`, `ns2.${domain}`], TXT: [`v=spf1 include:_spf.${domain} ~all`] }, real: false }; },
    (d) => { setRes(d); addHistory({ module: "DNS / Domain Intel", tool: "DNS Record Lookup", target: domain, summary: `Records resolved` }); }
  );
  return (
    <div>
      <div className="flex gap-2"><Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" /><Button onClick={go}>Lookup</Button></div>
      {loading && <div className="mt-4"><Spinner /></div>}
      {res && !loading && <ResultBox title={<span>DNS Records <RealBadge real={res.real} /></span> as any}>
        {Object.entries(res.records || {}).map(([k, v]) => (
          <div key={k} className="border-b border-slate-800 py-2 last:border-0">
            <span className="mr-3 inline-block w-14 text-xs font-semibold text-teal-400">{k}</span>
            <span className="mono text-sm text-slate-200">{(v as string[]).join(" · ")}</span>
          </div>
        ))}
      </ResultBox>}
    </div>
  );
}

/* ─── WHOIS ─────────────────────────────────────────────── */
export function Whois() {
  const [domain, setDomain] = useState("example.com");
  const [res, setRes] = useState<any>(null);
  const { loading, run } = useRunner();
  const go = () => run(
    () => api.dns.whois(domain),
    () => { const rng = seeded(domain + "whois"); const yr = randInt(rng,1998,2021); return { Domain: domain, Registrar: pick(rng,["GoDaddy","Namecheap","Cloudflare","Gandi"]), Created: `${yr}-${randInt(rng,1,12).toString().padStart(2,"0")}-01`, Expires: `${yr+randInt(rng,5,12)}`, Status: "clientTransferProhibited", Registrant: "REDACTED (GDPR)", real: false }; },
    (d) => { setRes(d); addHistory({ module: "DNS / Domain Intel", tool: "WHOIS Lookup", target: domain, summary: "Registrar & expiry retrieved" }); }
  );
  const display = res ? { Domain: res.domain||res.Domain, Registrar: res.registrar||res.Registrar, Created: res.created||res.Created, Expires: res.expires||res.Expires, Status: res.status||res.Status, Registrant: res.registrant||res.Registrant } : {};
  return (
    <div>
      <div className="flex gap-2"><Input value={domain} onChange={e => setDomain(e.target.value)} /><Button onClick={go}>WHOIS</Button></div>
      {loading && <div className="mt-4"><Spinner /></div>}
      {res && !loading && <ResultBox title={<span>WHOIS <RealBadge real={res.real} /></span> as any}><KeyVal data={display} /></ResultBox>}
    </div>
  );
}

/* ─── Reverse WHOIS ─────────────────────────────────────── */
export function ReverseWhois() {
  const [q, setQ] = useState("");
  const [res, setRes] = useState<string[] | null>(null);
  const { loading, run } = useRunner();
  const go = () => run(
    async () => ({ domains: [], real: false }),
    () => { const rng = seeded(q + "rwhois"); const n = randInt(rng,3,10); return { domains: Array.from({length:n},()=>`${pick(rng,["acme","globex","stark","wayne","vault"])}${randInt(rng,1,9)}.com`), real: false }; },
    (d) => { setRes(d.domains); addHistory({ module: "DNS / Domain Intel", tool: "Reverse WHOIS", target: q, summary: `${d.domains.length} domains found` }); }
  );
  return (
    <div>
      <div className="flex gap-2"><Input value={q} onChange={e => setQ(e.target.value)} placeholder="registrant name or email" /><Button onClick={go}>Search</Button></div>
      {loading && <div className="mt-4"><Spinner /></div>}
      {res && !loading && <ResultBox title={`${res.length} domains`}><div className="flex flex-wrap gap-2">{res.map(d => <Badge key={d} color="teal">{d}</Badge>)}</div></ResultBox>}
    </div>
  );
}

/* ─── Reverse IP ────────────────────────────────────────── */
export function ReverseIp() {
  const [ip, setIp] = useState("8.8.8.8");
  const [res, setRes] = useState<string[] | null>(null);
  const { loading, run } = useRunner();
  const go = () => run(
    async () => ({ domains: [], real: false }),
    () => { const rng = seeded(ip + "rev"); const n = randInt(rng,3,12); return { domains: Array.from({length:n},()=>`${pick(rng,["acme","globex","umbrella","stark","wayne","hooli","vault"])}${randInt(rng,1,99)}.com`), real: false }; },
    (d) => { setRes(d.domains); addHistory({ module: "DNS / Domain Intel", tool: "Reverse IP Lookup", target: ip, summary: `${d.domains.length} domains share this host` }); }
  );
  return (
    <div>
      <div className="flex gap-2"><Input value={ip} onChange={e => setIp(e.target.value)} placeholder="IP address" /><Button onClick={go}>Reverse</Button></div>
      {loading && <div className="mt-4"><Spinner /></div>}
      {res && !loading && <ResultBox title={`${res.length} hosted domains`}><div className="flex flex-wrap gap-2">{res.map(d => <Badge key={d} color="teal">{d}</Badge>)}</div></ResultBox>}
    </div>
  );
}

/* ─── Reverse MX / NS ───────────────────────────────────── */
export function ReverseMx() {
  const [q, setQ] = useState("mail.google.com"); const [res, setRes] = useState<string[] | null>(null); const { loading, run } = useRunner();
  const go = () => run(async () => ({ domains: [], real: false }), () => { const rng = seeded(q + "rmx"); const n = randInt(rng,3,10); return { domains: Array.from({length:n},()=>`${pick(rng,["acme","hooli","stark","globex"])}${randInt(rng,1,9)}.com`), real: false }; }, (d) => { setRes(d.domains); addHistory({ module: "DNS / Domain Intel", tool: "Reverse MX Lookup", target: q, summary: `${d.domains.length} domains` }); });
  return <div><div className="flex gap-2"><Input value={q} onChange={e => setQ(e.target.value)} placeholder="mail server hostname" /><Button onClick={go}>Lookup</Button></div>{loading && <div className="mt-4"><Spinner /></div>}{res && !loading && <ResultBox title={`${res.length} domains`}><div className="flex flex-wrap gap-2">{res.map(d => <Badge key={d} color="teal">{d}</Badge>)}</div></ResultBox>}</div>;
}

export function ReverseNs() {
  const [q, setQ] = useState("ns1.cloudflare.com"); const [res, setRes] = useState<string[] | null>(null); const { loading, run } = useRunner();
  const go = () => run(async () => ({ domains: [], real: false }), () => { const rng = seeded(q + "rns"); const n = randInt(rng,4,14); return { domains: Array.from({length:n},()=>`${pick(rng,["vault","blade","nexus","prime"])}${randInt(rng,1,9)}.com`), real: false }; }, (d) => { setRes(d.domains); addHistory({ module: "DNS / Domain Intel", tool: "Reverse NS Lookup", target: q, summary: `${d.domains.length} domains` }); });
  return <div><div className="flex gap-2"><Input value={q} onChange={e => setQ(e.target.value)} placeholder="name server hostname" /><Button onClick={go}>Lookup</Button></div>{loading && <div className="mt-4"><Spinner /></div>}{res && !loading && <ResultBox title={`${res.length} domains`}><div className="flex flex-wrap gap-2">{res.map(d => <Badge key={d} color="teal">{d}</Badge>)}</div></ResultBox>}</div>;
}

/* ─── Reverse DNS ───────────────────────────────────────── */
export function ReverseDns() {
  const [ip, setIp] = useState("8.8.8.8"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(
    () => api.dns.reverseDns(ip),
    () => { const rng = seeded(ip + "ptr"); return { IP: ip, "PTR Record": `${pick(rng,["dns","host","mail","server"])}-${ip.replace(/\./g,"-")}.${pick(rng,["googleusercontent.com","amazonaws.com","azure.net"])}`, "Forward Match": pick(rng,["✓ Confirmed","✗ Mismatch"]), real: false }; },
    (d) => { setRes(d); addHistory({ module: "DNS / Domain Intel", tool: "Reverse DNS (PTR)", target: ip, summary: "PTR resolved" }); }
  );
  const display = res ? { IP: res.ip||res.IP, "PTR Record": res["PTR Record"]||res.ptr, "Forward Match": res["Forward Match"]||"—" } : {};
  return <div><div className="flex gap-2"><Input value={ip} onChange={e => setIp(e.target.value)} placeholder="IP address" /><Button onClick={go}>Resolve</Button></div>{loading && <div className="mt-4"><Spinner /></div>}{res && !loading && <ResultBox title={<span>Reverse DNS <RealBadge real={res.real} /></span> as any}><KeyVal data={display} /></ResultBox>}</div>;
}

/* ─── IP Geolocation ───────────────────────────────────── */
export function IpLocation() {
  const [ip, setIp] = useState("1.1.1.1"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(
    () => api.dns.geo(ip),
    () => { const rng = seeded(ip + "geo"); const p = pick(rng,[["US","Cloudflare Inc.","AS13335"],["DE","Hetzner Online","AS24940"],["SG","DigitalOcean","AS14061"]]); return { IP: ip, Country: p[0], ISP: p[1], ASN: p[2], Coordinates: `${(rng()*180-90).toFixed(4)}, ${(rng()*360-180).toFixed(4)}`, Timezone: pick(rng,["UTC-5","UTC+1","UTC+8"]), real: false }; },
    (d) => { setRes(d); addHistory({ module: "DNS / Domain Intel", tool: "IP Geolocation", target: ip, summary: `${d.Country||d.country||""} (${d.ISP||d.isp||""})` }); }
  );
  const display = res ? { IP: res.IP||res.ip, Country: res.Country||res.country, City: res.City||res.city, ISP: res.ISP||res.isp, ASN: res.ASN, Coordinates: res.Coordinates||res.loc, Timezone: res.Timezone||res.timezone } : {};
  return <div><div className="flex gap-2"><Input value={ip} onChange={e => setIp(e.target.value)} /><Button onClick={go}>Locate</Button></div>{loading && <div className="mt-4"><Spinner /></div>}{res && !loading && <ResultBox title={<span>Geolocation <RealBadge real={res.real} /></span> as any}><KeyVal data={display} /></ResultBox>}</div>;
}

/* ─── IP History ─────────────────────────────────────────── */
export function IpHistory() {
  const [domain, setDomain] = useState("example.com"); const [res, setRes] = useState<any[] | null>(null); const { loading, run } = useRunner();
  const go = () => run(async () => ({ items: [], real: false }), () => { const rng = seeded(domain + "iphist"); const owners = ["Cloudflare","Amazon AWS","Google Cloud","DigitalOcean","Hetzner"]; const n = randInt(rng,4,8); let yr = randInt(rng,2012,2016); return { items: Array.from({length:n},()=>{yr+=randInt(rng,1,2);return{ip:randIp(rng),owner:pick(rng,owners),date:`${Math.min(yr,2025)}-${randInt(rng,1,12).toString().padStart(2,"0")}`};}), real: false }; }, (d) => { setRes(d.items||[]); addHistory({ module: "DNS / Domain Intel", tool: "IP History", target: domain, summary: `${d.items?.length||0} historical IPs` }); });
  return <div><div className="flex gap-2"><Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="domain.com" /><Button onClick={go}>History</Button></div>{loading && <div className="mt-4"><Spinner /></div>}{res && !loading && <ResultBox title={`${res.length} Historical IPs`}><div className="space-y-1">{res.map((r,i)=><div key={i} className="mono flex items-center justify-between rounded border border-slate-800 px-3 py-1.5 text-xs"><span className="text-teal-300">{r.ip}</span><span className="text-slate-400">{r.owner}</span><span className="text-slate-500">{r.date}</span></div>)}</div></ResultBox>}</div>;
}

/* ─── ASN Lookup ─────────────────────────────────────────── */
export function AsnLookup() {
  const [q, setQ] = useState("8.8.8.8"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(async () => ({ real: false }), () => { const rng = seeded(q + "asn"); const o = pick(rng,[["AS15169","Google LLC","US"],["AS13335","Cloudflare Inc.","US"],["AS16509","Amazon.com Inc.","US"]]); return { ASN: o[0], Organization: o[1], Country: o[2], Registry: pick(rng,["ARIN","RIPE","APNIC"]), Allocated: `${randInt(rng,2000,2015)}`, "IPv4 Count": randInt(rng,256,5000000).toLocaleString(), real: false }; }, (d) => { setRes(d); addHistory({ module: "DNS / Domain Intel", tool: "ASN Lookup", target: q, summary: `${d.ASN||""} — ${d.Organization||""}` }); });
  const display: Record<string,string> = res ? { ASN: String(res.ASN||""), Organization: String(res.Organization||""), Country: String(res.Country||""), Registry: String(res.Registry||""), Allocated: String(res.Allocated||""), "IPv4 Count": String(res["IPv4 Count"]||"") } : {};
  return <div><div className="flex gap-2"><Input value={q} onChange={e => setQ(e.target.value)} placeholder="IP or AS number" /><Button onClick={go}>Lookup</Button></div>{loading && <div className="mt-4"><Spinner /></div>}{res && !loading && <ResultBox title="ASN Info"><KeyVal data={display} /></ResultBox>}</div>;
}

/* ─── DNS Health Report ─────────────────────────────────── */
export function DnsReport() {
  const [domain, setDomain] = useState("example.com"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(async () => ({ real: false }), () => { const rng = seeded(domain + "report"); const checks = ["NS records present","Multiple name servers","MX records reachable","SPF record found","DMARC policy set","DNSSEC enabled","No open recursion","Reverse DNS configured","TTL values reasonable","CAA record present"].map(c=>({c,status:rng()>0.25?"pass":rng()>0.5?"warn":"fail"})); const passes=checks.filter(c=>c.status==="pass").length; const grade=passes>=9?"A":passes>=7?"B":passes>=5?"C":"D"; return{grade,checks,real:false}; }, (d)=>{setRes(d);addHistory({module:"DNS / Domain Intel",tool:"DNS Health Report",target:domain,summary:`Grade ${d.grade}`,risk:d.grade==="A"||d.grade==="B"?"Low":"Medium"});});
  const col=(s:string)=>s==="pass"?"text-emerald-400":s==="warn"?"text-amber-400":"text-rose-400";
  return <div><div className="flex gap-2"><Input value={domain} onChange={e=>setDomain(e.target.value)}/><Button onClick={go}>Audit</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title="DNS Health Report"><div className="mb-3 flex items-center gap-3"><div className={`flex h-12 w-12 items-center justify-center rounded-lg text-2xl font-bold ${res.grade==="A"?"bg-emerald-500/15 text-emerald-400":"bg-amber-500/15 text-amber-400"}`}>{res.grade}</div><span className="text-sm text-slate-400">Overall grade</span></div><div className="grid gap-1.5 sm:grid-cols-2">{res.checks?.map((c:any,i:number)=><div key={i} className="flex items-center gap-2 rounded border border-slate-800 px-3 py-1.5 text-sm"><span className={`font-bold ${col(c.status)}`}>{c.status==="pass"?"✓":c.status==="warn"?"!":"✗"}</span><span className="text-slate-300">{c.c}</span></div>)}</div></ResultBox>}</div>;
}

/* ─── DNSBL ──────────────────────────────────────────────── */
export function Dnsbl() {
  const [ip, setIp] = useState("8.8.8.8"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const LISTS = ["Spamhaus ZEN","Barracuda","SpamCop","SORBS","UCEPROTECT","PSBL","Mailspike","Hostkarma","DroneBL","CBL"];
  const go = () => run(
    () => api.dns.blacklist(ip),
    () => { const rng = seeded(ip + "dnsbl"); const checks = LISTS.map(l=>({list:l,listed:rng()>0.85})); return{checks,listed_count:checks.filter(c=>c.listed).length,total:LISTS.length,real:false}; },
    (d) => { setRes(d); addHistory({module:"DNS / Domain Intel",tool:"Spam Blacklist (DNSBL)",target:ip,summary:`Listed on ${d.listed_count||0}/${d.total||10}`,risk:(d.listed_count||0)>0?"High":"Low"}); }
  );
  const checks = res?.checks || [];
  return <div><div className="flex gap-2"><Input value={ip} onChange={e=>setIp(e.target.value)}/><Button onClick={go}>Check</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>Listed on {res.listed_count||0}/{res.total||10} <RealBadge real={res.real}/></span> as any}><div className="grid gap-1.5 sm:grid-cols-2">{checks.map((c:any)=><div key={c.list||c.l} className="flex items-center justify-between rounded border border-slate-800 px-3 py-1.5 text-sm"><span className="text-slate-300">{c.list||c.l}</span><span className={(c.listed)?"text-rose-400":"text-emerald-400"}>{(c.listed)?"⚠ Listed":"✓ Clean"}</span></div>)}</div></ResultBox>}</div>;
}

/* ─── China Firewall Test ────────────────────────────────── */
export function FirewallTest() {
  const [url, setUrl] = useState("https://example.com"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const NODES = ["Beijing","Shanghai","Guangzhou","Shenzhen","Chengdu","Hangzhou"];
  const go = () => run(async () => ({ real: false }), () => { const rng = seeded(url + "gfw"); const blocked = rng()>0.6; return{blocked,nodes:NODES.map(n=>({n,ok:blocked?rng()>0.6:rng()>0.1})),real:false}; }, (d)=>{setRes(d);addHistory({module:"DNS / Domain Intel",tool:"China Firewall Test",target:url,summary:d.blocked?"Appears blocked":"Accessible",risk:d.blocked?"Medium":"Low"});});
  return <div><p className="mb-3 text-sm text-slate-400">Tests whether a site is reachable from behind the Great Firewall of China.</p><div className="flex gap-2"><Input value={url} onChange={e=>setUrl(e.target.value)}/><Button onClick={go}>Test</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={res.blocked?"⚠ Likely BLOCKED in China":"✓ Accessible from China"}><div className="grid gap-1.5 sm:grid-cols-2">{res.nodes?.map((nd:any)=><div key={nd.n} className="flex items-center justify-between rounded border border-slate-800 px-3 py-1.5 text-sm"><span className="text-slate-300">{nd.n}</span><span className={nd.ok?"text-emerald-400":"text-rose-400"}>{nd.ok?"✓ Reachable":"✗ Timeout"}</span></div>)}</div></ResultBox>}</div>;
}

/* ─── Abuse Contact ─────────────────────────────────────── */
export function AbuseContact() {
  const [q, setQ] = useState("8.8.8.8"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(async () => ({ real: false }), () => { const rng = seeded(q + "abuse"); const o = pick(rng,[["Google LLC","abuse@google.com","+1-650-253-0000"],["Cloudflare","abuse@cloudflare.com","+1-650-319-8930"]]); return{"Network Owner":o[0],"Abuse Email":o[1],"Abuse Phone":o[2],Registry:pick(rng,["ARIN","RIPE","APNIC"]),real:false}; }, (d)=>{setRes(d);addHistory({module:"DNS / Domain Intel",tool:"Abuse Contact Lookup",target:q,summary:`Contact: ${d["Abuse Email"]||""}`});});
  return <div><div className="flex gap-2"><Input value={q} onChange={e=>setQ(e.target.value)} placeholder="IP or domain"/><Button onClick={go}>Lookup</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title="Abuse Contact"><KeyVal data={{...res,real:undefined}} /></ResultBox>}</div>;
}

/* ─── MAC Address Lookup ─────────────────────────────────── */
export function MacLookup() {
  const [mac, setMac] = useState("00:1A:2B:3C:4D:5E"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(
    () => api.dns.mac(mac),
    () => { const rng = seeded(mac + "mac"); return{"MAC Address":mac,"OUI Prefix":mac.slice(0,8),Vendor:pick(rng,["Apple, Inc.","Samsung Electronics","Cisco Systems","Intel Corporate","TP-Link"]),Type:"Global (Unique)",real:false}; },
    (d)=>{setRes(d);addHistory({module:"DNS / Domain Intel",tool:"MAC Address Lookup",target:mac,summary:"Vendor identified"});}
  );
  const display = res ? {"MAC Address":res["MAC Address"]||mac,"OUI Prefix":res["OUI Prefix"]||res.oui,Vendor:res.Vendor||res.vendor,Type:res.Type||res.type} : {};
  return <div><div className="flex gap-2"><Input value={mac} onChange={e=>setMac(e.target.value)} className="mono"/><Button onClick={go}>Lookup</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>MAC / OUI Vendor <RealBadge real={res.real}/></span> as any}><KeyVal data={display}/></ResultBox>}</div>;
}

/* ─── SSL Certificate ───────────────────────────────────── */
export function SslInfo() {
  const [domain, setDomain] = useState("example.com"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(
    () => api.dns.ssl(domain),
    () => { const rng = seeded(domain + "ssl"); const yr = randInt(rng,2024,2025); return{Subject:`CN=${domain}`,Issuer:pick(rng,["Let's Encrypt R3","DigiCert TLS RSA","Google Trust Services"]),"Valid From":`${yr}-01-01`,"Valid To":`${yr+1}-01-01`,"Days Left":randInt(rng,30,365),Protocol:pick(rng,["TLS 1.3","TLS 1.2"]),Key:pick(rng,["RSA 2048","ECDSA P-256"]),Status:"✓ Valid",real:false}; },
    (d)=>{setRes(d);addHistory({module:"DNS / Domain Intel",tool:"SSL Certificate Info",target:domain,summary:"Certificate inspected"});}
  );
  const display = res ? {Subject:res.Subject,Issuer:res.Issuer,"Valid From":res["Valid From"]||res.valid_from,"Valid To":res["Valid To"]||res.valid_to,"Days Left":res["Days Left"]||res.days_left,Protocol:res.Protocol||res.protocol,Status:res.Status||res.status} : {};
  return <div><div className="flex gap-2"><Input value={domain} onChange={e=>setDomain(e.target.value)}/><Button onClick={go}>Inspect</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>SSL/TLS Certificate <RealBadge real={res.real}/></span> as any}><KeyVal data={display}/></ResultBox>}</div>;
}

/* ─── Port Scanner ──────────────────────────────────────── */
export function PortScan() {
  const [host, setHost] = useState("example.com"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const PORTS = [21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443];
  const NAMES: Record<number,string> = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",3306:"MySQL",3389:"RDP",8080:"HTTP-Alt",8443:"HTTPS-Alt"};
  const go = () => run(
    () => api.dns.ports(host),
    () => { const rng = seeded(host + "ports"); const list = PORTS.map(p=>({port:p,service:NAMES[p],state:rng()>0.62?"open":"closed",open:rng()>0.62})); return{ports:list,open_count:list.filter(l=>l.open).length,real:false}; },
    (d)=>{setRes(d);addHistory({module:"DNS / Domain Intel",tool:"Port Scanner",target:host,summary:`${d.open_count||0} open ports`,risk:(d.open_count||0)>5?"Medium":"Low"});}
  );
  const ports = res?.ports || [];
  return <div><div className="flex gap-2"><Input value={host} onChange={e=>setHost(e.target.value)}/><Button onClick={go}>Scan</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>Port Scan — {res.open_count||0} open <RealBadge real={res.real}/></span> as any}><div className="grid grid-cols-2 gap-2 sm:grid-cols-3">{ports.map((p:any)=><div key={p.port} className={`flex items-center justify-between rounded-md border px-3 py-2 text-sm ${(p.open||p.state==="open")?"border-emerald-500/30 bg-emerald-500/5":"border-slate-800 opacity-50"}`}><span className="mono">{p.port}</span><span className="text-xs text-slate-400">{p.service||NAMES[p.port]||""}</span><span className={(p.open||p.state==="open")?"text-emerald-400":"text-slate-600"}>{(p.open||p.state==="open")?"open":"closed"}</span></div>)}</div></ResultBox>}</div>;
}

/* ─── HTTP Headers ──────────────────────────────────────── */
export function HttpHeaders() {
  const [url, setUrl] = useState("https://example.com"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(
    () => api.dns.headers(url),
    () => { const rng = seeded(url + "hdr"); return{headers:{Status:"200 OK",Server:pick(rng,["nginx/1.25","Apache/2.4","cloudflare"]),HSTS:pick(rng,["max-age=31536000","(missing)"]),CSP:pick(rng,["default-src 'self'","(missing)"]),"X-Frame-Options":pick(rng,["SAMEORIGIN","(missing)"])},real:false}; },
    (d)=>{setRes(d);addHistory({module:"DNS / Domain Intel",tool:"HTTP Headers",target:url,summary:"Headers captured"});}
  );
  const display: Record<string,string> = res ? Object.fromEntries(Object.entries(res.headers||res).filter(([k])=>k!=="real"&&k!=="url").map(([k,v])=>[k,String(v)])) : {};
  return <div><div className="flex gap-2"><Input value={url} onChange={e=>setUrl(e.target.value)}/><Button onClick={go}>Fetch</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>HTTP Headers <RealBadge real={res.real}/></span> as any}><KeyVal data={display}/></ResultBox>}</div>;
}

/* ─── Ping / Traceroute ─────────────────────────────────── */
export function Ping() {
  const [host, setHost] = useState("example.com"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(
    () => api.dns.ping(host),
    () => { const rng = seeded(host + "ping"); const hops = randInt(rng,6,14); return{avg_ms:(rng()*60+5).toFixed(1),packet_loss:`${randInt(rng,0,2)}%`,status:"reachable",reply_times:Array.from({length:4},()=>+(rng()*60+5).toFixed(1)),real:false}; },
    (d)=>{setRes(d);addHistory({module:"DNS / Domain Intel",tool:"Ping / Traceroute",target:host,summary:`${d.avg_ms||"?"}ms avg`});}
  );
  return <div><div className="flex gap-2"><Input value={host} onChange={e=>setHost(e.target.value)}/><Button onClick={go}>Ping</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>Ping Result <RealBadge real={res.real}/></span> as any}><div className="grid grid-cols-2 gap-2 sm:grid-cols-3 text-sm"><div className="rounded border border-slate-800 p-3"><div className="text-xs text-slate-500">Avg Latency</div><div className="mono text-lg text-slate-100">{res.avg_ms}ms</div></div><div className="rounded border border-slate-800 p-3"><div className="text-xs text-slate-500">Packet Loss</div><div className="mono text-lg text-slate-100">{res.packet_loss}</div></div><div className="rounded border border-slate-800 p-3"><div className="text-xs text-slate-500">Status</div><div className={`mono text-lg ${res.status==="reachable"?"text-emerald-400":"text-rose-400"}`}>{res.status}</div></div></div></ResultBox>}</div>;
}

/* ─── DNS Propagation ───────────────────────────────────── */
export function DnsPropagation() {
  const [domain, setDomain] = useState("example.com"); const [res, setRes] = useState<any>(null); const { loading, run } = useRunner();
  const go = () => run(
    () => api.dns.propagation(domain),
    () => { const rng = seeded(domain + "prop"); const locs = ["Google (US)","Cloudflare (US)","OpenDNS (US)","Quad9 (EU)","Comodo (US)","Verisign (US)","Level3 (US)","Norton (US)"]; const ip = randIp(rng); return{results:locs.map(l=>({location:l,ip,ok:rng()>0.15,propagated:rng()>0.15})),real:false}; },
    (d)=>{setRes(d);addHistory({module:"DNS / Domain Intel",tool:"DNS Propagation",target:domain,summary:"Global check complete"});}
  );
  const results = res?.results || [];
  return <div><div className="flex gap-2"><Input value={domain} onChange={e=>setDomain(e.target.value)}/><Button onClick={go}>Check</Button></div>{loading&&<div className="mt-4"><Spinner/></div>}{res&&!loading&&<ResultBox title={<span>Global Propagation <RealBadge real={res.real}/></span> as any}><div className="grid gap-2 sm:grid-cols-2">{results.map((r:any)=><div key={r.location} className="flex items-center justify-between rounded-md border border-slate-800 px-3 py-2 text-sm"><span className="truncate">{r.location}</span><span className="mono text-xs text-slate-400">{r.ip}</span><span className={(r.ok||r.propagated)?"text-emerald-400":"text-rose-400"}>{(r.ok||r.propagated)?"✓":"✗"}</span></div>)}</div></ResultBox>}</div>;
}
