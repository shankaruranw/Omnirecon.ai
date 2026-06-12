import { useState } from "react";
import * as Icons from "lucide-react";
import { Button, Input, Badge } from "../lib/ui";
import { seeded, pick, randInt, randIp, delay } from "../lib/sim";
import { addHistory } from "../lib/history";

type StepStatus = "pending" | "running" | "done";
type Step = { key: string; label: string; icon: string; status: StepStatus; summary?: string };

const STEP_DEFS = [
  { key: "dns", label: "DNS Analysis", icon: "Globe" },
  { key: "whois", label: "WHOIS Analysis", icon: "FileText" },
  { key: "subdomains", label: "Subdomain Enumeration", icon: "Network" },
  { key: "ssl", label: "SSL Review", icon: "ShieldCheck" },
  { key: "headers", label: "Header Analysis", icon: "ListTree" },
  { key: "waf", label: "WAF Detection", icon: "Shield" },
  { key: "reputation", label: "Reputation Checks", icon: "Gauge" },
  { key: "tech", label: "Technology Detection", icon: "Cpu" },
  { key: "scoring", label: "AI Risk Scoring", icon: "BrainCircuit" },
  { key: "report", label: "AI Security Report", icon: "FileCheck2" },
];

function IconC({ name, className }: { name: string; className?: string }) {
  const C = (Icons as any)[name] || Icons.Circle; return <C className={className} />;
}

function computeStep(key: string, d: string, rng: () => number, data: any): string {
  if (key === "dns") { data.dns = { a: [randIp(rng), randIp(rng)], mx: `mail.${d}`, spf: rng() > 0.4, dmarc: rng() > 0.5 }; return `${data.dns.a.length} A records · SPF ${data.dns.spf ? "✓" : "✗"}`; }
  if (key === "whois") { const yr = randInt(rng, 1998, 2022); data.whois = { registrar: pick(rng, ["GoDaddy", "Cloudflare", "Namecheap"]), age: 2026 - yr }; return `${data.whois.registrar} · ${data.whois.age} yrs old`; }
  if (key === "subdomains") { const subs = ["www", "mail", "api", "dev", "admin", "vpn", "cdn", "blog", "shop", "git", "staging", "test"].filter(() => rng() > 0.5); data.subdomains = subs.map(s => `${s}.${d}`); return `${subs.length} subdomains discovered`; }
  if (key === "ssl") { const valid = rng() > 0.2; data.ssl = { issuer: pick(rng, ["Let's Encrypt", "DigiCert", "Google Trust"]), tls: pick(rng, ["TLS 1.3", "TLS 1.2"]), valid, expiresDays: randInt(rng, valid ? 20 : -10, 360) }; return `${data.ssl.issuer} · ${data.ssl.valid ? `${data.ssl.expiresDays}d left` : "expired"}`; }
  if (key === "headers") { const present = ["HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"].filter(() => rng() > 0.45); data.headers = { present, missing: ["HSTS", "CSP", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"].filter(h => !present.includes(h)), server: pick(rng, ["nginx", "Apache", "cloudflare", "IIS"]) }; return `${present.length}/5 security headers`; }
  if (key === "waf") { const waf = pick(rng, ["Cloudflare", "AWS WAF", "Akamai", "Sucuri", "None detected"]); data.waf = { name: waf, protected: waf !== "None detected" }; return data.waf.protected ? `Protected by ${waf}` : "No WAF detected"; }
  if (key === "reputation") { const bl = randInt(rng, 0, 4); data.reputation = { blacklists: bl, malware: rng() > 0.85 }; return `${bl} blacklist hits`; }
  if (key === "tech") { const stack = [pick(rng, ["WordPress", "React", "Next.js", "Laravel", "Django"]), pick(rng, ["PHP", "Node.js", "Python", "Ruby"]), pick(rng, ["MySQL", "PostgreSQL", "MongoDB"])]; data.tech = stack; return stack.slice(0, 2).join(" · "); }
  if (key === "scoring") { let score = 20; if (!data.dns?.spf) score += 8; if (!data.dns?.dmarc) score += 8; if (data.headers?.missing?.length) score += data.headers.missing.length * 4; if (!data.ssl?.valid) score += 18; if (!data.waf?.protected) score += 14; score += (data.reputation?.blacklists || 0) * 7; if (data.reputation?.malware) score += 25; score = Math.min(99, Math.max(5, score + randInt(rng, -5, 5))); data.score = score; data.level = score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 40 ? "Medium" : "Low"; return `Score: ${score}/100 (${data.level})`; }
  if (key === "report") {
    const findings: any[] = [];
    if (!data.dns?.spf) findings.push({ title: "SPF record missing", sev: "Medium" });
    if (!data.dns?.dmarc) findings.push({ title: "No DMARC policy", sev: "Medium" });
    data.headers?.missing?.forEach((h: string) => findings.push({ title: `Missing header: ${h}`, sev: "Low" }));
    if (!data.ssl?.valid) findings.push({ title: "SSL certificate invalid/expired", sev: "High" });
    if (!data.waf?.protected) findings.push({ title: "No WAF detected", sev: "High" });
    if ((data.reputation?.blacklists || 0) > 0) findings.push({ title: `IP on ${data.reputation.blacklists} blacklist(s)`, sev: "High" });
    if (data.reputation?.malware) findings.push({ title: "Domain flagged for malware", sev: "Critical" });
    if (!findings.length) findings.push({ title: "No significant issues detected", sev: "Info" });
    const recs = ["Publish SPF and DMARC records", "Add missing HTTP security headers", "Renew/validate TLS certificate", "Deploy a Web Application Firewall", "Remove non-production subdomains"].filter(() => rng() > 0.35).slice(0, 4);
    if (!recs.length) recs.push("Enable WAF and monitor subdomains");
    data.report = { score: data.score, level: data.level, findings, recs, summary: `Automated reconnaissance of ${d} completed. Risk: ${data.level} (${data.score}/100). ${findings.length} issue(s) identified.` };
    return `${findings.length} findings · ${recs.length} recommendations`;
  }
  return "";
}

export function AiReconWorkspace() {
  const [domain, setDomain] = useState(""); const [steps, setSteps] = useState<Step[]>([]); const [running, setRunning] = useState(false); const [report, setReport] = useState<any>(null);
  const run = async () => {
    const d = domain.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, ""); if (!d) return;
    setRunning(true); setReport(null);
    const rng = seeded(d + "workspace");
    setSteps(STEP_DEFS.map(s => ({ ...s, status: "pending" })));
    const data: any = { domain: d };
    for (let i = 0; i < STEP_DEFS.length; i++) {
      setSteps(p => p.map((s, idx) => idx === i ? { ...s, status: "running" } : s));
      await delay(650 + Math.random() * 500);
      const summary = computeStep(STEP_DEFS[i].key, d, rng, data);
      setSteps(p => p.map((s, idx) => idx === i ? { ...s, status: "done", summary } : s));
    }
    setReport(data.report); setRunning(false);
    addHistory({ module: "AI Recon Workspace", tool: "Automated Recon", target: d, summary: `Risk ${data.report.score}/100 · ${data.report.findings.length} findings`, risk: data.report.level });
  };
  const progress = steps.length ? Math.round((steps.filter(s => s.status === "done").length / steps.length) * 100) : 0;
  const color = (l: string) => l === "Critical" || l === "High" ? "#f43f5e" : l === "Medium" ? "#f59e0b" : "#10b981";
  const sevColor = (s: string) => s === "Critical" || s === "High" ? "rose" : s === "Medium" ? "amber" : "emerald";
  return (
    <div>
      <div className="rounded-xl border border-teal-500/30 bg-gradient-to-br from-teal-500/10 via-slate-900/40 to-indigo-500/10 p-5">
        <div className="flex items-center gap-2 text-teal-300"><Icons.Sparkles className="h-5 w-5" /><span className="text-sm font-semibold uppercase tracking-wider">One-Click Automated Recon</span></div>
        <p className="mt-1 text-sm text-slate-400">Enter a domain. The AI engine runs the full 10-stage reconnaissance pipeline then scores risk and writes a security report.</p>
        <div className="mt-4 flex flex-col gap-2 sm:flex-row">
          <Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" onKeyDown={e => e.key === "Enter" && !running && run()} className="flex-1" />
          <Button onClick={run} disabled={running}>{running ? <><div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950/30 border-t-slate-950" />Scanning…</> : <><Icons.Play className="h-4 w-4" />Run Full Recon</>}</Button>
        </div>
      </div>
      {steps.length > 0 && <div className="mt-5">
        <div className="mb-3 flex items-center justify-between text-xs text-slate-400"><span>Pipeline progress</span><span className="mono">{progress}%</span></div>
        <div className="mb-5 h-1.5 w-full overflow-hidden rounded-full bg-slate-800"><div className="h-full rounded-full bg-teal-500 transition-all duration-300" style={{ width: `${progress}%` }} /></div>
        <div className="space-y-2">{steps.map(s => (
          <div key={s.key} className={`flex items-center gap-3 rounded-lg border px-4 py-3 transition ${s.status === "running" ? "border-teal-500/50 bg-teal-500/5" : s.status === "done" ? "border-slate-800 bg-slate-900/40" : "border-slate-800/60 opacity-50"}`}>
            <div className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${s.status === "done" ? "bg-emerald-500/15 text-emerald-400" : "bg-slate-800 text-teal-400"}`}>{s.status === "running" ? <div className="h-4 w-4 animate-spin rounded-full border-2 border-teal-500/30 border-t-teal-400" /> : s.status === "done" ? <Icons.Check className="h-4 w-4" /> : <IconC name={s.icon} className="h-4 w-4" />}</div>
            <div className="min-w-0 flex-1"><div className="text-sm font-medium text-slate-100">{s.label}</div>{s.summary && <div className="truncate text-xs text-slate-500">{s.summary}</div>}</div>
            {s.status === "done" && <Badge color="emerald">done</Badge>}{s.status === "running" && <Badge color="teal">running</Badge>}
          </div>
        ))}</div>
      </div>}
      {report && <div className="fade-in mt-6 rounded-xl border border-slate-800 bg-slate-950/60 p-5">
        <div className="mb-4 flex items-center justify-between"><div className="flex items-center gap-2 text-slate-100"><Icons.FileCheck2 className="h-5 w-5 text-teal-400" /><h3 className="font-bold">AI Security Report</h3></div><button onClick={() => navigator.clipboard?.writeText(`AI SECURITY REPORT\nRisk: ${report.score}/100 (${report.level})\n\n${report.summary}\n\nFINDINGS:\n${report.findings.map((f: any) => `- [${f.sev}] ${f.title}`).join("\n")}\n\nRECOMMENDATIONS:\n${report.recs.map((r: string) => `- ${r}`).join("\n")}`)} className="rounded-md border border-slate-700 px-3 py-1.5 text-xs text-slate-300 hover:border-teal-500 hover:text-teal-300">Copy Report</button></div>
        <div className="mb-5 flex items-center gap-5">
          <div className="relative h-28 w-28"><svg viewBox="0 0 100 100" className="h-28 w-28 -rotate-90"><circle cx="50" cy="50" r="42" fill="none" stroke="#1e293b" strokeWidth="10" /><circle cx="50" cy="50" r="42" fill="none" stroke={color(report.level)} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${(report.score / 100) * 264} 264`} /></svg><div className="absolute inset-0 flex flex-col items-center justify-center"><span className="text-3xl font-bold" style={{ color: color(report.level) }}>{report.score}</span><span className="text-[10px] text-slate-500">/100</span></div></div>
          <div><div className="text-xs uppercase tracking-wider text-slate-500">Overall Risk</div><div className="text-2xl font-bold" style={{ color: color(report.level) }}>{report.level}</div><p className="mt-2 max-w-xl text-sm leading-relaxed text-slate-400">{report.summary}</p></div>
        </div>
        <div className="mb-5"><h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Findings ({report.findings.length})</h4><div className="space-y-2">{report.findings.map((f: any, i: number) => <div key={i} className="flex items-center justify-between gap-2 rounded-md border border-slate-800 px-3 py-2 text-sm"><span className="text-slate-200">{f.title}</span><Badge color={sevColor(f.sev) as any}>{f.sev}</Badge></div>)}</div></div>
        <div><h4 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">AI Recommendations</h4><ul className="space-y-1.5 text-sm text-slate-300">{report.recs.map((r: string, i: number) => <li key={i} className="flex gap-2"><span className="text-teal-400">✓</span>{r}</li>)}</ul></div>
      </div>}
    </div>
  );
}
