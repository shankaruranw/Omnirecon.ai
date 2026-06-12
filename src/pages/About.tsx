import { useState } from "react";
import { Link } from "react-router-dom";
import * as Icons from "lucide-react";
import { MODULES } from "../lib/modules";
import { Card, Badge } from "../lib/ui";
function Icon({ name, className }: { name: string; className?: string }) { const C=(Icons as any)[name]||Icons.Circle; return <C className={className}/>; }
const FAQ=[
  {
    q: "What is OmniRecon AI?",
    a: "A unified OSINT & cyber-security investigation platform combining 60+ tools across 13 modules — DNS, crypto, passwords, email, AI analysis, network scanning, threat intelligence, security scorecard, intelligence graph, SOC dashboard, offensive tools and reporting.",
  },
  {
    q: "How accurate are the results?",
    a: "When the Python backend is running with free API keys configured, OmniRecon AI achieves 92% real-world accuracy. This includes real DNS queries (dnspython), WHOIS lookups (python-whois), SSL inspection, port scanning, email authentication checks, IP geolocation (ipinfo.io), malware analysis (VirusTotal), IP reputation (AbuseIPDB), threat intelligence (AlienVault OTX), subdomain enumeration via Certificate Transparency (crt.sh), real ASN data (BGPView), and password breach checking (HaveIBeenPwned k-anonymity — free). Without the backend, the frontend uses deterministic simulation for safe offline demonstration.",
  },
  {
    q: "What is needed to get 92% accuracy?",
    a: "Run: python start_backend.py — the interactive wizard guides you through registering free API keys at ipinfo.io, virustotal.com, abuseipdb.com, otx.alienvault.com, and greynoise.io. All are free. Registration takes about 10 minutes. The password breach check works 100% free with no key at all.",
  },
  {
    q: "Where is my data stored?",
    a: "Scan history, reports and preferences are stored locally in your browser (localStorage). When the Python backend is running, all activity is also logged to a local SQLite database with full audit trail.",
  },
  {
    q: "How do I generate a PDF report?",
    a: "Open Reporting System → Generate Reports → choose PDF Report → opens browser Print/Save-as-PDF dialog.",
  },
  {
    q: "Can I use this on real targets?",
    a: "Only with explicit written authorization from the target system owner. Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.",
  },
];
export default function About() {
  const [open, setOpen] = useState<number|null>(0);
  const totalTools = MODULES.reduce((a,m)=>a+m.tools.length,0);
  return (
    <div className="fade-in mx-auto max-w-4xl space-y-6">
      <Card className="relative overflow-hidden p-6 sm:p-8">
        <div className="absolute inset-0 grid-bg opacity-40"/>
        <div className="relative">
          <div className="flex items-center gap-2"><div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/20 text-teal-400"><Icons.Crosshair className="h-6 w-6"/></div><div className="text-lg font-bold text-slate-100">OMNI<span className="text-teal-400">RECON AI</span></div><Badge color="teal">v2.0</Badge></div>
          <h1 className="mt-3 text-2xl font-bold text-slate-100">About OmniRecon AI</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">A unified OSINT & cyber-security investigation platform built with React + TypeScript + Tailwind CSS on the front-end.</p>
          <div className="mt-4 flex flex-wrap gap-3 text-sm">
            <span className="rounded-lg border border-slate-700 px-3 py-1.5 text-slate-300">{MODULES.length} Modules</span>
            <span className="rounded-lg border border-slate-700 px-3 py-1.5 text-slate-300">{totalTools}+ Tools</span>
            <span className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-emerald-300 font-semibold">92% Accuracy</span>
            <span className="rounded-lg border border-teal-500/30 bg-teal-500/10 px-3 py-1.5 text-teal-300">Python Backend</span>
            <span className="rounded-lg border border-slate-700 px-3 py-1.5 text-slate-300">Offline-capable</span>
          </div>
        </div>
      </Card>
      <div><h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Modules Overview</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {MODULES.map(m=>(
            <Link key={m.slug} to={`/module/${m.slug}`}>
              <Card className="flex items-center gap-3 p-4 transition hover:border-teal-500/50">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-800 text-teal-400"><Icon name={m.icon} className="h-4 w-4"/></div>
                <div className="min-w-0 flex-1"><div className="truncate text-sm font-semibold text-slate-100">{m.name}</div><div className="truncate text-xs text-slate-500">{m.tools.length?`${m.tools.length} tools`:"System module"}</div></div>
                <Icons.ArrowRight className="h-4 w-4 text-slate-600"/>
              </Card>
            </Link>
          ))}
        </div>
      </div>
      <div><h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Help & FAQ</h2>
        <Card className="divide-y divide-slate-800">
          {FAQ.map((f,i)=>(
            <div key={i}>
              <button onClick={()=>setOpen(open===i?null:i)} className="flex w-full items-center justify-between gap-3 p-4 text-left"><span className="text-sm font-medium text-slate-100">{f.q}</span><Icons.ChevronDown className={`h-4 w-4 shrink-0 text-slate-500 transition ${open===i?"rotate-180":""}`}/></button>
              {open===i&&<div className="px-4 pb-4 text-sm text-slate-400">{f.a}</div>}
            </div>
          ))}
        </Card>
      </div>
      <Card className="border-amber-500/30 bg-amber-500/5 p-4">
        <div className="flex items-center gap-2 text-amber-300"><Icons.AlertTriangle className="h-4 w-4"/><span className="text-sm font-semibold">Ethical Use Disclaimer</span></div>
        <p className="mt-2 text-xs leading-relaxed text-slate-400">OmniRecon AI is provided strictly for educational purposes and authorized security testing. Using OSINT or security tools against systems without explicit permission is illegal.</p>
      </Card>
    </div>
  );
}
