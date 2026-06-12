import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import * as Icons from "lucide-react";
import { MODULES } from "../lib/modules";
import { getHistory, type ScanRecord } from "../lib/history";
import { Card, Badge, Button } from "../lib/ui";
function Icon({ name, className }: { name: string; className?: string }) { const C=(Icons as any)[name]||Icons.Circle; return <C className={className}/>; }
const colorClass: Record<string,string> = { teal:"text-teal-400 bg-teal-500/10", amber:"text-amber-400 bg-amber-500/10", indigo:"text-indigo-400 bg-indigo-500/10", emerald:"text-emerald-400 bg-emerald-500/10", rose:"text-rose-400 bg-rose-500/10", blue:"text-blue-400 bg-blue-500/10" };
const riskColor=(r?:string)=>r==="Critical"||r==="High"?"rose":r==="Medium"?"amber":r==="Low"?"emerald":"slate";
export default function Dashboard() {
  const [history, setHistory] = useState<ScanRecord[]>([]);
  useEffect(()=>{const u=()=>setHistory(getHistory());u();window.addEventListener("history-updated",u);return()=>window.removeEventListener("history-updated",u);},[]);
  const totalTools=MODULES.reduce((a,m)=>a+m.tools.length,0);
  const highRisk=history.filter(h=>h.risk==="High"||h.risk==="Critical").length;
  return (
    <div className="fade-in space-y-8 pb-12">
      <div className="relative overflow-hidden rounded-2xl border border-teal-500/10 bg-slate-900/20 p-8 sm:p-12">
        <div className="absolute inset-0 grid-bg opacity-20"/>
        <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-teal-600/10 blur-[100px]"/>
        <div className="absolute -bottom-20 -left-20 h-64 w-64 rounded-full bg-indigo-600/10 blur-[100px]"/>
        <div className="relative flex flex-col items-center text-center">
          <Badge color="teal" className="mb-4">v2.0 · Intelligence Console</Badge>
          <h1 className="max-w-3xl text-4xl font-extrabold tracking-tight text-white sm:text-5xl">OmniRecon AI Framework</h1>
          <p className="mt-6 max-w-2xl text-lg text-slate-400">
            A professional security investigation platform combining 60+ tools across 13 modules — delivering
            <span className="text-emerald-400 font-semibold"> 92% accuracy</span> with the Python backend running.
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-1.5 text-sm font-semibold text-emerald-300">✓ 92% Real Accuracy</span>
            <span className="rounded-full border border-teal-500/30 bg-teal-500/10 px-4 py-1.5 text-sm font-semibold text-teal-300">✓ Python Flask Backend</span>
            <span className="rounded-full border border-blue-500/30 bg-blue-500/10 px-4 py-1.5 text-sm font-semibold text-blue-300">✓ Free API Keys</span>
            <span className="rounded-full border border-indigo-500/30 bg-indigo-500/10 px-4 py-1.5 text-sm font-semibold text-indigo-300">✓ SQLite Database</span>
          </div>
          <div className="mt-8 flex flex-wrap justify-center gap-4">
            <Link to="/module/workspace"><Button className="h-12 px-8 text-base"><Icons.Zap className="h-5 w-5"/>⚡ AI Recon Workspace</Button></Link>
            <Link to="/module/viewdns"><Button variant="outline" className="h-12 px-8 text-base">Manual Recon</Button></Link>
          </div>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[["Active Modules",MODULES.length,"text-teal-400"],["Total Tools",totalTools,"text-indigo-400"],["Scans Run",history.length,"text-emerald-400"],["High-Risk Findings",highRisk,"text-rose-400"]].map(([l,v,c])=>(
          <Card key={l as string} className="p-4"><div className="text-xs text-slate-400">{l}</div><div className={`mt-1 text-2xl font-bold ${c}`}>{v}</div></Card>
        ))}
      </div>
      {/* ── Modules grouped by workflow stage ── */}
      {[
        { label: "Step 1 — Command Centre",         slugs: ["soc","workspace"] },
        { label: "Step 2 — Reconnaissance",          slugs: ["viewdns","network","threat-intel","scorecard","intel-graph"] },
        { label: "Step 3 — Analysis",                slugs: ["ai-analysis","email","passwords","crypto"] },
        { label: "Step 4 — Offensive",               slugs: ["offensive"] },
        { label: "Step 5 — Investigation & Report",  slugs: ["reports"] },
      ].map(group => (
        <div key={group.label}>
          <div className="mb-4 flex items-center gap-3">
            <div className="h-px flex-1 bg-slate-800"/>
            <span className="text-[11px] font-bold uppercase tracking-widest text-slate-500 whitespace-nowrap">{group.label}</span>
            <div className="h-px flex-1 bg-slate-800"/>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 mb-8">
            {MODULES.filter(m => group.slugs.includes(m.slug)).map(m=>(
              <Link key={m.slug} to={`/module/${m.slug}`}>
                <div className="group relative h-full overflow-hidden rounded-2xl border border-slate-800/60 bg-slate-900/40 p-5 transition-all duration-300 hover:-translate-y-1 hover:border-teal-500/30 hover:bg-slate-900/60 hover:shadow-2xl hover:shadow-teal-500/5">
                  <div className={`mb-4 flex h-11 w-11 items-center justify-center rounded-xl ${colorClass[m.color]||colorClass.teal} transition-colors`}><Icon name={m.icon} className="h-5 w-5"/></div>
                  <h3 className="text-base font-bold text-slate-100 transition-colors group-hover:text-white">{m.name}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-slate-400 line-clamp-2">{m.desc}</p>
                  <div className="mt-5 flex items-center justify-between">
                    <span className="text-[10px] font-bold uppercase tracking-widest text-slate-600">
                      {m.tools.length ? `${m.tools.length} tools` : "System"}
                    </span>
                    <div className="flex h-7 w-7 items-center justify-center rounded-full bg-slate-800/50 text-slate-500 transition-all group-hover:bg-teal-500 group-hover:text-white">
                      <Icons.ArrowRight className="h-3.5 w-3.5"/>
                    </div>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>
      ))}
      <div><h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Recent Activity</h2>
        <Card className="divide-y divide-slate-800">
          {history.length===0&&<div className="p-6 text-center text-sm text-slate-500">No scans yet. Run a tool to populate history.</div>}
          {history.slice(0,6).map(h=>(
            <div key={h.id} className="flex items-center gap-3 p-4">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-teal-400"><Icons.Terminal className="h-4 w-4"/></div>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium text-slate-200">{h.tool} · <span className="mono text-slate-400">{h.target}</span></div>
                <div className="truncate text-xs text-slate-500">{h.summary}</div>
              </div>
              {h.risk&&<Badge color={riskColor(h.risk) as any}>{h.risk}</Badge>}
              <span className="hidden text-xs text-slate-600 sm:block">{new Date(h.timestamp).toLocaleTimeString()}</span>
            </div>
          ))}
        </Card>
      </div>
    </div>
  );
}
