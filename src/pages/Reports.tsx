import { useEffect, useMemo, useState } from "react";
import * as Icons from "lucide-react";
import { getHistory,clearHistory,removeHistory,type ScanRecord,getReports,addReport,removeReport,clearReports,type ReportRecord,type ReportType } from "../lib/history";
import { buildReportHtml,openPrint,downloadHtml,summarize } from "../lib/reportgen";
import { Card,Button,Badge,Input,Select } from "../lib/ui";
import { toast } from "../lib/toast";
type Tab="generate"|"scans"|"reports"|"investigations";
export default function Reports() {
  const [tab,setTab]=useState<Tab>("generate");
  const [history,setHistory]=useState<ScanRecord[]>([]);
  const [reports,setReports]=useState<ReportRecord[]>([]);
  const [q,setQ]=useState(""); const [mod,setMod]=useState("all");
  useEffect(()=>{const u=()=>{setHistory(getHistory());setReports(getReports());};u();window.addEventListener("history-updated",u);return()=>window.removeEventListener("history-updated",u);},[]);
  const riskColor=(r?:string)=>r==="Critical"||r==="High"?"rose":r==="Medium"?"amber":r==="Low"?"emerald":"slate";
  const modules=["all",...Array.from(new Set(history.map(h=>h.module)))];
  const filtered=history.filter(h=>(mod==="all"||h.module===mod)&&(q===""||`${h.target}${h.tool}${h.summary}`.toLowerCase().includes(q.toLowerCase())));
  const investigations=useMemo(()=>{const map=new Map<string,ScanRecord[]>();for(const h of history){const k=h.target||"—";if(!map.has(k))map.set(k,[]);map.get(k)!.push(h);}return[...map.entries()].map(([target,recs])=>({target,recs,last:Math.max(...recs.map(r=>r.timestamp))})).sort((a,b)=>b.last-a.last);},[history]);
  const stats=summarize(history);
  const exportCsv=()=>{const rows=[["Time","Module","Tool","Target","Summary","Risk"],...history.map(h=>[new Date(h.timestamp).toISOString(),h.module,h.tool,h.target,h.summary,h.risk||""])];const csv=rows.map(r=>r.map(c=>`"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n");const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([csv],{type:"text/csv"}));a.download=`omnirecon-scans-${Date.now()}.csv`;a.click();};
  const exportJson=()=>{const a=document.createElement("a");a.href=URL.createObjectURL(new Blob([JSON.stringify(history,null,2)],{type:"application/json"}));a.download=`omnirecon-scans-${Date.now()}.json`;a.click();};
  const generate=(type:ReportType,andPrint:boolean)=>{if(history.length===0){alert("No scan data. Run some tools first.");return;}const html=buildReportHtml(type,history,"All modules");const title=`${type} Report — All modules`;addReport({title,type,scope:"All modules",recordCount:history.length,html});setReports(getReports());toast(`${type} report generated`,"success");if(andPrint)openPrint(html);};
  const tabs:["generate"|"scans"|"reports"|"investigations",string,string][]=[ ["generate","Generate Reports","FileOutput"],["scans",`Scan History (${history.length})`,"FileSearch"],["reports",`Report History (${reports.length})`,"Files"],["investigations",`Investigations (${investigations.length})`,"FolderSearch"]];
  return (
    <div className="fade-in space-y-5">
      <div><h1 className="text-2xl font-bold text-slate-100">Reporting System</h1><p className="text-sm text-slate-400">Generate professional reports and review your scan, report & investigation history.</p></div>
      <div className="flex flex-wrap gap-2">
        {tabs.map(([t,label,icon])=>{const I=(Icons as any)[icon]||Icons.Circle;return(<button key={t} onClick={()=>setTab(t)} className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-medium transition ${tab===t?"border-teal-500/50 bg-teal-500/10 text-teal-300":"border-slate-800 text-slate-300 hover:border-slate-600"}`}><I className="h-4 w-4"/>{label}</button>);})}
      </div>
      {tab==="generate"&&(
        <div className="space-y-5">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[["Total Scans",stats.total,"text-teal-400"],["Targets",stats.targets.length,"text-indigo-400"],["High/Critical",(stats.counts.Critical||0)+(stats.counts.High||0),"text-rose-400"],["Posture",`${stats.score}/100`,"text-emerald-400"]].map(([l,v,c])=>(
              <Card key={l as string} className="p-4"><div className="text-xs text-slate-400">{l}</div><div className={`mt-1 text-2xl font-bold ${c}`}>{v}</div></Card>
            ))}
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {([["Executive","High-level posture & priorities for management.","Briefcase","text-indigo-400"],["Technical","Detailed findings & full scan log for engineers.","Terminal","text-teal-400"],["AI Summary","AI-written narrative with recommended next steps.","BrainCircuit","text-emerald-400"],["PDF","Print-ready — opens browser print/Save-as-PDF dialog.","FileDown","text-rose-400"]] as [ReportType,string,string,string][]).map(([type,desc,icon,c])=>{const I=(Icons as any)[icon]||Icons.File;return(
              <Card key={type} className="p-5">
                <div className="mb-3 flex items-center gap-3"><div className="flex h-10 w-10 items-center justify-center rounded-lg bg-slate-800"><I className={`h-5 w-5 ${c}`}/></div><h3 className="font-semibold text-slate-100">{type} Report</h3></div>
                <p className="mb-4 text-sm text-slate-400">{desc}</p>
                <div className="flex gap-2"><Button onClick={()=>generate(type,true)}>{type==="PDF"?"Open / Save PDF":"Generate & Open"}</Button><Button variant="ghost" onClick={()=>generate(type,false)}>Save Only</Button></div>
              </Card>
            );})}
          </div>
        </div>
      )}
      {tab==="scans"&&(<>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-slate-400">{history.length} saved scans · stored locally.</p>
          <div className="flex gap-2"><Button variant="ghost" onClick={exportCsv}><Icons.FileSpreadsheet className="h-4 w-4"/>CSV</Button><Button variant="ghost" onClick={exportJson}><Icons.FileJson className="h-4 w-4"/>JSON</Button><Button variant="danger" onClick={()=>confirm("Clear all scan history?")&&clearHistory()}><Icons.Trash2 className="h-4 w-4"/>Clear</Button></div>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row"><Input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search scans…"/><Select value={mod} onChange={e=>setMod(e.target.value)} className="sm:w-64">{modules.map(m=><option key={m} value={m}>{m==="all"?"All modules":m}</option>)}</Select></div>
        <Card className="divide-y divide-slate-800">
          {filtered.length===0&&<div className="p-10 text-center text-sm text-slate-500">No matching scans.</div>}
          {filtered.map(h=>(
            <div key={h.id} className="flex items-center gap-3 p-4">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-teal-400"><Icons.FileSearch className="h-4 w-4"/></div>
              <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold text-slate-100">{h.tool}</span><Badge color="indigo">{h.module}</Badge>{h.risk&&<Badge color={riskColor(h.risk) as any}>{h.risk}</Badge>}</div>
                <div className="mt-0.5 truncate text-sm text-slate-400"><span className="mono text-slate-300">{h.target}</span> — {h.summary}</div>
                <div className="text-xs text-slate-600">{new Date(h.timestamp).toLocaleString()}</div>
              </div>
              <button onClick={()=>h.id&&removeHistory(h.id)} className="rounded-md p-2 text-slate-500 hover:bg-slate-800 hover:text-rose-400"><Icons.X className="h-4 w-4"/></button>
            </div>
          ))}
        </Card>
      </>)}
      {tab==="reports"&&(<>
        <div className="flex items-center justify-between"><p className="text-sm text-slate-400">{reports.length} generated reports.</p>{reports.length>0&&<Button variant="danger" onClick={()=>confirm("Clear report history?")&&clearReports()}><Icons.Trash2 className="h-4 w-4"/>Clear</Button>}</div>
        <Card className="divide-y divide-slate-800">
          {reports.length===0&&<div className="p-10 text-center text-sm text-slate-500">No reports yet. Generate one above.</div>}
          {reports.map(r=>(
            <div key={r.id} className="flex items-center gap-3 p-4">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-teal-400"><Icons.FileText className="h-4 w-4"/></div>
              <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold text-slate-100">{r.title}</span><Badge color="teal">{r.type}</Badge></div><div className="truncate text-xs text-slate-500">Scope: {r.scope} · {r.recordCount} records · {new Date(r.timestamp).toLocaleString()}</div></div>
              <button onClick={()=>openPrint(r.html)} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-teal-500">Open</button>
              <button onClick={()=>downloadHtml(r.html,`${r.title.replace(/\s+/g,"-")}.html`)} className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-teal-500">Download</button>
              <button onClick={()=>r.id&&removeReport(r.id)} className="rounded-md p-2 text-slate-500 hover:bg-slate-800 hover:text-rose-400"><Icons.X className="h-4 w-4"/></button>
            </div>
          ))}
        </Card>
      </>)}
      {tab==="investigations"&&(
        <Card className="divide-y divide-slate-800">
          {investigations.length===0&&<div className="p-10 text-center text-sm text-slate-500">No investigations yet.</div>}
          {investigations.map(inv=>{const worst=inv.recs.map(r=>r.risk).sort((a,b)=>({Critical:4,High:3,Medium:2,Low:1,Info:0}as any)[b||"Info"]-({Critical:4,High:3,Medium:2,Low:1,Info:0}as any)[a||"Info"])[0];return(
            <div key={inv.target} className="p-4">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-teal-400"><Icons.FolderSearch className="h-4 w-4"/></div>
                <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><span className="mono text-sm font-semibold text-slate-100">{inv.target}</span>{worst&&<Badge color={riskColor(worst) as any}>{worst}</Badge>}<span className="text-xs text-slate-500">{inv.recs.length} scans</span></div><div className="text-xs text-slate-600">Last: {new Date(inv.last).toLocaleString()}</div></div>
              </div>
              <div className="mt-2 flex flex-wrap gap-1.5 pl-12">{inv.recs.slice(0,8).map(r=><Badge key={r.id} color="slate">{r.tool}</Badge>)}{inv.recs.length>8&&<span className="text-xs text-slate-500">+{inv.recs.length-8} more</span>}</div>
            </div>
          );})}
        </Card>
      )}
    </div>
  );
}
