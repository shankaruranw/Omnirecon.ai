import { useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import * as Icons from "lucide-react";
import { MODULES } from "../lib/modules";
import { Card, Badge } from "../lib/ui";
type Hit={module:string;moduleSlug:string;icon:string;tool:string;toolSlug:string;desc:string};
function Icon({ name, className }: { name: string; className?: string }) { const C=(Icons as any)[name]||Icons.Circle; return <C className={className}/>; }
function detectType(q: string) {
  if(/^(\d{1,3}\.){3}\d{1,3}$/.test(q)) return "IP Address";
  if(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(q)) return "Email";
  if(/^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/i.test(q)) return "Domain / URL";
  if(/^[a-z0-9_.-]{2,30}$/i.test(q)) return "Username";
  return "Keyword";
}
const ENGINES=[
  {name:"Google",icon:"Globe",url:(q:string)=>`https://www.google.com/search?q=${encodeURIComponent(q)}`},
  {name:"Bing",icon:"Globe",url:(q:string)=>`https://www.bing.com/search?q=${encodeURIComponent(q)}`},
  {name:"DuckDuckGo",icon:"Globe",url:(q:string)=>`https://duckduckgo.com/?q=${encodeURIComponent(q)}`},
  {name:"Shodan",icon:"Server",url:(q:string)=>`https://www.shodan.io/search?query=${encodeURIComponent(q)}`},
];
export default function Search() {
  const [params]=useSearchParams(); const q=(params.get("q")||"").trim(); const type=detectType(q);
  const hits=useMemo<Hit[]>(()=>{
    if(!q) return []; const ql=q.toLowerCase(); const results:Hit[]=[];
    for(const m of MODULES) for(const t of m.tools) if(`${m.name} ${t.name} ${t.desc}`.toLowerCase().includes(ql)) results.push({module:m.name,moduleSlug:m.slug,icon:m.icon,tool:t.name,toolSlug:t.slug,desc:t.desc});
    return results;
  },[q]);
  const suggestions=useMemo<Hit[]>(()=>{
    const map:Record<string,[string,string][]>={
      "IP Address":[["viewdns","ip-location"],["viewdns","reverse-ip"],["viewdns","port-scan"],["network","scan"]],
      "Email":[["email","validate"],["email","breach"],["email","header"],["email","spf"]],
      "Domain / URL":[["viewdns","dns-lookup"],["viewdns","whois"],["network","subdomain"],["network","waf"],["offensive","phishing"],["ai-analysis","risk"]],
      "Username":[["email","breach"],["ai-analysis","risk"]],
      "Keyword":[["ai-analysis","risk"],["ai-analysis","vuln"]],
    };
    const pairs=map[type]||[]; const out:Hit[]=[];
    for(const[ms,ts]of pairs){const m=MODULES.find(x=>x.slug===ms);const t=m?.tools.find(x=>x.slug===ts);if(m&&t)out.push({module:m.name,moduleSlug:m.slug,icon:m.icon,tool:t.name,toolSlug:t.slug,desc:t.desc});}
    return out;
  },[type]);
  const tp=q?`?q=${encodeURIComponent(q)}`:"";
  return (
    <div className="fade-in mx-auto max-w-4xl space-y-6">
      <div className="flex items-center gap-2 text-sm text-slate-400">
        <Icons.Search className="h-4 w-4"/>Search results for <span className="font-semibold text-slate-100">"{q}"</span>
        {q&&<Badge color="teal">{type}</Badge>}
      </div>
      {!q&&<Card className="p-10 text-center text-slate-400"><Icons.SearchX className="mx-auto mb-3 h-8 w-8 text-slate-600"/>Type something in the search bar above to begin.</Card>}
      {q&&suggestions.length>0&&<div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Recommended for this {type.toLowerCase()}</h2>
        <div className="grid gap-3 sm:grid-cols-2">
          {suggestions.map(h=>(
            <Link key={h.moduleSlug+h.toolSlug} to={`/module/${h.moduleSlug}/${h.toolSlug}${tp}`}>
              <Card className="flex items-center gap-3 p-4 transition hover:border-teal-500/50">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/15 text-teal-400"><Icon name={h.icon} className="h-5 w-5"/></div>
                <div className="min-w-0"><div className="truncate font-semibold text-slate-100">{h.tool}</div><div className="truncate text-xs text-slate-400">{h.module}</div></div>
                <Icons.ArrowRight className="ml-auto h-4 w-4 text-slate-500"/>
              </Card>
            </Link>
          ))}
        </div>
      </div>}
      {q&&hits.length>0&&<div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Tools & modules</h2>
        <Card className="divide-y divide-slate-800">
          {hits.map(h=>(
            <Link key={h.moduleSlug+h.toolSlug} to={`/module/${h.moduleSlug}/${h.toolSlug}${tp}`} className="flex items-center gap-3 p-4 hover:bg-slate-800/40">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-teal-400"><Icon name={h.icon} className="h-4 w-4"/></div>
              <div className="min-w-0 flex-1"><div className="font-medium text-slate-100">{h.tool}</div><div className="truncate text-xs text-slate-500">{h.module} — {h.desc}</div></div>
              <Badge color="indigo">{h.module}</Badge>
            </Link>
          ))}
        </Card>
      </div>}
      {q&&<div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">Search the web</h2>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {ENGINES.map(e=>(
            <a key={e.name} href={e.url(q)} target="_blank" rel="noreferrer">
              <Card className="flex flex-col items-center gap-2 p-4 text-center transition hover:border-teal-500/50">
                <Icon name={e.icon} className="h-6 w-6 text-teal-400"/>
                <span className="text-sm font-medium text-slate-200">{e.name}</span>
                <span className="text-[10px] text-slate-500">Open ↗</span>
              </Card>
            </a>
          ))}
        </div>
      </div>}
    </div>
  );
}
