import { useEffect } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import * as Icons from "lucide-react";
import { getModule } from "../lib/modules";
import { TOOL_COMPONENTS } from "../lib/registry";
import { Card, Panel } from "../lib/ui";
import Reports from "./Reports";
function Icon({ name, className }: { name: string; className?: string }) { const C=(Icons as any)[name]||Icons.Circle; return <C className={className}/>; }
export default function ModulePage() {
  const { moduleSlug="", toolSlug } = useParams();
  const navigate = useNavigate();
  const mod = getModule(moduleSlug);
  useEffect(() => { if(mod&&mod.tools.length>0&&!toolSlug) navigate(`/module/${mod.slug}/${mod.tools[0].slug}`,{replace:true}); },[mod,toolSlug,navigate]);
  if (!mod) return <div className="text-slate-400">Module not found. <Link to="/" className="text-teal-400">Back</Link></div>;
  if (mod.slug==="reports") return <Reports/>;
  const ToolComp = toolSlug ? TOOL_COMPONENTS[mod.slug]?.[toolSlug] : undefined;
  const activeTool = mod.tools.find(t=>t.slug===toolSlug);
  return (
    <div className="fade-in space-y-5">
      <div className="flex items-center gap-3">
        <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-teal-500/15 text-teal-400"><Icon name={mod.icon} className="h-5 w-5"/></div>
        <div><h1 className="text-xl font-bold text-slate-100">{mod.name}</h1><p className="text-sm text-slate-400">{mod.desc}</p></div>
      </div>
      <div className="flex flex-wrap gap-2">
        {mod.tools.map(t=>(
          <Link key={t.slug} to={`/module/${mod.slug}/${t.slug}`}
            className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition ${t.slug===toolSlug?"border-teal-500/50 bg-teal-500/10 text-teal-300":"border-slate-800 text-slate-300 hover:border-slate-600"}`}>
            {t.name}
          </Link>
        ))}
      </div>
      <div className="grid gap-5 lg:grid-cols-3">
        <div className="lg:col-span-2">
          {ToolComp&&activeTool ? <Panel title={activeTool.name} desc={activeTool.desc}><ToolComp/></Panel> : <Card className="p-8 text-center text-slate-500">Select a tool above to begin.</Card>}
        </div>
        <div className="space-y-4">
          <Card className="p-4">
            <h4 className="mb-3 text-xs font-semibold uppercase tracking-wider text-slate-400">All Tools</h4>
            <div className="space-y-1">
              {mod.tools.map(t=>(
                <Link key={t.slug} to={`/module/${mod.slug}/${t.slug}`}
                  className={`block rounded-md px-3 py-2 text-sm ${t.slug===toolSlug?"bg-slate-800 text-teal-300":"text-slate-300 hover:bg-slate-800/60"}`}>
                  <div className="font-medium">{t.name}</div>
                  <div className="text-xs text-slate-500">{t.desc}</div>
                </Link>
              ))}
            </div>
          </Card>
          <Card className="p-4">
            <div className="flex items-center gap-2 text-teal-400"><Icons.ShieldCheck className="h-4 w-4"/><span className="text-sm font-semibold">Security Level: High</span></div>
            <p className="mt-2 text-xs leading-relaxed text-slate-400">All scans are routed through the OmniRecon AI engine. Historical data is stored locally in the secure investigation workspace.</p>
          </Card>
        </div>
      </div>
    </div>
  );
}
