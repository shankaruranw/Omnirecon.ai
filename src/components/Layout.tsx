import { useEffect, useRef, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import * as Icons from "lucide-react";
import { MODULES } from "../lib/modules";
import { getHistory } from "../lib/history";
import { getCurrentUser, logout, isAdmin } from "../lib/auth";
import { isBackendOnline } from "../lib/api";
import { getTheme, toggleTheme, type Theme } from "../lib/theme";
import { cn } from "../utils/cn";
function Icon({ name, className }: { name: string; className?: string }) {
  const C = (Icons as any)[name] || Icons.Circle; return <C className={className} />;
}
export default function Layout({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const [count, setCount] = useState(0);
  const [menuOpen, setMenuOpen] = useState(false);
  const [realMode, setRealMode] = useState(isBackendOnline());
  const [theme, setTheme] = useState<Theme>(getTheme());
  const menuRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const user = getCurrentUser();

  // Listen for theme changes from anywhere in the app
  useEffect(() => {
    const update = (e: Event) => setTheme((e as CustomEvent).detail.theme);
    window.addEventListener("theme-changed", update);
    return () => window.removeEventListener("theme-changed", update);
  }, []);

  const handleThemeToggle = () => {
    const next = toggleTheme();
    setTheme(next);
  };

  useEffect(() => {
    const update = (e: Event) => setRealMode((e as CustomEvent).detail.online);
    window.addEventListener("backend-status", update);
    return () => window.removeEventListener("backend-status", update);
  }, []);
  const initials = (user?.name||user?.email||"U").slice(0,1).toUpperCase();
  useEffect(() => {
    const u = () => setCount(getHistory().length);
    u(); window.addEventListener("history-updated",u); return () => window.removeEventListener("history-updated",u);
  },[]);
  useEffect(() => {
    const h = (e: MouseEvent) => { if(menuRef.current&&!menuRef.current.contains(e.target as Node)) setMenuOpen(false); };
    document.addEventListener("mousedown",h); return () => document.removeEventListener("mousedown",h);
  },[]);
  if (!user) return null;
  return (
    <div className="grid-bg min-h-screen">
      <aside className={cn("fixed inset-y-0 left-0 z-40 w-64 border-r border-slate-800 bg-slate-950/95 backdrop-blur transition-transform lg:translate-x-0 flex flex-col", open?"translate-x-0":"-translate-x-full")}>
        <div className="flex h-16 items-center gap-2 border-b border-slate-800 px-5 shrink-0">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-teal-500/15 text-teal-400"><Icons.Crosshair className="h-5 w-5" /></div>
          <div><div className="text-sm font-bold tracking-tight text-slate-100">OMNI<span className="text-teal-400">RECON AI</span></div><div className="text-[10px] uppercase tracking-widest text-slate-500">Unified Intelligence Framework</div></div>
        </div>
        <nav className="flex flex-col gap-1 overflow-y-auto p-3 flex-1">
          <NavLink to="/" end onClick={()=>setOpen(false)} className={({isActive})=>cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition",isActive?"bg-teal-500/10 text-teal-300":"text-slate-300 hover:bg-slate-800/60")}>
            <Icons.LayoutDashboard className="h-4 w-4"/> Dashboard
          </NavLink>
          {/* ── Step 1: Command Centre ── */}
          <div className="mt-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">Command Centre</div>
          {MODULES.filter(m => ["soc","workspace"].includes(m.slug)).map(m=>(
            <NavLink key={m.slug} to={`/module/${m.slug}`} onClick={()=>setOpen(false)}
              className={({isActive})=>cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition",isActive?"bg-teal-500/10 text-teal-300":"text-slate-300 hover:bg-slate-800/60")}>
              <Icon name={m.icon} className="h-4 w-4 shrink-0"/>
              <span className="flex-1 truncate">{m.name}</span>
            </NavLink>
          ))}

          {/* ── Step 2: Reconnaissance ── */}
          <div className="mt-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">Reconnaissance</div>
          {MODULES.filter(m => ["viewdns","network","threat-intel","scorecard","intel-graph"].includes(m.slug)).map(m=>(
            <NavLink key={m.slug} to={`/module/${m.slug}`} onClick={()=>setOpen(false)}
              className={({isActive})=>cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition",isActive?"bg-teal-500/10 text-teal-300":"text-slate-300 hover:bg-slate-800/60")}>
              <Icon name={m.icon} className="h-4 w-4 shrink-0"/>
              <span className="flex-1 truncate">{m.name}</span>
            </NavLink>
          ))}

          {/* ── Step 3: Analysis ── */}
          <div className="mt-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">Analysis</div>
          {MODULES.filter(m => ["ai-analysis","email","passwords","crypto"].includes(m.slug)).map(m=>(
            <NavLink key={m.slug} to={`/module/${m.slug}`} onClick={()=>setOpen(false)}
              className={({isActive})=>cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition",isActive?"bg-teal-500/10 text-teal-300":"text-slate-300 hover:bg-slate-800/60")}>
              <Icon name={m.icon} className="h-4 w-4 shrink-0"/>
              <span className="flex-1 truncate">{m.name}</span>
            </NavLink>
          ))}

          {/* ── Step 4: Offensive ── */}
          <div className="mt-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">Offensive</div>
          {MODULES.filter(m => ["offensive"].includes(m.slug)).map(m=>(
            <NavLink key={m.slug} to={`/module/${m.slug}`} onClick={()=>setOpen(false)}
              className={({isActive})=>cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition",isActive?"bg-teal-500/10 text-teal-300":"text-slate-300 hover:bg-slate-800/60")}>
              <Icon name={m.icon} className="h-4 w-4 shrink-0"/>
              <span className="flex-1 truncate">{m.name}</span>
            </NavLink>
          ))}

          {/* ── Step 5: Investigation & Reporting ── */}
          <div className="mt-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">Investigation</div>
          {MODULES.filter(m => ["reports"].includes(m.slug)).map(m=>(
            <NavLink key={m.slug} to={`/module/${m.slug}`} onClick={()=>setOpen(false)}
              className={({isActive})=>cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition",isActive?"bg-teal-500/10 text-teal-300":"text-slate-300 hover:bg-slate-800/60")}>
              <Icon name={m.icon} className="h-4 w-4 shrink-0"/>
              <span className="flex-1 truncate">{m.name}</span>
              {m.slug==="reports"&&count>0&&<span className="rounded-full bg-teal-500/20 px-1.5 text-[10px] text-teal-300">{count}</span>}
            </NavLink>
          ))}
          {isAdmin()&&<>
            <div className="mt-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-rose-400">Owner Panel</div>
            <NavLink to="/admin" onClick={()=>setOpen(false)} className={({isActive})=>cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition",isActive?"bg-rose-500/10 text-rose-300":"text-rose-300 hover:bg-rose-500/10")}>
              <Icons.Shield className="h-4 w-4 shrink-0"/> Admin Dashboard
            </NavLink>
          </>}
          <div className="mt-3 px-3 text-[10px] font-semibold uppercase tracking-widest text-slate-600">System</div>
          {[{to:"/settings",label:"Settings",icon:"Settings"},{to:"/about",label:"About & Help",icon:"HelpCircle"}].map(l=>(
            <NavLink key={l.to} to={l.to} onClick={()=>setOpen(false)} className={({isActive})=>cn("flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition",isActive?"bg-teal-500/10 text-teal-300":"text-slate-300 hover:bg-slate-800/60")}>
              <Icon name={l.icon} className="h-4 w-4 shrink-0"/> {l.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      {open&&<div className="fixed inset-0 z-30 bg-black/60 lg:hidden" onClick={()=>setOpen(false)}/>}
      <div className="lg:pl-64">
        <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-slate-800 bg-slate-950/80 px-4 backdrop-blur">
          <button className="rounded-lg border border-slate-700 p-2 lg:hidden" onClick={()=>setOpen(true)}><Icons.Menu className="h-5 w-5"/></button>
          <form className="relative flex-1 max-w-xl" onSubmit={e=>{e.preventDefault();if(q.trim())navigate(`/search?q=${encodeURIComponent(q.trim())}`)}}>
            <Icons.Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"/>
            <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search OmniRecon AI & the web: username, domain, IP, email…"
              className="w-full rounded-lg border border-slate-800 bg-slate-900/70 py-2 pl-9 pr-3 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-teal-500"/>
          </form>
          {realMode ? (
            <span className="hidden items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-300 sm:flex">
              <span className="relative flex h-2 w-2 text-emerald-400">
                <span className="pulse-ring absolute inline-flex h-full w-full"/>
                <span className="inline-flex h-2 w-2 rounded-full bg-emerald-400"/>
              </span>
              92% Accuracy · Live
            </span>
          ) : (
            <span className="hidden items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-300 sm:flex">
              <span className="inline-flex h-2 w-2 rounded-full bg-amber-400"/>
              Simulation Mode
            </span>
          )}

          {/* ── Theme Toggle Button ── */}
          <button
            onClick={handleThemeToggle}
            title={theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode"}
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-700 bg-slate-900/70 text-slate-400 transition hover:border-teal-500 hover:text-teal-300"
          >
            {theme === "dark"
              ? <Icons.Sun className="h-4 w-4"/>
              : <Icons.Moon className="h-4 w-4"/>
            }
          </button>

          <div className="relative" ref={menuRef}>
            <button onClick={()=>setMenuOpen(o=>!o)} className="flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/70 py-1.5 pl-1.5 pr-2.5 hover:border-slate-600">
              <span className="flex h-7 w-7 items-center justify-center rounded-md bg-teal-500 text-sm font-bold text-slate-950">{initials}</span>
              <span className="hidden max-w-[120px] truncate text-sm text-slate-200 sm:block">{user?.name||user?.email}</span>
              <Icons.ChevronDown className="hidden h-4 w-4 text-slate-500 sm:block"/>
            </button>
            {menuOpen&&(
              <div className="absolute right-0 mt-2 w-56 overflow-hidden rounded-lg border border-slate-800 bg-slate-900 shadow-xl">
                <div className="border-b border-slate-800 px-4 py-3"><div className="truncate text-sm font-semibold text-slate-100">{user?.name}</div><div className="truncate text-xs text-slate-500">{user?.email}</div></div>
                {[{path:"/module/reports",label:"Reports & History",icon:"FileClock"},{path:"/settings",label:"Settings",icon:"Settings"},{path:"/about",label:"About & Help",icon:"HelpCircle"}].map(item=>(
                  <button key={item.path} onClick={()=>{navigate(item.path);setMenuOpen(false);}} className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-slate-300 hover:bg-slate-800">
                    <Icon name={item.icon} className="h-4 w-4"/> {item.label}
                  </button>
                ))}
                <button onClick={()=>logout()} className="flex w-full items-center gap-2 border-t border-slate-800 px-4 py-2.5 text-sm text-rose-300 hover:bg-slate-800">
                  <Icons.LogOut className="h-4 w-4"/> Sign Out
                </button>
              </div>
            )}
          </div>
        </header>
        <main className="mx-auto max-w-7xl p-4 sm:p-6">{children}</main>
        <footer className="border-t border-slate-800 px-6 py-5">
          <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-3 sm:flex-row">
            <div className="flex items-center gap-2 text-xs text-slate-500"><Icons.Crosshair className="h-4 w-4 text-teal-500"/><span>OMNI<span className="text-teal-400">RECON AI</span> · Unified Intelligence Framework</span></div>
            <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500">
              <NavLink to="/" className="hover:text-teal-300">Dashboard</NavLink>
              <NavLink to="/module/reports" className="hover:text-teal-300">Reports</NavLink>
              <NavLink to="/settings" className="hover:text-teal-300">Settings</NavLink>
              <NavLink to="/about" className="hover:text-teal-300">About</NavLink>
            </div>
            <div className="text-xs text-slate-600">Security Intelligence Framework · © 2026</div>
          </div>
        </footer>
      </div>
    </div>
  );
}
