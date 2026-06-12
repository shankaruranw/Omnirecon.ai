import { useState } from "react";
import * as Icons from "lucide-react";
import { login, signUp } from "../lib/auth";
export default function Login({ onSuccess }: { onSuccess: () => void }) {
  const [mode, setMode] = useState<"login"|"signup">("login");
  const [name, setName] = useState(""); const [email, setEmail] = useState(""); const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false); const [error, setError] = useState(""); const [loading, setLoading] = useState(false);
  const submit = (e: React.FormEvent) => {
    e.preventDefault(); setError(""); setLoading(true);
    setTimeout(() => {
      if (mode==="signup") { const r=signUp(name,email,password); if(!r.ok){setError(r.error||"Sign up failed.");setLoading(false);return;} }
      const r=login(email,password); setLoading(false);
      if(!r.ok){setError(r.error||"Login failed.");return;} onSuccess();
    },500);
  };
  return (
    <div className="grid-bg flex min-h-screen items-center justify-center p-4">
      <div className="absolute inset-0 bg-gradient-to-br from-slate-950 via-slate-900/40 to-slate-950"/>
      <div className="absolute -right-20 -top-20 h-64 w-64 rounded-full bg-teal-600/10 blur-[100px] pointer-events-none"/>
      <div className="absolute -bottom-20 -left-20 h-64 w-64 rounded-full bg-indigo-600/10 blur-[100px] pointer-events-none"/>
      <div className="relative grid w-full max-w-4xl overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70 shadow-2xl backdrop-blur lg:grid-cols-2">
        <div className="relative hidden flex-col justify-between bg-gradient-to-br from-teal-600/10 via-slate-900 to-indigo-700/10 p-10 lg:flex border-r border-slate-800">
          <div className="flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-teal-500/20 text-teal-400"><Icons.Shield className="h-6 w-6"/></div>
            <div><div className="text-lg font-bold text-slate-100">OMNI<span className="text-teal-400">RECON AI</span></div><div className="text-[10px] uppercase tracking-widest text-slate-500">Unified Intelligence Framework</div></div>
          </div>
          <div>
            <h2 className="text-2xl font-bold leading-tight text-slate-100">Offensive Security<br/>Simplified.</h2>
            <p className="mt-3 text-sm text-slate-400">OmniRecon AI provides an enterprise-grade workspace for vulnerability management, automated reconnaissance, and modular intelligence gathering.</p>
            <ul className="mt-6 space-y-2 text-sm text-slate-300">
              {["Domain & Network Intelligence","AI Risk & Vulnerability Analysis","Crypto, Stego & Phishing Labs"].map(t=>(
                <li key={t} className="flex items-center gap-2"><Icons.ShieldCheck className="h-4 w-4 text-teal-400"/>{t}</li>
              ))}
            </ul>
          </div>
          <div className="text-xs text-slate-600">Enterprise Grade Security Framework · v2.0</div>
        </div>
        <div className="p-8 sm:p-10">
          <div className="mb-6 flex items-center gap-2 lg:hidden">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-teal-500/20 text-teal-400"><Icons.Shield className="h-5 w-5"/></div>
            <div className="text-base font-bold text-slate-100">OMNI<span className="text-teal-400">RECON AI</span></div>
          </div>
          <h1 className="text-xl font-bold text-slate-100">{mode==="login"?"Sign in to your account":"Create your account"}</h1>
          <p className="mt-1 text-sm text-slate-400">{mode==="login"?"Enter your email and password to continue.":"Fill in your details to get started."}</p>
          <form onSubmit={submit} className="mt-6 space-y-4">
            {mode==="signup"&&<div><label className="mb-1 block text-xs font-medium text-slate-400">Full Name</label>
              <div className="relative"><Icons.User className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"/>
                <input value={name} onChange={e=>setName(e.target.value)} placeholder="Jane Analyst" className="w-full rounded-lg border border-slate-700 bg-slate-950/70 py-2.5 pl-9 pr-3 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-teal-500"/></div></div>}
            <div><label className="mb-1 block text-xs font-medium text-slate-400">Email Address</label>
              <div className="relative"><Icons.Mail className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"/>
                <input type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="you@example.com" required className="w-full rounded-lg border border-slate-700 bg-slate-950/70 py-2.5 pl-9 pr-3 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-teal-500"/></div></div>
            <div><label className="mb-1 block text-xs font-medium text-slate-400">Password</label>
              <div className="relative"><Icons.Lock className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"/>
                <input type={showPw?"text":"password"} value={password} onChange={e=>setPassword(e.target.value)} placeholder="••••••••" required className="w-full rounded-lg border border-slate-700 bg-slate-950/70 py-2.5 pl-9 pr-10 text-sm text-slate-100 outline-none placeholder:text-slate-500 focus:border-teal-500"/>
                <button type="button" onClick={()=>setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300">{showPw?<Icons.EyeOff className="h-4 w-4"/>:<Icons.Eye className="h-4 w-4"/>}</button></div></div>
            {error&&<div className="flex items-center gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-sm text-rose-300"><Icons.AlertCircle className="h-4 w-4 shrink-0"/>{error}</div>}
            <button type="submit" disabled={loading} className="flex w-full items-center justify-center gap-2 rounded-lg bg-teal-500 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-teal-400 disabled:opacity-60">
              {loading?<div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950/30 border-t-slate-950"/>:<Icons.LogIn className="h-4 w-4"/>}
              {mode==="login"?"Sign In":"Create Account"}
            </button>
          </form>
          <div className="mt-6 text-center text-sm text-slate-400">
            {mode==="login"?<>Don't have an account? <button onClick={()=>{setMode("signup");setError("");}} className="font-semibold text-teal-400 hover:underline">Sign up</button></>:<>Already have an account? <button onClick={()=>{setMode("login");setError("");}} className="font-semibold text-teal-400 hover:underline">Sign in</button></>}
          </div>
          <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2 text-center text-[11px] text-slate-500">Demo: any valid email + 6+ char password.</div>
        </div>
      </div>
    </div>
  );
}
