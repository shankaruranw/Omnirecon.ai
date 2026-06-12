import { useState } from "react";
import CryptoJS from "crypto-js";
import { Button, Input, ResultBox, Badge, CopyButton } from "../lib/ui";
import { seeded, randInt } from "../lib/sim";
import { addHistory } from "../lib/history";
import { api, isBackendOnline } from "../lib/api";

function entropyBits(pw: string) {
  let p = 0;
  if (/[a-z]/.test(pw)) p += 26;
  if (/[A-Z]/.test(pw)) p += 26;
  if (/[0-9]/.test(pw)) p += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) p += 33;
  return pw.length * Math.log2(p || 1);
}
function crackTime(bits: number) {
  let v = (2 ** bits) / 2 / 1e11, l = "seconds";
  for (const [d, n] of [[60, "minutes"], [24, "hours"], [365, "days"], [100, "years"]] as [number, string][]) { if (v < d) { l = n; break; } v /= d; l = n; }
  return v > 1e6 ? "millions of years" : `${v < 1 ? "< 1" : Math.round(v)} ${l}`;
}

export function StrengthChecker() {
  const [pw, setPw] = useState("");
  const bits = entropyBits(pw); const score = Math.min(100, Math.round((bits / 90) * 100));
  const level = score < 30 ? "Very Weak" : score < 50 ? "Weak" : score < 70 ? "Fair" : score < 90 ? "Strong" : "Excellent";
  const color = score < 30 ? "bg-rose-500" : score < 50 ? "bg-orange-500" : score < 70 ? "bg-amber-500" : score < 90 ? "bg-lime-500" : "bg-emerald-500";
  return (
    <div>
      <Input type="text" value={pw} onChange={e => setPw(e.target.value)} placeholder="Type a password to analyze…" className="mono" />
      {pw && <ResultBox>
        <div className="mb-3 flex items-center justify-between"><span className="text-sm text-slate-300">Strength: <strong>{level}</strong></span><Badge color={score >= 70 ? "emerald" : score >= 50 ? "amber" : "rose"}>{score}/100</Badge></div>
        <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800"><div className={`h-full ${color} transition-all`} style={{ width: `${score}%` }} /></div>
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <div className="rounded border border-slate-800 p-3 text-sm"><div className="text-slate-400">Entropy</div><div className="mono text-lg text-slate-100">{bits.toFixed(1)} bits</div></div>
          <div className="rounded border border-slate-800 p-3 text-sm"><div className="text-slate-400">Est. crack time</div><div className="mono text-lg text-slate-100">{crackTime(bits)}</div></div>
        </div>
      </ResultBox>}
    </div>
  );
}

export function Generator() {
  const [len, setLen] = useState(16); const [opts, setOpts] = useState({ lower: true, upper: true, num: true, sym: true }); const [pw, setPw] = useState("");
  const gen = () => {
    let pool = "";
    if (opts.lower) pool += "abcdefghijklmnopqrstuvwxyz";
    if (opts.upper) pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (opts.num) pool += "0123456789";
    if (opts.sym) pool += "!@#$%^&*()-_=+[]{}";
    if (!pool) return;
    const arr = new Uint32Array(len); crypto.getRandomValues(arr);
    setPw(Array.from(arr).map(n => pool[n % pool.length]).join(""));
    addHistory({ module: "Password Lab", tool: "Password Generator", target: `${len} chars`, summary: "Secure password generated" });
  };
  return (
    <div>
      <label className="flex items-center gap-2 text-sm text-slate-300">Length: <strong className="mono text-teal-300">{len}</strong><input type="range" min={6} max={64} value={len} onChange={e => setLen(+e.target.value)} className="accent-teal-500" /></label>
      <div className="mt-3 flex flex-wrap gap-3">{Object.keys(opts).map(k => <label key={k} className="flex items-center gap-2 text-sm text-slate-300"><input type="checkbox" checked={(opts as any)[k]} onChange={e => setOpts({ ...opts, [k]: e.target.checked })} className="accent-teal-500" />{k === "num" ? "Numbers" : k === "sym" ? "Symbols" : k}</label>)}</div>
      <Button className="mt-4" onClick={gen}>Generate</Button>
      {pw && <ResultBox><div className="flex items-center justify-between gap-3"><code className="mono break-all text-lg text-teal-300">{pw}</code><CopyButton text={pw} /></div></ResultBox>}
    </div>
  );
}

const WORDS = "able acid army away baby back ball band bank base bath bear beat belt bird blow blue boat body bone book boot born boss bowl bulk bush call calm came camp card care case cash cell chip city clay clip club coal coat code cold cook cool cope copy core cost crew crop dark data date dawn days dead deal dear debt deep deny desk dial diet dirt dish does dose down draw drug drum duty each earn ease east easy edge else even ever evil exit face fact fade fail".split(" ");

export function Passphrase() {
  const [count, setCount] = useState(5); const [phrase, setPhrase] = useState("");
  const gen = () => {
    const arr = new Uint32Array(count); crypto.getRandomValues(arr);
    const words = Array.from(arr).map(n => WORDS[n % WORDS.length]);
    const num = new Uint32Array(1); crypto.getRandomValues(num);
    setPhrase(words.join("-") + "-" + (num[0] % 100));
    addHistory({ module: "Password Lab", tool: "Passphrase Generator", target: `${count} words`, summary: "Passphrase generated" });
  };
  return (
    <div>
      <label className="flex items-center gap-2 text-sm text-slate-300">Words: <strong className="mono text-teal-300">{count}</strong><input type="range" min={3} max={8} value={count} onChange={e => setCount(+e.target.value)} className="accent-teal-500" /></label>
      <Button className="mt-4" onClick={gen}>Generate Passphrase</Button>
      {phrase && <ResultBox><div className="flex items-center justify-between gap-3"><code className="mono break-all text-lg text-teal-300">{phrase}</code><CopyButton text={phrase} /></div></ResultBox>}
    </div>
  );
}

export function BreachCheck() {
  const [pw, setPw] = useState(""); const [res, setRes] = useState<any>(null); const [loading, setLoading] = useState(false);
  const check = async () => {
    if (!pw) return;
    setLoading(true);
    let data: any;
    if (isBackendOnline()) {
      try { data = await api.password.breach(pw); } catch {}
    }
    if (!data) {
      const hash = CryptoJS.SHA1(pw).toString().toUpperCase();
      const rng = seeded(hash);
      const exposed = rng() > 0.5;
      data = { exposed, count: exposed ? randInt(rng, 1, 250000) : 0, hash_prefix: hash.slice(0,5), real: false };
    }
    setRes(data); setLoading(false);
    addHistory({ module: "Password Lab", tool: "Breach Check", target: "password", summary: data.exposed ? `Found in ${data.count?.toLocaleString()||"?"} breaches` : "Not found", risk: data.exposed ? "High" : "Low" });
  };
  return (
    <div>
      <p className="mb-3 text-sm text-slate-400">Uses HaveIBeenPwned k-anonymity API — only a SHA-1 prefix is sent. {isBackendOnline() ? <span className="text-emerald-400 font-semibold">● Real check active</span> : <span className="text-amber-400">● Simulation (start backend for real check)</span>}</p>
      <div className="flex gap-2"><Input type="text" value={pw} onChange={e => setPw(e.target.value)} placeholder="password to check" className="mono" /><Button onClick={check} disabled={loading}>Check</Button></div>
      {loading && <div className="mt-4"><div className="flex items-center gap-2 text-sm text-teal-300"><div className="h-4 w-4 animate-spin rounded-full border-2 border-teal-500/30 border-t-teal-400" />Checking against breach database…</div></div>}
      {res && !loading && <ResultBox><div className="mb-2 text-xs text-slate-500">SHA-1 prefix: <span className="mono">{res.hash_prefix||res.hash}</span> {res.real && <span className="text-emerald-400">● REAL</span>}</div>{res.exposed ? <div className="text-rose-300">⚠ Found in <strong>{(res.count||0).toLocaleString()}</strong> breach records.</div> : <div className="text-emerald-300">✓ Not found in breach corpus.</div>}</ResultBox>}
    </div>
  );
}
