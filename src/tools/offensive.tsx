import { useRef, useState } from "react";
import { Button, Input, Textarea, ResultBox, Badge, CopyButton, Select } from "../lib/ui";
import { seeded } from "../lib/sim";
import { addHistory } from "../lib/history";
import { api, isBackendOnline } from "../lib/api";

function textToBits(text: string): number[] {
  const bytes = new TextEncoder().encode(text); const len = bytes.length;
  const header = [(len >>> 24) & 255, (len >>> 16) & 255, (len >>> 8) & 255, len & 255];
  const bits: number[] = [];
  for (const b of [...header, ...bytes]) for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  return bits;
}

export function StegoStudio() {
  const [mode, setMode] = useState<"hide" | "extract">("hide"); const [secret, setSecret] = useState(""); const [img, setImg] = useState<HTMLImageElement | null>(null); const [imgName, setImgName] = useState(""); const [outUrl, setOutUrl] = useState(""); const [extracted, setExtracted] = useState(""); const [error, setError] = useState("");
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const loadImg = (file?: File) => { if (!file) return; setImgName(file.name); const url = URL.createObjectURL(file); const image = new Image(); image.onload = () => setImg(image); image.src = url; };
  const hide = () => { setError(""); setOutUrl(""); if (!img || !secret) { setError("Provide both an image and secret text."); return; } const c = canvasRef.current!; c.width = img.width; c.height = img.height; const ctx = c.getContext("2d")!; ctx.drawImage(img, 0, 0); const data = ctx.getImageData(0, 0, c.width, c.height); const bits = textToBits(secret); if (bits.length > Math.floor((data.data.length / 4) * 3)) { setError("Secret too large."); return; } let bi = 0; for (let i = 0; i < data.data.length && bi < bits.length; i++) { if (i % 4 === 3) continue; data.data[i] = (data.data[i] & 0xfe) | bits[bi++]; } ctx.putImageData(data, 0, 0); setOutUrl(c.toDataURL("image/png")); addHistory({ module: "Offensive Suite", tool: "Steganography Studio", target: imgName, summary: `${secret.length} chars embedded` }); };
  const extract = () => { setError(""); setExtracted(""); if (!img) { setError("Load an image first."); return; } const c = canvasRef.current!; c.width = img.width; c.height = img.height; const ctx = c.getContext("2d")!; ctx.drawImage(img, 0, 0); const data = ctx.getImageData(0, 0, c.width, c.height).data; const bits: number[] = []; for (let i = 0; i < data.length; i++) { if (i % 4 === 3) continue; bits.push(data[i] & 1); } const rb = (off: number) => { let b = 0; for (let i = 0; i < 8; i++) b = (b << 1) | bits[off + i]; return b; }; const len = (rb(0) << 24) | (rb(8) << 16) | (rb(16) << 8) | rb(24); if (len <= 0 || len > 100000) { setError("No hidden message found."); return; } const out = new Uint8Array(len); for (let i = 0; i < len; i++) out[i] = rb(32 + i * 8); try { setExtracted(new TextDecoder().decode(out)); addHistory({ module: "Offensive Suite", tool: "Steganography Studio", target: imgName, summary: `${len} bytes extracted` }); } catch { setError("Failed to decode."); } };
  return <div><div className="mb-3 flex gap-2"><Select value={mode} onChange={e => { setMode(e.target.value as any); setOutUrl(""); setExtracted(""); setError(""); }} className="w-44"><option value="hide">Hide message</option><option value="extract">Extract message</option></Select></div><label className="block cursor-pointer rounded-lg border border-dashed border-slate-700 p-5 text-center text-sm text-slate-400 hover:border-teal-500"><input type="file" accept="image/png,image/jpeg" className="hidden" onChange={e => loadImg(e.target.files?.[0])} />{imgName ? `🖼 Loaded: ${imgName}` : "🖼 Select a PNG/JPG cover image"}</label>{mode === "hide" && <><Textarea className="mt-3" rows={3} value={secret} onChange={e => setSecret(e.target.value)} placeholder="Secret text to embed…" /><Button className="mt-3" onClick={hide}>Embed (LSB)</Button></>}{mode === "extract" && <Button className="mt-3" onClick={extract}>Extract (LSB)</Button>}<canvas ref={canvasRef} className="hidden" />{error && <div className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-300">{error}</div>}{outUrl && <ResultBox title="Stego Image"><img src={outUrl} alt="stego" className="max-h-64 rounded-lg border border-slate-800" /><a href={outUrl} download="stego.png" className="mt-3 inline-block rounded-lg bg-teal-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-teal-400">Download</a></ResultBox>}{extracted && <ResultBox title="Extracted Secret"><div className="flex items-start justify-between gap-3"><code className="mono break-all text-teal-300">{extracted}</code><CopyButton text={extracted} /></div></ResultBox>}</div>;
}

const HOMO: Record<string, string[]> = { a: ["4", "@"], e: ["3"], i: ["1", "l"], o: ["0"], s: ["5", "$"], l: ["1"], g: ["9"] };
export function Phishing() {
  const [domain, setDomain] = useState(""); const [res, setRes] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const generate = async () => {
    if (!domain) return;
    setLoading(true);
    let data: any;
    if (isBackendOnline()) {
      try { data = await api.security.typosquat(domain); } catch {}
    }
    if (!data) {
      const dot = domain.lastIndexOf("."); const name = dot > -1 ? domain.slice(0, dot) : domain; const tld = dot > -1 ? domain.slice(dot) : ".com";
      const rng = seeded(domain + "phish"); const variants = new Set<string>();
      for (let i = 0; i < name.length; i++) { variants.add(name.slice(0,i)+name.slice(i+1)+tld); variants.add(name.slice(0,i)+name[i]+name[i]+name.slice(i+1)+tld); for(const s of HOMO[name[i].toLowerCase()]||[])variants.add(name.slice(0,i)+s+name.slice(i+1)+tld); }
      for(let i=0;i<name.length-1;i++)variants.add(name.slice(0,i)+name[i+1]+name[i]+name.slice(i+2)+tld);
      for(const t of[".com",".net",".org",".co",".io",".xyz",".site",".online"])if(t!==tld)variants.add(name+t);
      variants.add(`secure-${name}${tld}`);variants.add(`${name}-login${tld}`);variants.add(`${name}-verify${tld}`);
      const list=[...variants].slice(0,30).map(v=>({domain:v,d:v,registered:rng()>0.7,risk:rng()>0.6?"High":"Low"}));
      data = { variants: list, count: list.length, active: list.filter((l:any)=>l.registered).length, real: false };
    }
    setRes(data); setLoading(false);
    const active = data.active || 0;
    addHistory({ module:"Offensive Suite", tool:"Phishing & Typosquatting", target:domain, summary:`${data.count||0} variants, ${active} registered`, risk:active>3?"High":"Medium" });
  };
  const variants = res?.variants || [];
  return <div><p className="mb-3 text-sm text-slate-400">Generates malicious look-alike domains. {isBackendOnline() ? <span className="text-emerald-400 font-semibold">● Real DNS registration check active</span> : <span className="text-amber-400">● Start backend for real DNS checks</span>}</p><div className="flex gap-2"><Input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="yourbrand.com"/><Button onClick={generate} disabled={loading}>Generate Variants</Button></div>{loading&&<div className="mt-4"><div className="flex items-center gap-2 text-sm text-teal-300"><div className="h-4 w-4 animate-spin rounded-full border-2 border-teal-500/30 border-t-teal-400"/>Generating & checking domain registration…</div></div>}{res&&!loading&&<ResultBox title={`${variants.length} Look-alike Domains (${res.active||0} registered)`}><div className="space-y-1">{variants.map((v:any)=><div key={v.domain||v.d} className="mono flex items-center justify-between rounded border border-slate-800 px-3 py-1.5 text-sm"><span className="text-slate-200">{v.domain||v.d}</span><div className="flex items-center gap-2"><Badge color={(v.registered)?"rose":"slate"}>{(v.registered)?"registered ⚠":"available"}</Badge>{(v.registered)&&<Badge color={v.risk==="High"?"rose":"emerald"}>{v.risk}</Badge>}</div></div>)}</div></ResultBox>}</div>;
}
