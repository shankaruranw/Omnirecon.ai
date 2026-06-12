import { useState } from "react";
import CryptoJS from "crypto-js";
import { Input, Textarea, ResultBox, CopyButton, Select } from "../lib/ui";

function Converter({ name, encode, decode }: { name: string; encode: (s: string) => string; decode: (s: string) => string }) {
  const [input, setInput] = useState(""); const [mode, setMode] = useState<"encode" | "decode">("encode");
  let output = ""; try { output = input ? (mode === "encode" ? encode(input) : decode(input)) : ""; } catch { output = "⚠ Invalid input."; }
  return <div><div className="mb-3 flex gap-2"><Select value={mode} onChange={e => setMode(e.target.value as any)} className="w-40"><option value="encode">Encode</option><option value="decode">Decode</option></Select></div><Textarea rows={4} value={input} onChange={e => setInput(e.target.value)} placeholder={`Enter text to ${mode}…`} />{output && <ResultBox title={`${name} Output`}><div className="flex items-start justify-between gap-3"><code className="mono break-all text-sm text-teal-300">{output}</code><CopyButton text={output} /></div></ResultBox>}</div>;
}

export const Base64 = () => <Converter name="Base64" encode={s => btoa(unescape(encodeURIComponent(s)))} decode={s => decodeURIComponent(escape(atob(s)))} />;
export const Hex = () => <Converter name="Hex" encode={s => Array.from(s).map(c => c.charCodeAt(0).toString(16).padStart(2, "0")).join("")} decode={s => s.replace(/\s/g, "").match(/.{1,2}/g)!.map(h => String.fromCharCode(parseInt(h, 16))).join("")} />;
export const UrlEncode = () => <Converter name="URL" encode={encodeURIComponent} decode={decodeURIComponent} />;
export const Binary = () => <Converter name="Binary" encode={s => Array.from(s).map(c => c.charCodeAt(0).toString(2).padStart(8, "0")).join(" ")} decode={s => s.trim().split(/\s+/).map(b => String.fromCharCode(parseInt(b, 2))).join("")} />;

const rot = (s: string, n: number) => s.replace(/[a-z]/gi, c => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + n) % 26 + 26) % 26 + b); });
export function Rot() {
  const [input, setInput] = useState(""); const [shift, setShift] = useState(13);
  return <div><label className="mb-3 flex items-center gap-2 text-sm text-slate-300">Shift: <strong className="mono text-teal-300">{shift}</strong><input type="range" min={0} max={25} value={shift} onChange={e => setShift(+e.target.value)} className="accent-teal-500" /></label><Textarea rows={4} value={input} onChange={e => setInput(e.target.value)} placeholder="Enter text…" />{input && <ResultBox title={`Caesar (shift ${shift})`}><code className="mono break-all text-sm text-teal-300">{rot(input, shift)}</code></ResultBox>}</div>;
}

const MORSE: Record<string, string> = { a: ".-", b: "-...", c: "-.-.", d: "-..", e: ".", f: "..-.", g: "--.", h: "....", i: "..", j: ".---", k: "-.-", l: ".-..", m: "--", n: "-.", o: "---", p: ".--.", q: "--.-", r: ".-.", s: "...", t: "-", u: "..-", v: "...-", w: ".--", x: "-..-", y: "-.--", z: "--..", " ": "/" };
const RMORSE = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));
export const Morse = () => <Converter name="Morse" encode={s => s.toLowerCase().split("").map(c => MORSE[c] || "").join(" ")} decode={s => s.trim().split(" ").map(m => RMORSE[m] || "").join("")} />;

export function Hash() {
  const [input, setInput] = useState("");
  const hashes = input ? { MD5: CryptoJS.MD5(input), "SHA-1": CryptoJS.SHA1(input), "SHA-256": CryptoJS.SHA256(input), "SHA-512": CryptoJS.SHA512(input), "SHA-3": CryptoJS.SHA3(input), RIPEMD160: CryptoJS.RIPEMD160(input) } : {};
  return <div><Textarea rows={3} value={input} onChange={e => setInput(e.target.value)} placeholder="Text to hash…" />{input && <ResultBox title="Hash Digests">{Object.entries(hashes).map(([name, h]) => { const s = h.toString(); return <div key={name} className="flex items-center justify-between gap-3 border-b border-slate-800 py-2 last:border-0"><span className="w-24 shrink-0 text-xs font-semibold text-teal-400">{name}</span><code className="mono flex-1 break-all text-xs text-slate-200">{s}</code><CopyButton text={s} /></div>; })}</ResultBox>}</div>;
}

export function Hmac() {
  const [msg, setMsg] = useState(""); const [key, setKey] = useState(""); const [algo, setAlgo] = useState("SHA-256");
  const fns: any = { "SHA-256": CryptoJS.HmacSHA256, "SHA-1": CryptoJS.HmacSHA1, "SHA-512": CryptoJS.HmacSHA512, MD5: CryptoJS.HmacMD5 };
  const out = msg && key ? fns[algo](msg, key).toString() : "";
  return <div className="space-y-3"><Input value={key} onChange={e => setKey(e.target.value)} placeholder="Secret key" className="mono" /><Select value={algo} onChange={e => setAlgo(e.target.value)}>{Object.keys(fns).map(a => <option key={a}>{a}</option>)}</Select><Textarea rows={3} value={msg} onChange={e => setMsg(e.target.value)} placeholder="Message" />{out && <ResultBox title={`HMAC-${algo}`}><div className="flex justify-between gap-3"><code className="mono break-all text-sm text-teal-300">{out}</code><CopyButton text={out} /></div></ResultBox>}</div>;
}

export function Aes() {
  const [text, setText] = useState(""); const [pass, setPass] = useState(""); const [mode, setMode] = useState<"enc" | "dec">("enc");
  let out = ""; try { if (text && pass) out = mode === "enc" ? CryptoJS.AES.encrypt(text, pass).toString() : CryptoJS.AES.decrypt(text, pass).toString(CryptoJS.enc.Utf8) || "⚠ Wrong key"; } catch { out = "⚠ Failed."; }
  return <div className="space-y-3"><Select value={mode} onChange={e => setMode(e.target.value as any)}><option value="enc">Encrypt</option><option value="dec">Decrypt</option></Select><Input value={pass} onChange={e => setPass(e.target.value)} placeholder="Passphrase (AES-256)" className="mono" /><Textarea rows={4} value={text} onChange={e => setText(e.target.value)} placeholder={mode === "enc" ? "Plaintext…" : "Ciphertext (Base64)…"} />{out && <ResultBox title={mode === "enc" ? "Ciphertext" : "Plaintext"}><div className="flex justify-between gap-3"><code className="mono break-all text-sm text-teal-300">{out}</code><CopyButton text={out} /></div></ResultBox>}</div>;
}
