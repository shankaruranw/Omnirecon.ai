/**
 * OmniRecon AI — Reusable UI Component Library
 * ==============================================
 * All shared UI building blocks used across the application.
 * Every component follows the dark-theme design system.
 */

import { useState } from "react";
import { cn } from "../utils/cn";

/** Card — basic dark container box with border and backdrop blur */
export function Card({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("rounded-xl border border-slate-800/50 bg-slate-900/40 backdrop-blur-xl shadow-sm", className)}>{children}</div>;
}
/** Panel — Card with a title, optional description and optional icon header */
export function Panel({ title, desc, children, icon }: { title: string; desc?: string; children: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <Card className="p-6">
      <div className="mb-6 flex items-start gap-4">
        {icon && <div className="mt-1 flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500/10 text-blue-400">{icon}</div>}
        <div><h3 className="text-lg font-bold text-slate-50">{title}</h3>{desc && <p className="text-sm text-slate-400">{desc}</p>}</div>
      </div>
      {children}
    </Card>
  );
}
/** Button — supports four variants: primary (teal), ghost, danger (red), outline */
export function Button({ children, onClick, variant="primary", className, type="button", disabled }: {
  children: React.ReactNode; onClick?: () => void; variant?: "primary"|"ghost"|"danger"|"outline";
  className?: string; type?: "button"|"submit"; disabled?: boolean;
}) {
  const styles = {
    primary: "bg-teal-500 text-slate-950 hover:bg-teal-400 shadow-lg shadow-teal-900/20 disabled:opacity-50",
    ghost:   "text-slate-400 hover:text-white hover:bg-slate-800",
    danger:  "bg-rose-500 text-white hover:bg-rose-400",
    outline: "border border-slate-700 text-slate-300 hover:border-slate-500 hover:bg-slate-800",
  };
  return (
    <button type={type} disabled={disabled} onClick={onClick}
      className={cn("inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition-all duration-200 active:scale-[.98]", styles[variant], className)}>
      {children}
    </button>
  );
}
/** Input — styled text input with teal focus border */
export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cn("w-full rounded-lg border border-slate-800 bg-slate-950 px-4 py-2.5 text-sm text-slate-100 outline-none placeholder:text-slate-600 transition-all focus:border-teal-500 focus:ring-2 focus:ring-teal-500/20", props.className)} />;
}
/** Textarea — styled multiline text area with monospace font */
export function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cn("w-full rounded-lg border border-slate-800 bg-slate-950 px-4 py-2.5 text-sm text-slate-100 outline-none placeholder:text-slate-600 focus:border-teal-500 mono", props.className)} />;
}
/** Select — styled dropdown select with dark background */
export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={cn("w-full rounded-lg border border-slate-800 bg-slate-950 px-4 py-2.5 text-sm text-slate-100 outline-none focus:border-teal-500", props.className)} />;
}
/** Badge — small colored pill label. Colors: slate, teal, rose, amber, emerald, indigo, blue */
export function Badge({ children, color="slate", className }: { children: React.ReactNode; color?: "slate"|"teal"|"rose"|"amber"|"emerald"|"indigo"|"blue"; className?: string }) {
  const map = {
    slate:   "bg-slate-800/50 text-slate-400 border-slate-700/50",
    teal:    "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    blue:    "bg-blue-500/10 text-blue-400 border-blue-500/20",
    rose:    "bg-rose-500/10 text-rose-400 border-rose-500/20",
    amber:   "bg-amber-500/10 text-amber-400 border-amber-500/20",
    emerald: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    indigo:  "bg-indigo-500/10 text-indigo-400 border-indigo-500/20",
  };
  return <span className={cn("inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider", map[color], className)}>{children}</span>;
}
/** CopyButton — copies text to clipboard and shows a toast notification */
export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button onClick={() => { navigator.clipboard?.writeText(text); setCopied(true); window.dispatchEvent(new CustomEvent("toast",{detail:{message:"Copied to clipboard",type:"info"}})); setTimeout(()=>setCopied(false),1200); }}
      className="rounded-md border border-slate-700 px-2 py-1 text-xs text-slate-300 hover:border-teal-500 hover:text-teal-300">
      {copied ? "Copied!" : "Copy"}
    </button>
  );
}
/** ResultBox — dark container for displaying scan results with an optional section title */
export function ResultBox({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <div className="mt-4 rounded-lg border border-slate-800 bg-slate-950/60 p-4">
      {title && <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500">{title}</div>}
      {children}
    </div>
  );
}
/** KeyVal — renders a dictionary as a two-column key/value list. Used for WHOIS, headers, geolocation, etc. */
export function KeyVal({ data }: { data: Record<string, React.ReactNode> }) {
  return (
    <div className="divide-y divide-slate-800">
      {Object.entries(data).map(([k,v]) => (
        <div key={k} className="flex items-center justify-between gap-4 py-2 text-sm">
          <span className="text-slate-400">{k}</span>
          <span className="mono text-right text-slate-100">{v}</span>
        </div>
      ))}
    </div>
  );
}
/** Spinner — animated loading indicator shown while a scan is running */
export function Spinner() {
  return <div className="flex items-center gap-2 text-sm text-teal-300"><div className="h-4 w-4 animate-spin rounded-full border-2 border-teal-500/30 border-t-teal-400" />Running scan…</div>;
}
