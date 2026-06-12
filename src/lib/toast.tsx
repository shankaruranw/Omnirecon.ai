import { createContext, useCallback, useContext, useEffect, useState } from "react";
import * as Icons from "lucide-react";
type ToastType = "success"|"error"|"info";
type Toast = { id: number; type: ToastType; message: string };
const ToastCtx = createContext<(message: string, type?: ToastType) => void>(() => {});
export function useToast() { return useContext(ToastCtx); }
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((message: string, type: ToastType = "success") => {
    const id = Date.now() + Math.random();
    setToasts(t => [...t, { id, type, message }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), 3000);
  }, []);
  useEffect(() => {
    const h = (e: Event) => { const d = (e as CustomEvent).detail; if(d?.message) push(d.message, d.type); };
    window.addEventListener("toast", h); return () => window.removeEventListener("toast", h);
  }, [push]);
  const cfg = {
    success: { icon: Icons.CheckCircle2, cls: "border-emerald-500/40 text-emerald-300" },
    error:   { icon: Icons.AlertCircle,  cls: "border-rose-500/40 text-rose-300" },
    info:    { icon: Icons.Info,         cls: "border-teal-500/40 text-teal-300" },
  };
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
        {toasts.map(t => { const c=cfg[t.type]; const I=c.icon; return (
          <div key={t.id} className={`fade-in pointer-events-auto flex items-center gap-2 rounded-lg border bg-slate-900/95 px-4 py-2.5 text-sm shadow-xl backdrop-blur ${c.cls}`}>
            <I className="h-4 w-4 shrink-0" /><span className="text-slate-100">{t.message}</span>
          </div>
        );})}
      </div>
    </ToastCtx.Provider>
  );
}
export function toast(message: string, type: "success"|"error"|"info" = "success") {
  window.dispatchEvent(new CustomEvent("toast", { detail: { message, type } }));
}
