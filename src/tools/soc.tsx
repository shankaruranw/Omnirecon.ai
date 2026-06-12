/**
 * OmniRecon AI — SOC Dashboard (Module 14)
 * ==========================================
 * Tool: SOC Overview
 * Security Operations Center live view:
 * Recent scans, high-risk targets, alerts, and statistics.
 */

import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { getHistory, type ScanRecord } from "../lib/history";
import { Badge, Card } from "../lib/ui";
import * as Icons from "lucide-react";

// ── Helper ────────────────────────────────────────────────────────────────────

function riskColor(r?: string) {
  return r === "Critical" ? "rose"
       : r === "High"     ? "rose"
       : r === "Medium"   ? "amber"
       : r === "Low"      ? "emerald"
       : "slate";
}

function riskHex(r?: string) {
  return r === "Critical" ? "#f43f5e"
       : r === "High"     ? "#fb923c"
       : r === "Medium"   ? "#f59e0b"
       : "#10b981";
}

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, icon, color, sub }: {
  label: string; value: string | number; icon: React.ReactNode;
  color: string; sub?: string;
}) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs text-slate-400">{label}</span>
        <span style={{ color }}>{icon}</span>
      </div>
      <div className="text-3xl font-black" style={{ color }}>{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </Card>
  );
}

// ── Alert item ────────────────────────────────────────────────────────────────

function AlertItem({ scan }: { scan: ScanRecord }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2.5">
      <div className="mt-0.5 h-2 w-2 shrink-0 rounded-full animate-pulse" style={{ background: riskHex(scan.risk) }}/>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm font-semibold text-slate-100">{scan.tool}</span>
          <Badge color={riskColor(scan.risk) as any}>{scan.risk}</Badge>
        </div>
        <div className="mono text-xs text-teal-400 truncate">{scan.target}</div>
        <div className="text-xs text-slate-600">{new Date(scan.timestamp).toLocaleString()}</div>
      </div>
    </div>
  );
}

// ── Main SOC Dashboard ────────────────────────────────────────────────────────

export function SocDashboard() {
  const [history, setHistory] = useState<ScanRecord[]>([]);

  useEffect(() => {
    const u = () => setHistory(getHistory());
    u();
    window.addEventListener("history-updated", u);
    return () => window.removeEventListener("history-updated", u);
  }, []);

  // Compute stats
  const total     = history.length;
  const critical  = history.filter(h => h.risk === "Critical").length;
  const high      = history.filter(h => h.risk === "High").length;
  const low       = history.filter(h => h.risk === "Low" || h.risk === "Info").length;
  const alerts    = history.filter(h => h.risk === "Critical" || h.risk === "High");
  const recent    = history.slice(0, 8);

  // High-risk targets (unique targets with high/critical scans)
  const highTargets = Array.from(
    new Set(alerts.map(a => a.target))
  ).slice(0, 6);

  // Module breakdown
  const moduleCounts: Record<string, number> = {};
  history.forEach(h => { moduleCounts[h.module] = (moduleCounts[h.module] || 0) + 1; });
  const topModules = Object.entries(moduleCounts).sort((a,b)=>b[1]-a[1]).slice(0, 5);

  // Risk distribution for mini bar chart
  const riskDist = [
    { label: "Critical", count: critical,                              color: "#f43f5e" },
    { label: "High",     count: high,                                  color: "#fb923c" },
    { label: "Medium",   count: history.filter(h=>h.risk==="Medium").length, color: "#f59e0b" },
    { label: "Low",      count: low,                                   color: "#10b981" },
  ];
  const maxCount = Math.max(...riskDist.map(r => r.count), 1);

  return (
    <div className="space-y-5 fade-in">

      {/* Status bar */}
      <div className="flex items-center gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-4 py-3">
        <span className="relative flex h-3 w-3">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50"/>
          <span className="relative inline-flex h-3 w-3 rounded-full bg-emerald-400"/>
        </span>
        <span className="text-sm font-semibold text-emerald-300">SOC Engine Online</span>
        <span className="ml-auto text-xs text-slate-500">
          Last updated: {total > 0 ? new Date(history[0].timestamp).toLocaleTimeString() : "No activity"}
        </span>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Total Scans"     value={total}    icon={<Icons.Activity className="h-4 w-4"/>}    color="#2dd4bf"  sub="All time"/>
        <StatCard label="Critical Alerts" value={critical} icon={<Icons.AlertTriangle className="h-4 w-4"/>} color="#f43f5e" sub="Immediate action"/>
        <StatCard label="High Alerts"     value={high}     icon={<Icons.AlertCircle className="h-4 w-4"/>}   color="#fb923c" sub="Review soon"/>
        <StatCard label="Clean Scans"     value={low}      icon={<Icons.ShieldCheck className="h-4 w-4"/>}   color="#10b981" sub="Low / Info"/>
      </div>

      {/* Main content grid */}
      <div className="grid gap-5 lg:grid-cols-3">

        {/* Left col — Alerts + Recent */}
        <div className="lg:col-span-2 space-y-5">

          {/* Active Alerts */}
          <Card className="p-4">
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Icons.Bell className="h-4 w-4 text-rose-400"/> Active Alerts
                {alerts.length > 0 && (
                  <span className="rounded-full bg-rose-500/20 px-2 py-0.5 text-[10px] font-bold text-rose-300">
                    {alerts.length}
                  </span>
                )}
              </h3>
              <Link to="/module/reports" className="text-xs text-teal-400 hover:underline">View all →</Link>
            </div>
            <div className="space-y-2">
              {alerts.length === 0 && (
                <div className="py-6 text-center text-sm text-slate-500">
                  <Icons.CheckCircle2 className="mx-auto mb-2 h-8 w-8 text-emerald-500/30"/>
                  No critical or high alerts. System looks healthy.
                </div>
              )}
              {alerts.slice(0, 5).map(a => <AlertItem key={a.id} scan={a}/>)}
            </div>
          </Card>

          {/* Recent Scans */}
          <Card className="p-4">
            <h3 className="mb-3 text-sm font-bold text-slate-100 flex items-center gap-2">
              <Icons.Clock className="h-4 w-4 text-teal-400"/> Recent Scan Activity
            </h3>
            <div className="divide-y divide-slate-800">
              {recent.length === 0 && (
                <div className="py-6 text-center text-sm text-slate-500">
                  No scans yet. Run tools to see activity here.
                </div>
              )}
              {recent.map(s => (
                <div key={s.id} className="flex items-center gap-3 py-2.5">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-800 text-teal-400">
                    <Icons.Terminal className="h-3.5 w-3.5"/>
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-slate-200 truncate">{s.tool}</div>
                    <div className="mono text-xs text-slate-500 truncate">{s.target}</div>
                  </div>
                  <div className="text-right shrink-0">
                    <Badge color={riskColor(s.risk) as any}>{s.risk || "Info"}</Badge>
                    <div className="text-[10px] text-slate-600 mt-1">{new Date(s.timestamp).toLocaleTimeString()}</div>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* Right col — Risk chart + High-risk targets + Module stats */}
        <div className="space-y-5">

          {/* Risk Distribution */}
          <Card className="p-4">
            <h3 className="mb-4 text-sm font-bold text-slate-100 flex items-center gap-2">
              <Icons.BarChart3 className="h-4 w-4 text-teal-400"/> Risk Distribution
            </h3>
            <div className="space-y-3">
              {riskDist.map(r => (
                <div key={r.label}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-400">{r.label}</span>
                    <span className="font-bold" style={{color:r.color}}>{r.count}</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                    <div className="h-full rounded-full transition-all" style={{
                      width: `${(r.count / maxCount) * 100}%`,
                      background: r.color,
                    }}/>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* High-Risk Targets */}
          <Card className="p-4">
            <h3 className="mb-3 text-sm font-bold text-slate-100 flex items-center gap-2">
              <Icons.Target className="h-4 w-4 text-rose-400"/> High-Risk Targets
            </h3>
            {highTargets.length === 0 && (
              <div className="text-xs text-slate-500 py-3 text-center">No high-risk targets detected.</div>
            )}
            <div className="space-y-2">
              {highTargets.map((t, i) => (
                <div key={i} className="flex items-center gap-2 rounded-lg border border-rose-500/15 bg-rose-500/5 px-3 py-2">
                  <Icons.AlertTriangle className="h-3.5 w-3.5 text-rose-400 shrink-0"/>
                  <span className="mono text-xs text-rose-300 truncate">{t}</span>
                </div>
              ))}
            </div>
          </Card>

          {/* Top Modules */}
          <Card className="p-4">
            <h3 className="mb-3 text-sm font-bold text-slate-100 flex items-center gap-2">
              <Icons.LayoutGrid className="h-4 w-4 text-teal-400"/> Top Modules Used
            </h3>
            {topModules.length === 0 && (
              <div className="text-xs text-slate-500 py-3 text-center">No module activity yet.</div>
            )}
            <div className="space-y-2">
              {topModules.map(([mod, count]) => (
                <div key={mod} className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 truncate">{mod}</span>
                  <span className="font-bold text-teal-400 shrink-0 ml-2">{count} scans</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
