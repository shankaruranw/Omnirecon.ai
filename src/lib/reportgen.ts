import type { ScanRecord, ReportType } from "./history";
const RISK_WEIGHT: Record<string,number> = { Critical:4, High:3, Medium:2, Low:1, Info:0 };
export function summarize(records: ScanRecord[]) {
  const counts = { Critical:0, High:0, Medium:0, Low:0, Info:0 } as Record<string,number>;
  const modules = new Set<string>(); const targets = new Set<string>(); let weighted = 0;
  for (const r of records) {
    if (r.risk) counts[r.risk] = (counts[r.risk]||0)+1;
    modules.add(r.module); targets.add(r.target);
    weighted += RISK_WEIGHT[r.risk||"Info"]||0;
  }
  const max = records.length*4||1;
  const score = Math.round((weighted/max)*100);
  const posture = score>=70?"Critical":score>=50?"High":score>=30?"Elevated":score>=10?"Moderate":"Low";
  return { counts, modules:[...modules], targets:[...targets], score, posture, total:records.length };
}
function esc(s: string) { return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function riskBadge(risk?: string) {
  const colors: Record<string,string> = { Critical:"#f43f5e", High:"#fb7185", Medium:"#f59e0b", Low:"#10b981", Info:"#64748b" };
  const c = colors[risk||"Info"]||"#64748b";
  return `<span style="display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600;color:#fff;background:${c}">${risk||"Info"}</span>`;
}
export function buildReportHtml(type: ReportType, records: ScanRecord[], scopeLabel: string): string {
  const s = summarize(records); const now = new Date().toLocaleString();
  const scoreColor = s.score>=50?"#f43f5e":s.score>=30?"#f59e0b":"#10b981";
  const head = `<div class="hdr"><div class="brand">OMNI<span>RECON AI</span></div><div class="meta"><div><strong>${type} Report</strong></div><div>Scope: ${esc(scopeLabel)}</div><div>Generated: ${now}</div></div></div>`;
  const scoreCard = `<div class="scorecard"><div class="gauge" style="--c:${scoreColor}"><div class="gnum" style="color:${scoreColor}">${s.score}</div><div class="glabel">/100</div></div><div><div class="muted">Overall Security Posture</div><div class="posture" style="color:${scoreColor}">${s.posture}</div><div class="muted">${s.total} scans · ${s.targets.length} targets · ${s.modules.length} modules</div></div></div>`;
  const riskBars = `<div class="riskgrid">${["Critical","High","Medium","Low","Info"].map(k=>`<div class="riskcell"><div class="riskcount">${s.counts[k]||0}</div><div class="risklabel">${k}</div></div>`).join("")}</div>`;
  let body = "";
  if (type==="Executive"||type==="PDF") {
    const topFindings = records.filter(r=>r.risk==="Critical"||r.risk==="High").slice(0,8);
    body = `${scoreCard}<h2>Executive Summary</h2><p>This report consolidates <strong>${s.total}</strong> security assessments across <strong>${s.modules.length}</strong> modules against <strong>${s.targets.length}</strong> target(s). Aggregate risk: <strong style="color:${scoreColor}">${s.posture}</strong> (${s.score}/100).</p><h3>Risk Distribution</h3>${riskBars}<h3>Key Findings</h3>${topFindings.length?`<ul>${topFindings.map(r=>`<li>${riskBadge(r.risk)} <strong>${esc(r.tool)}</strong> — ${esc(r.summary)} <span class="muted">(${esc(r.target)})</span></li>`).join("")}</ul>`:`<p class="muted">No critical or high-severity findings.</p>`}<h3>Recommended Priorities</h3><ol><li>Remediate all Critical and High findings immediately.</li><li>Re-scan affected assets to validate fixes.</li><li>Establish continuous monitoring for the exposed attack surface.</li></ol>`;
  } else if (type==="Technical") {
    const rows = records.map(r=>`<tr><td>${new Date(r.timestamp).toLocaleString()}</td><td>${esc(r.module)}</td><td>${esc(r.tool)}</td><td class="mono">${esc(r.target)}</td><td>${esc(r.summary)}</td><td>${riskBadge(r.risk)}</td></tr>`).join("");
    body = `${scoreCard}<h2>Technical Assessment</h2>${riskBars}<h3>Full Scan Log (${records.length})</h3><table><thead><tr><th>Time</th><th>Module</th><th>Tool</th><th>Target</th><th>Result</th><th>Risk</th></tr></thead><tbody>${rows}</tbody></table>`;
  } else {
    body = `${scoreCard}<h2>🤖 AI-Generated Summary</h2><p>Automated analysis engine reviewed ${s.total} signals across ${s.modules.join(", ")}. The environment shows a ${s.posture.toLowerCase()} overall posture (${s.score}/100). ${(s.counts.Critical||0)+(s.counts.High||0)>0?"Immediate remediation is advised.":"No high-impact issues detected."}</p>${riskBars}<h3>AI Recommended Next Steps</h3><ul><li>✓ Address Critical findings immediately.</li><li>✓ Schedule High findings for remediation within the current sprint.</li><li>✓ Enable WAF, HSTS, DMARC if not already present.</li><li>✓ Automate weekly re-scans.</li></ul>`;
  }
  return wrap(head+body);
}
function wrap(inner: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><title>OmniRecon AI Report</title><style>*{box-sizing:border-box}body{font-family:-apple-system,Segoe UI,sans-serif;color:#0f172a;margin:0;padding:32px;background:#fff;line-height:1.5}.hdr{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:3px solid #0d9488;padding-bottom:14px;margin-bottom:22px}.brand{font-size:26px;font-weight:800;letter-spacing:-.5px}.brand span{color:#0d9488}.meta{text-align:right;font-size:12px;color:#475569}h2{font-size:18px;margin:24px 0 10px}h3{font-size:14px;margin:20px 0 8px;color:#334155;text-transform:uppercase;letter-spacing:.5px}p{font-size:13px;color:#1e293b}.muted{color:#64748b;font-size:12px}.scorecard{display:flex;align-items:center;gap:20px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:18px;margin-bottom:8px}.gauge{width:84px;height:84px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;border:8px solid var(--c);flex-shrink:0}.gnum{font-size:26px;font-weight:800;line-height:1}.glabel{font-size:10px;color:#94a3b8}.posture{font-size:24px;font-weight:800;margin:2px 0}.riskgrid{display:flex;gap:10px;margin:10px 0}.riskcell{flex:1;text-align:center;border:1px solid #e2e8f0;border-radius:10px;padding:10px}.riskcount{font-size:22px;font-weight:800}.risklabel{font-size:11px;color:#64748b;text-transform:uppercase}ul,ol{font-size:13px;color:#1e293b;padding-left:20px}li{margin:5px 0}table{width:100%;border-collapse:collapse;font-size:11px;margin-top:8px}th{background:#0f172a;color:#fff;text-align:left;padding:7px 8px}td{border-bottom:1px solid #e2e8f0;padding:6px 8px;vertical-align:top}.mono{font-family:monospace}@media print{body{padding:0}}</style></head><body>${inner}</body></html>`;
}
export function openPrint(html: string) { const w=window.open("","_blank"); if(!w)return; w.document.write(html); w.document.close(); setTimeout(()=>w.print(),400); }
export function downloadHtml(html: string, name: string) { const a=document.createElement("a"); a.href=URL.createObjectURL(new Blob([html],{type:"text/html"})); a.download=name; a.click(); }
