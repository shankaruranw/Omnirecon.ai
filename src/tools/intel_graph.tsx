/**
 * OmniRecon AI — Intelligence Graph (Module 13)
 * ===============================================
 * Tool: Relationship Graph
 * Visualizes Domain ↔ IP ↔ ASN ↔ SSL ↔ Subdomains connections.
 * Built with pure SVG — no external charting library needed.
 */

import { useState } from "react";
import { Button, Input, Spinner } from "../lib/ui";
import { seeded, pick, randInt, randIp, delay } from "../lib/sim";
import { addHistory } from "../lib/history";

// ── Types ─────────────────────────────────────────────────────────────────────

type Node = { id: string; label: string; type: string; x: number; y: number };
type Edge = { from: string; to: string };

// ── Color map for node types ──────────────────────────────────────────────────

const NODE_COLORS: Record<string, string> = {
  domain:    "#2dd4bf",
  ip:        "#3b82f6",
  asn:       "#f59e0b",
  ssl:       "#10b981",
  subdomain: "#a78bfa",
  mx:        "#f43f5e",
  ns:        "#fb923c",
};

// ── Graph renderer ────────────────────────────────────────────────────────────

function GraphCanvas({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
  const [tooltip, setTooltip] = useState<Node | null>(null);
  const W = 760; const H = 420;

  return (
    <div className="relative">
      <svg width="100%" viewBox={`0 0 ${W} ${H}`}
        className="rounded-xl border border-slate-800 bg-slate-950/80">
        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8"
            refX="8" refY="3" orient="auto">
            <path d="M0,0 L0,6 L9,3 z" fill="#334155"/>
          </marker>
        </defs>

        {/* Edges */}
        {edges.map((e, i) => {
          const from = nodes.find(n => n.id === e.from);
          const to   = nodes.find(n => n.id === e.to);
          if (!from || !to) return null;
          return (
            <line key={i}
              x1={from.x} y1={from.y} x2={to.x} y2={to.y}
              stroke="#1e293b" strokeWidth="1.5" strokeDasharray="4 3"
              markerEnd="url(#arrow)" />
          );
        })}

        {/* Nodes */}
        {nodes.map(n => {
          const c = NODE_COLORS[n.type] || "#64748b";
          const isCenter = n.type === "domain";
          const r = isCenter ? 36 : 28;
          return (
            <g key={n.id} onMouseEnter={() => setTooltip(n)} onMouseLeave={() => setTooltip(null)}
              style={{cursor:"pointer"}}>
              {/* Glow ring */}
              <circle cx={n.x} cy={n.y} r={r + 6} fill={c} opacity="0.08"/>
              {/* Main circle */}
              <circle cx={n.x} cy={n.y} r={r} fill={`${c}22`}
                stroke={c} strokeWidth={isCenter ? 2.5 : 1.5}/>
              {/* Icon text */}
              <text x={n.x} y={n.y - 4} textAnchor="middle"
                fontSize={isCenter ? 14 : 11} fill={c} fontWeight="700">
                {n.type === "domain"    ? "🌐" :
                 n.type === "ip"       ? "📡" :
                 n.type === "asn"      ? "🔗" :
                 n.type === "ssl"      ? "🔒" :
                 n.type === "subdomain"? "⬡"  :
                 n.type === "mx"       ? "📧" : "🔵"}
              </text>
              {/* Label */}
              <text x={n.x} y={n.y + 12} textAnchor="middle"
                fontSize={isCenter ? 10 : 8.5} fill={c} fontWeight="600">
                {n.label.length > 18 ? n.label.slice(0,16)+"…" : n.label}
              </text>
              {/* Type badge */}
              <text x={n.x} y={n.y + r + 14} textAnchor="middle"
                fontSize="7.5" fill="#475569" fontWeight="500">
                {n.type.toUpperCase()}
              </text>
            </g>
          );
        })}

        {/* Tooltip */}
        {tooltip && (
          <g>
            <rect x={tooltip.x + 12} y={tooltip.y - 30} width={160} height={44}
              rx="6" fill="#0f172a" stroke="#334155" strokeWidth="1"/>
            <text x={tooltip.x + 20} y={tooltip.y - 12}
              fontSize="11" fill="#f1f5f9" fontWeight="700">{tooltip.label}</text>
            <text x={tooltip.x + 20} y={tooltip.y + 4}
              fontSize="9.5" fill="#64748b">{tooltip.type.toUpperCase()}</text>
          </g>
        )}
      </svg>

      {/* Legend */}
      <div className="mt-3 flex flex-wrap gap-3">
        {Object.entries(NODE_COLORS).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1.5 text-xs text-slate-400">
            <div className="h-3 w-3 rounded-full" style={{background:color, opacity:0.8}}/>
            {type}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Graph layout builder ──────────────────────────────────────────────────────

function buildGraph(domain: string): { nodes: Node[]; edges: Edge[] } {
  const rng = seeded(domain + "graph");
  const W = 760; const H = 420;
  const cx = W / 2; const cy = H / 2;

  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Centre node — domain
  nodes.push({ id: "domain", label: domain, type: "domain", x: cx, y: cy });

  // IPs — arranged around the domain
  const ipCount = randInt(rng, 2, 4);
  for (let i = 0; i < ipCount; i++) {
    const angle = (i / ipCount) * 2 * Math.PI - Math.PI / 2;
    const ip    = randIp(rng);
    const id    = `ip_${i}`;
    nodes.push({ id, label: ip, type: "ip",
      x: cx + Math.cos(angle) * 160, y: cy + Math.sin(angle) * 130 });
    edges.push({ from: "domain", to: id });

    // ASN for each IP
    const asnId = `asn_${i}`;
    const asnAngle = angle + 0.4;
    nodes.push({ id: asnId, label: `AS${randInt(rng,1000,60000)}`, type: "asn",
      x: cx + Math.cos(asnAngle) * 300, y: cy + Math.sin(asnAngle) * 210 });
    edges.push({ from: id, to: asnId });
  }

  // Subdomains
  const subs = ["www","mail","api","dev","admin"].filter(() => rng() > 0.4);
  subs.forEach((s, i) => {
    const angle = ((i + 0.5) / subs.length) * 2 * Math.PI + Math.PI / 6;
    const id    = `sub_${i}`;
    nodes.push({ id, label: `${s}.${domain}`, type: "subdomain",
      x: Math.min(W-50, Math.max(50, cx + Math.cos(angle) * 250)),
      y: Math.min(H-40, Math.max(40, cy + Math.sin(angle) * 170)) });
    edges.push({ from: "domain", to: id });
  });

  // SSL cert node
  nodes.push({ id: "ssl", label: pick(rng,["Let's Encrypt","DigiCert","Sectigo"]), type: "ssl",
    x: cx + 10, y: cy - 195 });
  edges.push({ from: "domain", to: "ssl" });

  // MX node
  nodes.push({ id: "mx", label: `mail.${domain}`, type: "mx",
    x: cx - 220, y: cy + 60 });
  edges.push({ from: "domain", to: "mx" });

  // NS nodes
  ["ns1","ns2"].forEach((ns, i) => {
    nodes.push({ id: `ns_${i}`, label: `${ns}.${domain}`, type: "ns",
      x: cx + 200 + i * 30, y: cy + 170 });
    edges.push({ from: "domain", to: `ns_${i}` });
  });

  return { nodes, edges };
}

// ── Main component ────────────────────────────────────────────────────────────

export function IntelGraph() {
  const [domain, setDomain]   = useState("");
  const [graph, setGraph]     = useState<{ nodes: Node[]; edges: Edge[] } | null>(null);
  const [loading, setLoading] = useState(false);

  const buildMap = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    await delay(1000 + Math.random() * 600);
    setGraph(buildGraph(domain.trim()));
    setLoading(false);
    addHistory({ module:"Intelligence Graph", tool:"Relationship Graph", target:domain,
      summary:"Domain intelligence graph generated" });
  };

  return (
    <div>
      <p className="mb-3 text-sm text-slate-400">
        Enter a domain to visualize its complete relationship map — IPs, ASNs, subdomains, SSL and mail servers.
      </p>
      <div className="flex gap-2 mb-5">
        <Input value={domain} onChange={e => setDomain(e.target.value)}
          placeholder="example.com" onKeyDown={e => e.key==="Enter" && buildMap()}/>
        <Button onClick={buildMap} disabled={loading}>
          {loading ? "Mapping…" : "Build Graph"}
        </Button>
      </div>
      {loading && <Spinner />}
      {graph && !loading && <GraphCanvas nodes={graph.nodes} edges={graph.edges}/>}
      {!graph && !loading && (
        <div className="rounded-xl border border-dashed border-slate-800 p-16 text-center text-slate-600 text-sm">
          Enter a domain above to generate the intelligence relationship graph.
        </div>
      )}
    </div>
  );
}
