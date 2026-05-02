"""Generate a self-contained interactive HTML threat intelligence report.

Takes run_pipeline() JSON output and produces a browser-ready HTML file with:
  - Live summary strip (IOC / technique / hypothesis / rule counts + stage badges)
  - D3.js layered force graph: IOCs → Techniques → Tactics with confidence weighting,
    click-to-highlight, hover tooltips, zoom/pan, tactic filter
  - ATT&CK Navigator-style tactic heatmap (click tactic to filter graph)
  - Hunt hypothesis cards with tabbed SPL / KQL / Elastic query viewer
  - Sigma rule cards with expandable YAML, status badge, and fallback search links
  - Full IOC table with type, confidence bar, and malicious/victim label

No server required — single self-contained HTML file. D3 v7 from CDN.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


_TACTIC_COLORS: dict[str, str] = {
    "initial-access": "#c0392b",
    "execution": "#e67e22",
    "persistence": "#f1c40f",
    "privilege-escalation": "#e74c3c",
    "defense-evasion": "#9b59b6",
    "credential-access": "#2980b9",
    "discovery": "#1abc9c",
    "lateral-movement": "#27ae60",
    "collection": "#2ecc71",
    "command-and-control": "#e74c3c",
    "exfiltration": "#8e44ad",
    "impact": "#c0392b",
}

_TACTIC_ORDER = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def _ioc_rows(ioc_list: list, ioc_type: str) -> list[dict]:
    rows = []
    for i in ioc_list:
        if isinstance(i, dict):
            rows.append(
                {
                    "value": i.get("value", ""),
                    "confidence": round(i.get("confidence", 0.5) * 100),
                    "label": i.get("label", "UNKNOWN"),
                    "type": ioc_type,
                }
            )
        else:
            rows.append({"value": str(i), "confidence": 50, "label": "UNKNOWN", "type": ioc_type})
    return rows


def generate_html_report(
    pipeline_json: str,
    title: str = "",
    output_path: str = "",
) -> str:
    """Generate an interactive HTML report from run_pipeline() JSON output.

    Args:
        pipeline_json: JSON string returned by run_pipeline().
        title: Optional report title.
        output_path: Optional file path for the HTML file.

    Returns: JSON with {"html_path": str, "bytes": int, "summary": dict}
    """
    try:
        data: dict[str, Any] = json.loads(pipeline_json)
    except json.JSONDecodeError as exc:
        return json.dumps({"error": f"Invalid pipeline JSON: {exc}"})

    report_title = (
        title or f"Threat Intelligence Report — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    )
    timestamp = datetime.utcnow().isoformat() + "Z"

    iocs_raw = data.get("iocs", {})
    ioc_rows: list[dict] = []
    for ioc_type in ("ips", "domains", "urls", "hashes", "emails"):
        ioc_rows.extend(_ioc_rows(iocs_raw.get(ioc_type, []), ioc_type))

    techniques: list[dict] = data.get("techniques", {}).get("techniques", [])
    suppressed: list[dict] = data.get("techniques", {}).get("suppressed", [])
    hypotheses: list[dict] = data.get("hunt_hypotheses", {}).get("hypotheses", [])
    sigma_rules: list[dict] = data.get("detections", {}).get("sigma", {}).get("rules", [])
    summary = data.get("summary", {})

    # Build graph nodes and links
    graph_nodes: list[dict] = []
    graph_links: list[dict] = []
    node_ids: set[str] = set()

    for row in ioc_rows[:25]:
        nid = f"ioc::{row['value']}"
        if nid not in node_ids:
            node_ids.add(nid)
            ioc_color = (
                "#e74c3c"
                if row["type"] in ("ips", "domains", "urls")
                else "#3498db"
                if row["type"] == "hashes"
                else "#f39c12"
            )
            graph_nodes.append(
                {
                    "id": nid,
                    "group": "ioc",
                    "type": row["type"],
                    "label": row["value"][:28] + ("…" if len(row["value"]) > 28 else ""),
                    "full": row["value"],
                    "color": ioc_color,
                    "confidence": row["confidence"] / 100,
                    "layer": 0,
                }
            )

    for t in techniques:
        nid = t["id"]
        if nid not in node_ids:
            node_ids.add(nid)
            color = _TACTIC_COLORS.get(t["tactic"], "#f39c12")
            graph_nodes.append(
                {
                    "id": nid,
                    "group": "technique",
                    "tactic": t["tactic"],
                    "label": t["id"],
                    "name": t.get("name", ""),
                    "color": color,
                    "confidence": t.get("confidence", 0),
                    "evidence": t.get("evidence", []),
                    "layer": 1,
                }
            )
        tac_id = f"tactic::{t['tactic']}"
        if tac_id not in node_ids:
            node_ids.add(tac_id)
            graph_nodes.append(
                {
                    "id": tac_id,
                    "group": "tactic",
                    "label": t["tactic"].replace("-", " ").title(),
                    "color": _TACTIC_COLORS.get(t["tactic"], "#555"),
                    "layer": 2,
                }
            )
        for ioc_row in ioc_rows[:25]:
            for ev in t.get("evidence", []):
                if ev.lower() in ioc_row["value"].lower() or ioc_row["value"].lower() in ev.lower():
                    src = f"ioc::{ioc_row['value']}"
                    if src in node_ids:
                        graph_links.append(
                            {
                                "source": src,
                                "target": nid,
                                "type": "ioc_technique",
                                "strength": t.get("confidence", 0.5),
                            }
                        )
                        break
        graph_links.append(
            {
                "source": nid,
                "target": tac_id,
                "type": "technique_tactic",
                "strength": 1.0,
            }
        )

    js_data = {
        "title": report_title,
        "timestamp": timestamp,
        "summary": {
            "ioc_count": len(ioc_rows),
            "technique_count": len(techniques),
            "suppressed_count": len(suppressed),
            "hypothesis_count": len(hypotheses),
            "sigma_rule_count": len(sigma_rules),
            "stages": summary.get("stages_completed", []),
            "text_chars": summary.get("text_chars_analyzed", 0),
            "confidence_threshold": data.get("techniques", {}).get("confidence_threshold", 0.45),
        },
        "ioc_rows": ioc_rows,
        "techniques": techniques,
        "suppressed": suppressed,
        "hypotheses": hypotheses,
        "sigma_rules": sigma_rules,
        "graph": {"nodes": graph_nodes, "links": graph_links},
        "tactic_colors": _TACTIC_COLORS,
        "tactic_order": _TACTIC_ORDER,
    }

    html = _render_html(js_data)

    if not output_path:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = str(Path(os.getcwd()) / f"threat_report_{ts}.html")

    Path(output_path).write_text(html, encoding="utf-8")

    return json.dumps(
        {
            "html_path": output_path,
            "bytes": len(html.encode("utf-8")),
            "open_cmd": f"start {output_path}" if os.name == "nt" else f"open {output_path}",
            "summary": js_data["summary"],
        },
        indent=2,
    )


def _render_html(data: dict) -> str:
    data_json = json.dumps(data, ensure_ascii=False)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{data["title"]}</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
:root{{
  --bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --green:#3fb950;--orange:#d29922;--red:#f85149;--purple:#bc8cff;
  --radius:8px;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.5;overflow-x:hidden}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
h2{{font-size:1.05rem;font-weight:700;margin-bottom:14px;color:var(--text);display:flex;align-items:center;gap:8px}}
h2 .icon{{font-size:1.2rem}}
.container{{max-width:1500px;margin:0 auto;padding:20px}}
.section{{margin-bottom:36px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px}}

/* Header */
.report-header{{background:linear-gradient(135deg,#161b22 0%,#0d1117 100%);border:1px solid var(--border);border-radius:12px;padding:20px 24px;margin-bottom:24px;display:flex;align-items:center;gap:20px}}
.report-badge{{width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,#1f6feb,#388bfd);display:flex;align-items:center;justify-content:center;font-size:1.6rem;flex-shrink:0}}
.report-title{{font-size:1.4rem;font-weight:700;line-height:1.2}}
.report-meta{{color:var(--muted);font-size:.8rem;margin-top:4px}}
.stage-badge{{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:2px 8px;font-size:.68rem;color:var(--muted);margin:2px}}

/* Stat strip */
.stat-strip{{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:24px}}
@media(max-width:1000px){{.stat-strip{{grid-template-columns:repeat(3,1fr)}}}}
@media(max-width:600px){{.stat-strip{{grid-template-columns:repeat(2,1fr)}}}}
.stat-box{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px;text-align:center}}
.stat-box:hover{{border-color:var(--accent);transform:translateY(-1px);transition:.15s}}
.stat-num{{font-size:2rem;font-weight:800;line-height:1}}
.stat-lbl{{font-size:.72rem;color:var(--muted);margin-top:3px}}

/* IOC table */
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse}}
th{{padding:8px 14px;text-align:left;border-bottom:1px solid var(--border);font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-weight:600}}
td{{padding:8px 14px;border-bottom:1px solid var(--border);font-size:.82rem}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:var(--surface2)}}
.mono{{font-family:'Cascadia Code','JetBrains Mono','Consolas',monospace;font-size:.78rem;word-break:break-all}}
.type-pill{{display:inline-block;padding:1px 7px;border-radius:3px;font-size:.66rem;font-weight:700;background:var(--surface2);color:var(--muted);text-transform:uppercase}}
.lbl-pill{{display:inline-block;padding:2px 9px;border-radius:10px;font-size:.68rem;font-weight:700}}
.lbl-MALICIOUS{{background:#3d1a1a;color:#f85149;border:1px solid #f8514955}}
.lbl-VICTIM{{background:#1a2d3d;color:#58a6ff;border:1px solid #58a6ff55}}
.lbl-RESEARCHER{{background:#2d2d1a;color:#d29922;border:1px solid #d2992255}}
.lbl-UNKNOWN{{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}}
.conf-wrap{{display:flex;align-items:center;gap:6px}}
.conf-track{{width:72px;height:5px;background:var(--surface2);border-radius:3px;overflow:hidden}}
.conf-fill{{height:5px;border-radius:3px}}
.conf-pct{{font-size:.72rem;color:var(--muted);min-width:30px}}

/* Heatmap */
.heatmap-scroll{{overflow-x:auto;padding-bottom:4px}}
.heatmap{{display:flex;gap:6px;min-width:900px}}
.hm-col{{flex:1;min-width:110px}}
.hm-head{{padding:5px 8px;border-radius:5px 5px 0 0;font-size:.65rem;font-weight:700;text-align:center;color:#fff;text-transform:uppercase;letter-spacing:.04em}}
.hm-body{{background:#21262d;border-radius:0 0 5px 5px;padding:4px;min-height:36px;cursor:pointer}}
.hm-body:hover{{background:#30363d}}
.hm-cell{{padding:3px 6px;border-radius:3px;font-size:.68rem;font-family:monospace;margin:2px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
.hm-cell:hover{{opacity:.75}}
.hm-empty{{color:var(--muted);font-size:.7rem;text-align:center;padding:8px;font-style:italic}}

/* Graph */
.graph-toolbar{{display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap}}
.graph-btn{{padding:4px 12px;border:1px solid var(--border);background:var(--surface2);color:var(--muted);border-radius:4px;cursor:pointer;font-size:.75rem}}
.graph-btn:hover,.graph-btn.active{{border-color:var(--accent);color:var(--accent)}}
.graph-filter{{display:flex;gap:4px;flex-wrap:wrap}}
.tactic-filter-btn{{padding:3px 10px;border-radius:10px;font-size:.65rem;font-weight:700;cursor:pointer;border:1px solid transparent;opacity:.5;transition:.15s}}
.tactic-filter-btn.on{{opacity:1;border-color:currentColor}}
#graph-svg{{width:100%;height:520px;background:var(--surface2);border-radius:var(--radius);border:1px solid var(--border);display:block}}
.graph-legend{{display:flex;gap:14px;flex-wrap:wrap;margin-top:8px}}
.leg-item{{display:flex;align-items:center;gap:5px;font-size:.73rem;color:var(--muted)}}
.leg-dot{{width:10px;height:10px;border-radius:50%;flex-shrink:0}}

/* Tooltip */
#tooltip{{position:fixed;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 14px;font-size:.78rem;pointer-events:none;z-index:9999;max-width:280px;display:none;box-shadow:0 8px 24px #00000088}}
#tooltip .tt-id{{font-family:monospace;font-weight:700;color:var(--accent);font-size:.85rem}}
#tooltip .tt-name{{color:var(--text);margin-top:2px}}
#tooltip .tt-conf{{color:var(--muted);margin-top:4px;font-size:.72rem}}
#tooltip .tt-ev{{margin-top:6px;display:flex;flex-wrap:wrap;gap:3px}}
#tooltip .tt-chip{{background:var(--surface2);border:1px solid var(--border);border-radius:3px;padding:1px 5px;font-size:.68rem;font-family:monospace}}

/* Hypothesis panel */
.hyp-panel{{display:none;background:var(--surface);border:1px solid var(--accent);border-radius:8px;padding:14px;margin-top:10px}}
.hyp-panel.show{{display:block}}
.hyp-card{{background:var(--surface2);border:1px solid var(--border);border-radius:7px;padding:14px;margin-bottom:10px}}
.hyp-card:last-child{{margin-bottom:0}}
.hyp-header{{display:flex;align-items:center;gap:8px;margin-bottom:8px;flex-wrap:wrap}}
.tac-badge{{padding:2px 9px;border-radius:9px;font-size:.65rem;font-weight:700;color:#fff}}
.src-badge{{font-size:.72rem;color:var(--muted)}}
.hyp-text{{color:var(--muted);font-size:.82rem;margin-bottom:10px;line-height:1.5}}
.q-tabs{{display:flex;gap:4px;margin-bottom:7px}}
.q-tab{{padding:3px 11px;border-radius:4px;border:1px solid var(--border);background:var(--surface);color:var(--muted);cursor:pointer;font-size:.73rem}}
.q-tab.on{{background:var(--accent);color:#fff;border-color:var(--accent)}}
.q-block{{background:#0d1117;border:1px solid var(--border);border-radius:5px;padding:10px 12px;font-family:'Cascadia Code','Consolas',monospace;font-size:.72rem;line-height:1.6;overflow-x:auto;white-space:pre;color:#e6edf3}}
.q-block.hide{{display:none}}

/* Sigma cards */
.sigma-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:15px;margin-bottom:10px;transition:.15s}}
.sigma-card:hover{{border-color:#30363d;background:#1c2128}}
.sigma-header{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px}}
.sigma-tid{{font-family:monospace;font-weight:700;font-size:.9rem}}
.sigma-name{{color:var(--muted);font-size:.82rem}}
.sigma-status-curated{{color:var(--green);font-size:.72rem;font-weight:700}}
.sigma-status-stub{{color:var(--muted);font-size:.72rem}}
.sigma-yaml-block{{background:#0d1117;border:1px solid var(--border);border-radius:5px;padding:10px 12px;font-family:'Cascadia Code','Consolas',monospace;font-size:.7rem;overflow-x:auto;white-space:pre;display:none;margin-top:10px;color:#e6edf3;max-height:400px;overflow-y:auto}}
.sigma-links{{font-size:.78rem;margin-top:8px;display:flex;gap:12px;flex-wrap:wrap}}
.btn-toggle{{background:none;border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:3px 10px;cursor:pointer;font-size:.72rem}}
.btn-toggle:hover{{border-color:var(--accent);color:var(--accent)}}

/* Technique card */
.tech-card{{background:var(--surface);border:1px solid var(--border);border-left:3px solid;border-radius:var(--radius);padding:12px 16px;margin-bottom:9px;cursor:pointer;transition:.15s}}
.tech-card:hover{{background:#1c2128}}
.tech-card.selected{{border-color:var(--accent)!important;background:#1c2128}}
.tech-top{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.tech-tid{{font-family:monospace;font-weight:700}}
.tech-nm{{color:var(--muted);font-size:.82rem}}
.conf-mini{{display:flex;align-items:center;gap:6px;flex:1;min-width:120px}}
.conf-track2{{width:100px;height:6px;background:var(--surface2);border-radius:3px;overflow:hidden}}
.conf-fill2{{height:6px;border-radius:3px}}
.conf-lbl{{font-size:.7rem;font-weight:700}}
.ev-chips{{display:flex;flex-wrap:wrap;gap:3px;margin-top:7px}}
.ev-chip{{background:var(--surface2);border:1px solid var(--border);border-radius:3px;padding:1px 6px;font-size:.68rem;font-family:monospace}}

.no-data{{color:var(--muted);text-align:center;padding:40px;font-size:.88rem}}
</style>
</head>
<body>
<div id="tooltip">
  <div class="tt-id" id="tt-id"></div>
  <div class="tt-name" id="tt-name"></div>
  <div class="tt-conf" id="tt-conf"></div>
  <div class="tt-ev" id="tt-ev"></div>
</div>

<div class="container">

<!-- ── Header ────────────────────────────────────────────────────────────── -->
<div class="report-header">
  <div class="report-badge">&#128270;</div>
  <div style="flex:1">
    <div class="report-title" id="rpt-title"></div>
    <div class="report-meta">
      Generated <span id="rpt-ts"></span> &nbsp;·&nbsp; threat-research-mcp
      &nbsp;·&nbsp; threshold <strong id="rpt-thr" style="color:var(--accent)"></strong>
    </div>
    <div style="margin-top:6px" id="stage-badges"></div>
  </div>
</div>

<!-- ── Stat strip ─────────────────────────────────────────────────────────── -->
<div class="stat-strip" id="stat-strip"></div>

<!-- ── IOCs ──────────────────────────────────────────────────────────────── -->
<div class="section">
  <h2><span class="icon">&#128270;</span> Extracted Indicators of Compromise</h2>
  <div class="card table-wrap">
    <table id="ioc-tbl">
      <thead><tr><th>Type</th><th>Value</th><th>Label</th><th>Confidence</th></tr></thead>
      <tbody id="ioc-body"></tbody>
    </table>
    <div id="ioc-empty" class="no-data" style="display:none">No IOCs extracted.</div>
  </div>
</div>

<!-- ── ATT&CK Heatmap ─────────────────────────────────────────────────────── -->
<div class="section">
  <h2><span class="icon">&#127919;</span> ATT&CK Technique Mapping</h2>
  <div class="card" style="margin-bottom:14px">
    <div style="font-size:.75rem;color:var(--muted);margin-bottom:10px">Click a tactic column to filter the graph below</div>
    <div class="heatmap-scroll"><div class="heatmap" id="heatmap"></div></div>
  </div>

  <!-- Technique cards (clickable → hypothesis drill-down) -->
  <div id="tech-cards-wrap"></div>

  <!-- Suppressed -->
  <div id="supp-wrap" style="display:none;margin-top:8px">
    <details>
      <summary style="cursor:pointer;color:var(--muted);font-size:.83rem;margin-bottom:8px">
        &#9660; Suppressed techniques (below confidence threshold)
      </summary>
      <div id="supp-cards"></div>
    </details>
  </div>
</div>

<!-- ── Graph ──────────────────────────────────────────────────────────────── -->
<div class="section">
  <h2><span class="icon">&#128200;</span> IOC → Technique → Tactic Graph</h2>
  <div class="card" style="padding:12px 16px">
    <div class="graph-toolbar">
      <button class="graph-btn" id="btn-reset">&#8634; Reset View</button>
      <button class="graph-btn" id="btn-labels">Labels On</button>
      <div style="flex:1"></div>
      <div class="graph-filter" id="tactic-filters"></div>
    </div>
    <svg id="graph-svg"></svg>
    <div class="graph-legend">
      <div class="leg-item"><div class="leg-dot" style="background:#e74c3c"></div>IP / Domain</div>
      <div class="leg-item"><div class="leg-dot" style="background:#3498db"></div>Hash</div>
      <div class="leg-item"><div class="leg-dot" style="background:#f39c12"></div>Email IOC</div>
      <div class="leg-item"><div class="leg-dot" style="background:#8e44ad;opacity:.85"></div>Tactic</div>
      <div class="leg-item">
        <svg width="32" height="10"><line x1="0" y1="5" x2="32" y2="5" stroke="#58a6ff" stroke-width="2"/></svg>
        High confidence
      </div>
      <div class="leg-item">
        <svg width="32" height="10"><line x1="0" y1="5" x2="32" y2="5" stroke="#30363d" stroke-width="1" stroke-dasharray="4,3"/></svg>
        Low confidence
      </div>
    </div>
  </div>
</div>

<!-- ── Hypothesis drill-down panel (populated on tech card click) ─────────── -->
<div class="section" id="hyp-section">
  <h2><span class="icon">&#128270;</span> Hunt Hypotheses <span id="hyp-tech-label" style="font-weight:400;color:var(--muted);font-size:.85rem"></span></h2>
  <div id="hyp-cards-wrap"></div>
  <div id="hyp-empty" class="no-data" style="display:none">No hunt hypotheses in playbook for these techniques. Try adding them to playbook/atomic_tests.yaml.</div>
</div>

<!-- ── Sigma Detections ───────────────────────────────────────────────────── -->
<div class="section">
  <h2><span class="icon">&#128737;</span> Sigma Detection Rules</h2>
  <div id="sigma-wrap"></div>
  <div id="sigma-empty" class="no-data" style="display:none">No Sigma rules generated. Curated rules exist for T1059.001, T1003.001, T1071.001.</div>
</div>

</div><!-- /container -->

<script>
const D = {data_json};

// ── helpers ──────────────────────────────────────────────────────────────────
const $= id=>document.getElementById(id);
const el=(tag,cls,html)=>{{const e=document.createElement(tag);if(cls)e.className=cls;if(html!==undefined)e.innerHTML=html;return e;}};
const esc=s=>(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const confColor=c=>c>=.8?'#3fb950':c>=.5?'#d29922':c>=.3?'#e67e22':'#f85149';
const pct=c=>Math.round((c||0)*100);

// ── header ───────────────────────────────────────────────────────────────────
$('rpt-title').textContent=D.title;
$('rpt-ts').textContent=new Date(D.timestamp).toLocaleString();
$('rpt-thr').textContent=D.summary.confidence_threshold.toFixed(2);
$('stage-badges').innerHTML=(D.summary.stages||[]).map(s=>`<span class="stage-badge">${{esc(s.replace(/_/g,' '))}}</span>`).join('');

// ── stat strip ───────────────────────────────────────────────────────────────
[
  [D.summary.ioc_count,'IOCs Extracted','#e74c3c'],
  [D.summary.technique_count,'Techniques','#f39c12'],
  [D.summary.suppressed_count,'Suppressed','#8b949e'],
  [D.summary.hypothesis_count,'Hunt Hypotheses','#3fb950'],
  [D.summary.sigma_rule_count,'Sigma Rules','#58a6ff'],
  [(D.summary.text_chars/1000).toFixed(1)+'k','Chars Analyzed','#8b949e'],
].forEach(([num,label,color])=>{{
  const b=el('div','stat-box');
  b.innerHTML=`<div class="stat-num" style="color:${{color}}">${{num}}</div><div class="stat-lbl">${{label}}</div>`;
  $('stat-strip').appendChild(b);
}});

// ── IOC table ────────────────────────────────────────────────────────────────
if(!D.ioc_rows.length){{$('ioc-empty').style.display='block';$('ioc-tbl').style.display='none';}}
else D.ioc_rows.forEach(r=>{{
  const p=r.confidence;const fc=p>=80?'#3fb950':p>=50?'#d29922':'#f85149';
  const tr=el('tr');
  tr.innerHTML=`<td><span class="type-pill">${{r.type}}</span></td>
    <td class="mono">${{esc(r.value)}}</td>
    <td><span class="lbl-pill lbl-${{r.label}}">${{r.label}}</span></td>
    <td><div class="conf-wrap"><div class="conf-track"><div class="conf-fill" style="width:${{p}}%;background:${{fc}}"></div></div><span class="conf-pct">${{p}}%</span></div></td>`;
  $('ioc-body').appendChild(tr);
}});

// ── heatmap ──────────────────────────────────────────────────────────────────
const byTactic={{}};
D.techniques.forEach(t=>{{if(!byTactic[t.tactic])byTactic[t.tactic]=[];byTactic[t.tactic].push(t);}});

const hm=$('heatmap');
let activeTactic=null;
D.tactic_order.forEach(tac=>{{
  const hits=byTactic[tac]||[];
  const col=el('div','hm-col');
  const color=D.tactic_colors[tac]||'#555';
  const head=el('div','hm-head',tac.replace(/-/g,' '));
  head.style.background=color;
  col.appendChild(head);
  const body=el('div','hm-body');
  body.dataset.tactic=tac;
  body.title=`Filter graph to ${{tac}}`;
  body.onclick=()=>filterGraphByTactic(tac,body);
  if(!hits.length)body.appendChild(el('div','hm-empty','—'));
  else hits.forEach(t=>{{
    const c=el('div','hm-cell');
    c.style.background=color+'2a';c.style.color=color;
    c.textContent=t.id;c.title=t.name;
    body.appendChild(c);
  }});
  col.appendChild(body);hm.appendChild(col);
}});

// ── technique cards ───────────────────────────────────────────────────────────
let selectedTid=null;
function renderTechCard(t,container,dim=false){{
  const color=D.tactic_colors[t.tactic]||'#f39c12';
  const c=t.confidence||0;
  const fc=confColor(c);
  const card=el('div','tech-card');
  card.style.borderLeftColor=color;
  if(dim)card.style.opacity='.45';
  card.innerHTML=`
    <div class="tech-top">
      <span class="tech-tid" style="color:${{color}}">${{t.id}}</span>
      <span class="tech-nm">${{esc(t.name)}}</span>
      <div class="conf-mini">
        <div class="conf-track2"><div class="conf-fill2" style="width:${{pct(c)}}%;background:${{fc}}"></div></div>
        <span class="conf-lbl" style="color:${{fc}}">${{t.confidence_label||'?'}} ${{pct(c)}}%</span>
      </div>
      <a href="https://attack.mitre.org/techniques/${{t.id.replace('.','//')}}/" target="_blank" style="font-size:.72rem;color:var(--muted)" onclick="event.stopPropagation()">ATT&CK ↗</a>
    </div>
    <div class="ev-chips">${{(t.evidence||[]).map(e=>`<span class="ev-chip">${{esc(e)}}</span>`).join('')}}</div>`;
  card.addEventListener('click',()=>{{
    document.querySelectorAll('.tech-card').forEach(x=>x.classList.remove('selected'));
    card.classList.add('selected');
    selectedTid=t.id;
    highlightNode(t.id);
    showHypotheses([t.id]);
  }});
  container.appendChild(card);
}}

const tcw=$('tech-cards-wrap');
if(!D.techniques.length)tcw.innerHTML='<div class="no-data">No techniques detected above confidence threshold.</div>';
else D.techniques.forEach(t=>renderTechCard(t,tcw));

if(D.suppressed.length){{
  $('supp-wrap').style.display='block';
  const sc=$('supp-cards');
  D.suppressed.forEach(t=>renderTechCard(t,sc,true));
}}

// ── hypothesis panel ──────────────────────────────────────────────────────────
const hypsWrap=$('hyp-cards-wrap');
const allHyps=D.hypotheses;

function showHypotheses(tids){{
  hypsWrap.innerHTML='';
  const label=tids.length===1?tids[0]:`[${{tids.join(', ')}}]`;
  $('hyp-tech-label').textContent=`— ${{label}}`;
  const matches=tids.length?allHyps.filter(h=>tids.includes(h.technique_id)):allHyps;
  if(!matches.length){{$('hyp-empty').style.display='block';return;}}
  $('hyp-empty').style.display='none';
  matches.forEach((h,i)=>{{
    const color=D.tactic_colors[h.tactic]||'#555';
    const uid='hq'+i;
    const card=el('div','hyp-card');
    card.innerHTML=`
      <div class="hyp-header">
        <span style="font-family:monospace;font-weight:700">${{h.technique_id}}</span>
        <span class="tac-badge" style="background:${{color}}">${{h.tactic}}</span>
        <span class="src-badge">&#128268; ${{esc(h.log_source)}}</span>
      </div>
      <div class="hyp-text">&#128270; ${{esc(h.hypothesis)}}</div>
      <div class="q-tabs">
        <button class="q-tab on" onclick="swTab('${{uid}}','splunk',this)">Splunk SPL</button>
        <button class="q-tab" onclick="swTab('${{uid}}','kql',this)">Sentinel KQL</button>
        <button class="q-tab" onclick="swTab('${{uid}}','elastic',this)">Elastic EQL</button>
        ${{h.queries?.sql?`<button class="q-tab" onclick="swTab('${{uid}}','sql',this)">SQL</button>`:''}}
      </div>
      <pre class="q-block" id="${{uid}}-splunk">${{esc(h.queries?.splunk||'—')}}</pre>
      <pre class="q-block hide" id="${{uid}}-kql">${{esc(h.queries?.kql||'—')}}</pre>
      <pre class="q-block hide" id="${{uid}}-elastic">${{esc(h.queries?.elastic||'—')}}</pre>
      ${{h.queries?.sql?`<pre class="q-block hide" id="${{uid}}-sql">${{esc(h.queries.sql)}}</pre>`:''}}
      `;
    hypsWrap.appendChild(card);
  }});
}}

// Show all hypotheses by default
if(allHyps.length){{showHypotheses([]);$('hyp-tech-label').textContent='';}}
else $('hyp-empty').style.display='block';

window.swTab=function(uid,tab,btn){{
  ['splunk','kql','elastic','sql'].forEach(t=>{{
    const e=document.getElementById(uid+'-'+t);if(e)e.classList.toggle('hide',t!==tab);
  }});
  btn.closest('.hyp-card').querySelectorAll('.q-tab').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
}};

// ── sigma cards ───────────────────────────────────────────────────────────────
const sw=$('sigma-wrap');
if(!D.sigma_rules.length)$('sigma-empty').style.display='block';
else D.sigma_rules.forEach((r,i)=>{{
  const uid='sy'+i;
  const curated=r.status==='curated';
  const card=el('div','sigma-card');
  const fb=r.fallback||{{}};
  card.innerHTML=`
    <div class="sigma-header">
      <span class="sigma-tid">${{esc(r.technique_id||'')}}</span>
      <span class="sigma-name">${{esc(r.technique_name||r.rule?.title||'')}}</span>
      ${{curated
        ?'<span class="sigma-status-curated">&#10003; curated</span>'
        :'<span class="sigma-status-stub">&#9888; no curated rule</span>'}}
      ${{curated?`<button class="btn-toggle" onclick="toggleYaml('${{uid}}')">&#128196; YAML</button>`:''}}
      ${{r.technique_id?`<a href="https://attack.mitre.org/techniques/${{r.technique_id.replace('.','//')}}/" target="_blank" style="font-size:.73rem;color:var(--muted)">ATT&CK ↗</a>`:''}}
    </div>
    ${{!curated?`<div class="sigma-links">Search community rules:
      ${{fb.sigmahq_search?`<a href="${{fb.sigmahq_search}}" target="_blank">SigmaHQ ↗</a>`:''}}
      ${{fb.elastic_rules?`<a href="${{fb.elastic_rules}}" target="_blank">Elastic Detection Rules ↗</a>`:''}}
      ${{fb.splunk_security_content?`<a href="${{fb.splunk_security_content}}" target="_blank">Splunk Security Content ↗</a>`:''}}
    </div>`:''}}
    ${{curated?`<pre class="sigma-yaml-block" id="${{uid}}">${{esc(r.rule_yaml||'')}}</pre>`:''}}`;
  sw.appendChild(card);
}});
window.toggleYaml=function(uid){{const e=document.getElementById(uid);if(e)e.style.display=e.style.display&&e.style.display!=='none'?'none':'block';}};

// ── D3 Force Graph ────────────────────────────────────────────────────────────
(function(){{
  const svgEl=$('graph-svg');
  const W=svgEl.clientWidth||1100,H=520;
  svgEl.setAttribute('viewBox',`0 0 ${{W}} ${{H}}`);

  const nodes=D.graph.nodes.map(n=>Object.assign({{}},n));
  const links=D.graph.links.map(l=>Object.assign({{}},l));

  if(!nodes.length){{
    d3.select(svgEl).append('text').attr('x',W/2).attr('y',H/2)
      .attr('text-anchor','middle').attr('fill','#8b949e').attr('font-size','13')
      .text('No IOC-technique connections to visualise.');
    return;
  }}

  // Group x anchors: IOC left, technique centre, tactic right
  const layerX={{0:W*.18, 1:W*.52, 2:W*.86}};
  nodes.forEach(n=>{{n._fx0=layerX[n.layer||0];}});

  const svg=d3.select(svgEl);
  const g=svg.append('g');
  let showLabels=true;

  // zoom
  const zoom=d3.zoom().scaleExtent([.2,6]).on('zoom',e=>g.attr('transform',e.transform));
  svg.call(zoom);
  $('btn-reset').addEventListener('click',()=>svg.transition().duration(600).call(zoom.transform,d3.zoomIdentity));

  // labels toggle
  $('btn-labels').addEventListener('click',function(){{
    showLabels=!showLabels;
    this.textContent=showLabels?'Labels On':'Labels Off';
    this.classList.toggle('active',!showLabels);
    g.selectAll('.node-label').style('display',showLabels?null:'none');
  }});

  const nodeRadius=n=>n.group==='tactic'?20:n.group==='technique'?13:8;
  const nodeColor=n=>n.color||'#8b949e';

  // arrowhead markers per colour
  const defs=svg.append('defs');
  ['#30363d','#58a6ff','#3fb950','#d29922','#f85149'].forEach(col=>{{
    const id='arr'+col.replace('#','');
    defs.append('marker').attr('id',id).attr('viewBox','0 -4 8 8').attr('refX',8).attr('refY',0)
      .attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto')
      .append('path').attr('d','M0,-4L8,0L0,4').attr('fill',col);
  }});

  const linkColor=l=>l.strength>0.6?'#58a6ff':l.strength>0.3?'#30363d':'#21262d';

  // simulation
  const sim=d3.forceSimulation(nodes)
    .force('link',d3.forceLink(links).id(d=>d.id).distance(d=>d.type==='technique_tactic'?90:110).strength(d=>d.type==='technique_tactic'?.9:.4))
    .force('charge',d3.forceManyBody().strength(d=>d.group==='tactic'?-250:d.group==='technique'?-150:-80))
    .force('x',d3.forceX(n=>layerX[n.layer||0]).strength(.45))
    .force('y',d3.forceY(H/2).strength(.08))
    .force('collision',d3.forceCollide(n=>nodeRadius(n)+6));

  // links
  const link=g.append('g').selectAll('line').data(links).join('line')
    .attr('stroke',l=>linkColor(l))
    .attr('stroke-width',l=>l.type==='technique_tactic'?1.5:.8)
    .attr('stroke-opacity',l=>l.strength>0.5?.7:.35)
    .attr('stroke-dasharray',l=>l.strength<.3?'4,3':null)
    .attr('marker-end',l=>{{const c=linkColor(l);return `url(#arr${{c.replace('#','')}})`;}});

  // nodes
  const node=g.append('g').selectAll('g').data(nodes).join('g')
    .attr('class','node-g')
    .call(d3.drag()
      .on('start',(e,d)=>{{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;}})
      .on('drag', (e,d)=>{{d.fx=e.x;d.fy=e.y;}})
      .on('end',  (e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}})
    );

  node.append('circle')
    .attr('r',d=>nodeRadius(d))
    .attr('fill',d=>nodeColor(d))
    .attr('fill-opacity',d=>d.group==='tactic'?.75:.88)
    .attr('stroke',d=>d.group==='tactic'?'#fff':'#00000040')
    .attr('stroke-width',d=>d.group==='tactic'?1.5:.5);

  // confidence ring for technique nodes
  node.filter(d=>d.group==='technique').append('circle')
    .attr('r',d=>nodeRadius(d)+3)
    .attr('fill','none')
    .attr('stroke',d=>confColor(d.confidence||0))
    .attr('stroke-width',2)
    .attr('stroke-opacity',.6)
    .attr('stroke-dasharray',d=>{{
      const circ=2*Math.PI*(nodeRadius(d)+3);
      const arc=circ*(d.confidence||0);
      return `${{arc.toFixed(1)}} ${{(circ-arc).toFixed(1)}}`;
    }})
    .attr('transform','rotate(-90)');

  // labels
  node.append('text').attr('class','node-label')
    .attr('dy',d=>d.group==='ioc'?-12:'.35em')
    .attr('text-anchor','middle')
    .attr('font-size',d=>d.group==='tactic'?10:9)
    .attr('fill',d=>d.group==='tactic'?'#fff':'#8b949e')
    .text(d=>d.label||d.id);

  // hover tooltip
  const tt=document.getElementById('tooltip');
  node.on('mousemove',(e,d)=>{{
    tt.style.display='block';tt.style.left=(e.clientX+14)+'px';tt.style.top=(e.clientY-10)+'px';
    $('tt-id').textContent=d.id;
    $('tt-name').textContent=d.name||d.label||'';
    $('tt-conf').textContent=d.confidence!=null?`Confidence: ${{pct(d.confidence)}}% · ${{d.group}}`:`Group: ${{d.group}}`;
    $('tt-ev').innerHTML=(d.evidence||[]).map(e=>`<span class="tt-chip">${{esc(e)}}</span>`).join('');
  }}).on('mouseleave',()=>tt.style.display='none');

  // click technique node
  node.on('click',(e,d)=>{{
    e.stopPropagation();
    if(d.group==='technique'){{
      highlightNode(d.id);
      document.querySelectorAll('.tech-card').forEach(c=>c.classList.remove('selected'));
      const card=[...document.querySelectorAll('.tech-card')].find(c=>c.querySelector('.tech-tid')?.textContent===d.id);
      if(card){{card.classList.add('selected');card.scrollIntoView({{behavior:'smooth',block:'nearest'}});}}
      showHypotheses([d.id]);
    }}
  }});
  svg.on('click',()=>{{resetHighlight();showHypotheses([]);$('hyp-tech-label').textContent='';}});

  // highlight helpers
  function highlightNode(tid){{
    const connected=new Set([tid]);
    links.forEach(l=>{{if((l.source.id||l.source)===tid||(l.target.id||l.target)===tid){{connected.add(l.source.id||l.source);connected.add(l.target.id||l.target);}}}} );
    node.attr('opacity',d=>connected.has(d.id)?1:.15);
    link.attr('opacity',l=>{{const s=l.source.id||l.source,t=l.target.id||l.target;return connected.has(s)&&connected.has(t)?1:.05;}});
  }}
  function resetHighlight(){{node.attr('opacity',1);link.attr('opacity',1);}}
  window.highlightNode=highlightNode;

  sim.on('tick',()=>{{
    link.attr('x1',l=>l.source.x).attr('y1',l=>l.source.y)
        .attr('x2',l=>{{const dx=l.target.x-l.source.x,dy=l.target.y-l.source.y,d=Math.sqrt(dx*dx+dy*dy)||1,r=nodeRadius(l.target)+4;return l.target.x-dx/d*r;}})
        .attr('y2',l=>{{const dx=l.target.x-l.source.x,dy=l.target.y-l.source.y,d=Math.sqrt(dx*dx+dy*dy)||1,r=nodeRadius(l.target)+4;return l.target.y-dy/d*r;}});
    node.attr('transform',d=>`translate(${{d.x}},${{d.y}})`);
  }});

  // tactic filter buttons
  const filters=$('tactic-filters');
  const activeTactics=new Set(nodes.filter(n=>n.group==='tactic').map(n=>n.tactic||n.id.replace('tactic::','')));
  activeTactics.forEach(tac=>{{
    const color=D.tactic_colors[tac]||'#555';
    const btn=el('button','tactic-filter-btn on',tac.replace(/-/g,'&#8209;'));
    btn.style.color=color;btn.dataset.tac=tac;
    btn.onclick=()=>toggleTacticFilter(tac,btn);
    filters.appendChild(btn);
  }});

  const hiddenTactics=new Set();
  function toggleTacticFilter(tac,btn){{
    if(hiddenTactics.has(tac)){{hiddenTactics.delete(tac);btn.classList.add('on');}}
    else{{hiddenTactics.add(tac);btn.classList.remove('on');}}
    const visNodes=new Set();
    nodes.forEach(n=>{{
      const t=n.tactic||(n.id.startsWith('tactic::')?n.id.replace('tactic::',''):null);
      const hide=t&&hiddenTactics.has(t);
      g.selectAll('.node-g').filter(d=>d.id===n.id).attr('opacity',hide?.05:1);
    }});
  }}

  function filterGraphByTactic(tac,body){{
    if(body.dataset.active==='1'){{body.dataset.active='';node.attr('opacity',1);link.attr('opacity',1);}}
    else{{
      document.querySelectorAll('.hm-body').forEach(b=>b.dataset.active='');
      body.dataset.active='1';
      const tacId='tactic::'+tac;
      const rel=new Set([tacId]);
      links.forEach(l=>{{if((l.target.id||l.target)===tacId)rel.add(l.source.id||l.source);}});
      links.forEach(l=>{{if(rel.has(l.target.id||l.target)||rel.has(l.source.id||l.source)){{rel.add(l.source.id||l.source);rel.add(l.target.id||l.target);}}}});
      node.attr('opacity',d=>rel.has(d.id)?1:.07);
      link.attr('opacity',l=>{{const s=l.source.id||l.source,t=l.target.id||l.target;return rel.has(s)&&rel.has(t)?.8:.03;}});
    }}
  }}
  window.filterGraphByTactic=filterGraphByTactic;
}})();
</script>
</body>
</html>"""
