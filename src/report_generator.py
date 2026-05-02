"""
LLM Security Scanner — HTML Report Generator
Produces a self-contained dark-mode security dashboard.
"""

import json
from scanner import ScanReport, ProbeResult
from probe_library import OWASP_REFERENCES, SEVERITY_WEIGHTS


SEVERITY_COLORS = {
    "CRITICAL": ("#ff6b6b", "#3b0000"),
    "HIGH":     ("#ff9f43", "#2d1b00"),
    "MEDIUM":   ("#ffd43b", "#2d2700"),
    "LOW":      ("#51cf66", "#0a2600"),
}

RISK_COLORS = {
    "CRITICAL": "#c62828",
    "HIGH":     "#bf360c",
    "MEDIUM":   "#e65100",
    "LOW":      "#1b5e20",
}


class ScanReportHTMLGenerator:

    def generate(self, report: ScanReport) -> str:
        vulnerable = [r for r in report.results if r.vulnerable and not r.error]
        resistant = [r for r in report.results if not r.vulnerable and not r.error]
        errored = [r for r in report.results if r.error]
        rc = RISK_COLORS.get(report.risk_rating, "#555")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Security Scan — {report.target_name}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
    --border: #30363d; --text: #e6edf3; --muted: #8b949e;
    --accent: #58a6ff; --red: #ff6b6b; --orange: #ff9f43;
    --yellow: #ffd43b; --green: #51cf66; --purple: #da77f2;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 13px; line-height: 1.6; }}
  .header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 1.8rem 3rem; display: flex; justify-content: space-between; align-items: flex-start; }}
  .badge {{ font-size: 10px; font-weight: 700; letter-spacing: .15em; text-transform: uppercase; color: var(--muted); margin-bottom: .4rem; }}
  .title {{ font-size: 22px; font-weight: 700; }}
  .meta {{ font-size: 11px; color: var(--muted); margin-top: .3rem; }}
  .risk-box {{ padding: .6rem 1.4rem; border-radius: 6px; text-align: center; border: 1px solid; }}
  .main {{ max-width: 1100px; margin: 0 auto; padding: 2rem 3rem; }}
  .section {{ margin-bottom: 2.5rem; }}
  .section-title {{ font-size: 10px; font-weight: 700; letter-spacing: .2em; text-transform: uppercase; color: var(--muted); border-bottom: 1px solid var(--border); padding-bottom: .5rem; margin-bottom: 1.2rem; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 1rem; }}
  .grid-2 {{ display: grid; grid-template-columns: repeat(2,1fr); gap: 1rem; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; }}
  .stat-label {{ font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .1em; margin-bottom: .4rem; }}
  .stat-value {{ font-size: 26px; font-weight: 700; }}
  .summary-box {{ background: var(--surface); border: 1px solid var(--border); border-left: 3px solid var(--accent); border-radius: 8px; padding: 1.2rem 1.5rem; white-space: pre-wrap; font-size: 12px; line-height: 1.8; }}
  .probe-row {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.2rem; margin-bottom: .5rem; }}
  .probe-row.vuln {{ border-left: 3px solid var(--red); }}
  .probe-row.safe {{ border-left: 3px solid var(--green); }}
  .probe-header {{ display: grid; grid-template-columns: auto 1fr auto auto; gap: 1rem; align-items: center; }}
  .sev-pill {{ font-size: 9px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; padding: 3px 8px; border-radius: 4px; white-space: nowrap; }}
  .sev-CRITICAL {{ background: #3b0000; color: var(--red); border: 1px solid var(--red); }}
  .sev-HIGH {{ background: #2d1b00; color: var(--orange); border: 1px solid var(--orange); }}
  .sev-MEDIUM {{ background: #2d2700; color: var(--yellow); border: 1px solid var(--yellow); }}
  .sev-LOW {{ background: #0a2600; color: var(--green); border: 1px solid var(--green); }}
  .probe-name {{ font-size: 13px; font-weight: 600; }}
  .probe-id {{ font-size: 10px; color: var(--muted); font-family: monospace; }}
  .probe-category {{ font-size: 10px; color: var(--accent); }}
  .status-badge {{ font-size: 10px; font-weight: 700; padding: 3px 10px; border-radius: 4px; }}
  .status-vuln {{ background: #3b0000; color: var(--red); }}
  .status-safe {{ background: #0a2600; color: var(--green); }}
  .status-error {{ background: #1a1a1a; color: var(--muted); }}
  .detail {{ font-size: 11px; color: var(--muted); margin-top: .6rem; padding-top: .6rem; border-top: 1px solid var(--border); }}
  .detail-row {{ margin-bottom: .3rem; }}
  .detail-row span {{ color: var(--accent); }}
  .prompt-box {{ background: var(--surface2); border-radius: 4px; padding: .5rem .7rem; font-size: 11px; margin-top: .3rem; color: var(--muted); white-space: pre-wrap; word-break: break-word; }}
  .response-box {{ background: #0d1f0d; border: 1px solid #1a3a1a; border-radius: 4px; padding: .5rem .7rem; font-size: 11px; margin-top: .3rem; color: #a8d8a8; white-space: pre-wrap; word-break: break-word; }}
  .response-box.vuln {{ background: #1f0d0d; border-color: #3a1a1a; color: #d8a8a8; }}
  .remediation {{ background: #0d1a2d; border: 1px solid #1a3a5c; border-radius: 4px; padding: .5rem .7rem; font-size: 11px; color: #7ab8f5; margin-top: .4rem; }}
  .remediation::before {{ content: "✓ Remediation: "; font-weight: 700; }}
  .heatmap {{ display: flex; flex-direction: column; gap: .4rem; }}
  .hmap-row {{ display: flex; align-items: center; gap: .8rem; }}
  .hmap-label {{ font-size: 10px; color: var(--muted); width: 200px; text-align: right; flex-shrink: 0; }}
  .hmap-bg {{ flex: 1; height: 18px; background: var(--surface2); border-radius: 3px; overflow: hidden; }}
  .hmap-fill {{ height: 100%; border-radius: 3px; display: flex; align-items: center; padding-left: 6px; }}
  .hmap-score {{ font-size: 9px; font-weight: 700; color: white; }}
  .owasp-tag {{ font-size: 9px; background: var(--surface2); border: 1px solid var(--border); border-radius: 3px; padding: 1px 6px; color: var(--muted); margin-left: 4px; }}
  .footer {{ border-top: 1px solid var(--border); padding: 1.5rem 3rem; text-align: center; font-size: 10px; color: var(--muted); margin-top: 3rem; }}
  details summary {{ cursor: pointer; list-style: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
  details summary::before {{ content: "▶ "; font-size: 9px; color: var(--muted); }}
  details[open] summary::before {{ content: "▼ "; }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="badge">LLM Security Scan Report</div>
    <div class="title">{report.target_name}</div>
    <div class="meta">
      {report.timestamp} &nbsp;·&nbsp; Model: {report.model} &nbsp;·&nbsp;
      OWASP LLM Top 10 2025 &nbsp;·&nbsp; MITRE ATLAS v4.5.2 &nbsp;·&nbsp;
      {report.probes_run} probes executed
    </div>
  </div>
  <div class="risk-box" style="background:{rc}22; color:{rc}; border-color:{rc};">
    <div style="font-size:11px; font-weight:700; letter-spacing:.1em;">{report.risk_rating}</div>
    <div style="font-size:28px; font-weight:700;">{report.overall_score}</div>
    <div style="font-size:10px; opacity:.7;">/100 vulnerability score</div>
  </div>
</div>

<div class="main">

  <div class="section">
    <div class="section-title">Scan Overview</div>
    <div class="grid-4">
      <div class="card">
        <div class="stat-label">Vulnerable</div>
        <div class="stat-value" style="color:var(--red);">{report.probes_vulnerable}</div>
        <div style="font-size:10px;color:var(--muted);">probes succeeded</div>
      </div>
      <div class="card">
        <div class="stat-label">Resistant</div>
        <div class="stat-value" style="color:var(--green);">{report.probes_resistant}</div>
        <div style="font-size:10px;color:var(--muted);">probes blocked</div>
      </div>
      <div class="card">
        <div class="stat-label">Errored</div>
        <div class="stat-value" style="color:var(--muted);">{report.probes_errored}</div>
        <div style="font-size:10px;color:var(--muted);">connection failures</div>
      </div>
      <div class="card">
        <div class="stat-label">Coverage</div>
        <div class="stat-value" style="color:var(--accent);">{len(report.category_scores)}</div>
        <div style="font-size:10px;color:var(--muted);">attack categories</div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="summary-box">{report.executive_summary}</div>
  </div>

  {self._render_heatmap(report)}

  <div class="section">
    <div class="section-title">Probe Results — Vulnerable ({report.probes_vulnerable})</div>
    {self._render_results([r for r in report.results if r.vulnerable and not r.error])}
  </div>

  <div class="section">
    <div class="section-title">Probe Results — Resistant ({report.probes_resistant})</div>
    {self._render_results([r for r in report.results if not r.vulnerable and not r.error], collapsed=True)}
  </div>

</div>

<div class="footer">
  Generated by <strong>LLM Security Scanner</strong> — by Tirthankar Dutta &nbsp;·&nbsp;
  github.com/tirthankardutta1983 &nbsp;·&nbsp;
  OWASP LLM Top 10 2025 &nbsp;·&nbsp; MITRE ATLAS v4.5.2 &nbsp;·&nbsp;
  For security assessment purposes only.
</div>
</body></html>"""

    def _render_heatmap(self, report: ScanReport) -> str:
        if not report.category_scores:
            return ""
        rows = []
        for cat, score in sorted(report.category_scores.items(), key=lambda x: -x[1]):
            color = "#c62828" if score >= 70 else "#e65100" if score >= 45 else "#f57f17" if score >= 20 else "#2e7d32"
            rows.append(f"""
      <div class="hmap-row">
        <div class="hmap-label">{cat}</div>
        <div class="hmap-bg">
          <div class="hmap-fill" style="width:{score}%; background:{color};">
            <span class="hmap-score">{score:.0f}%</span>
          </div>
        </div>
      </div>""")
        return f"""
  <div class="section">
    <div class="section-title">Category Vulnerability Heatmap</div>
    <div class="heatmap">{"".join(rows)}</div>
  </div>"""

    def _render_results(self, results: list, collapsed: bool = False) -> str:
        if not results:
            return '<div style="color:var(--muted);font-size:12px;padding:.5rem 0;">None</div>'
        html = []
        for r in results:
            status_cls = "vuln" if r.vulnerable else "safe"
            status_label = "VULNERABLE" if r.vulnerable else "RESISTANT"
            owasp_label = OWASP_REFERENCES.get(r.probe.owasp_ref, r.probe.owasp_ref)
            matched = ", ".join(r.matched_indicators[:3]) if r.matched_indicators else "none"
            response_cls = "vuln" if r.vulnerable else ""

            inner = f"""
        <div class="detail">
          <div class="detail-row"><span>OWASP:</span> {r.probe.owasp_ref} — {owasp_label}</div>
          <div class="detail-row"><span>ATLAS:</span> {r.probe.atlas_ref}</div>
          <div class="detail-row"><span>Indicators matched:</span> {matched}</div>
          <div class="detail-row"><span>Confidence:</span> {int(r.confidence*100)}%</div>
          <div class="detail-row" style="margin-top:.5rem;"><span>Probe sent:</span></div>
          <div class="prompt-box">{r.prompt_used[:300]}</div>
          <div class="detail-row" style="margin-top:.5rem;"><span>Model response:</span></div>
          <div class="response-box {response_cls}">{r.response[:400] or '(no response)'}</div>
          <div class="remediation">{r.probe.remediation}</div>
        </div>"""

            if collapsed:
                content = f'<details><summary style="font-size:11px;color:var(--muted);">Show details</summary>{inner}</details>'
            else:
                content = inner

            html.append(f"""
    <div class="probe-row {status_cls}">
      <div class="probe-header">
        <span class="sev-pill sev-{r.probe.severity}">{r.probe.severity}</span>
        <div>
          <div class="probe-name">{r.probe.name}
            <span class="owasp-tag">{r.probe.owasp_ref}</span>
          </div>
          <div class="probe-id">{r.probe.id} &nbsp;·&nbsp; <span class="probe-category">{r.probe.category}</span></div>
        </div>
        <span class="status-badge status-{status_cls if not r.error else 'error'}">{status_label}</span>
        <div style="font-size:10px;color:var(--muted);text-align:right;">
          {r.latency_ms:.0f}ms
        </div>
      </div>
      {content}
    </div>""")
        return "\n".join(html)


class JSONReportGenerator:
    def generate(self, report: ScanReport) -> str:
        return json.dumps({
            "metadata": {
                "tool": "LLM Security Scanner",
                "version": "1.0.0",
                "timestamp": report.timestamp,
                "frameworks": ["OWASP LLM Top 10 2025", "MITRE ATLAS v4.5.2"],
            },
            "target": {
                "name": report.target_name,
                "endpoint": report.target_endpoint,
                "model": report.model,
            },
            "summary": {
                "overall_score": report.overall_score,
                "risk_rating": report.risk_rating,
                "probes_run": report.probes_run,
                "probes_vulnerable": report.probes_vulnerable,
                "probes_resistant": report.probes_resistant,
                "probes_errored": report.probes_errored,
                "category_scores": report.category_scores,
            },
            "executive_summary": report.executive_summary,
            "findings": [
                {
                    "probe_id": r.probe.id,
                    "probe_name": r.probe.name,
                    "category": r.probe.category,
                    "severity": r.probe.severity,
                    "owasp_ref": r.probe.owasp_ref,
                    "atlas_ref": r.probe.atlas_ref,
                    "vulnerable": r.vulnerable,
                    "confidence": r.confidence,
                    "matched_indicators": r.matched_indicators,
                    "remediation": r.probe.remediation,
                    "latency_ms": r.latency_ms,
                }
                for r in report.results
            ],
        }, indent=2)
