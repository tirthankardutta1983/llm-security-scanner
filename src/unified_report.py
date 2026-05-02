"""
Unified Report Generator
Merges our scanner results + garak findings into one HTML dashboard.
"""

import json
from typing import Optional, List
from scanner import ScanReport
from garak_bridge import GarakScanResult, GarakFinding
from probe_library import OWASP_REFERENCES, SEVERITY_WEIGHTS

RISK_COLORS = {
    "CRITICAL": "#c62828", "HIGH": "#bf360c",
    "MEDIUM": "#e65100",   "LOW":  "#1b5e20",
}


def _score_color(score):
    if score >= 70: return "#c62828"
    if score >= 45: return "#e65100"
    if score >= 20: return "#f57f17"
    return "#2e7d32"


def _sev_pill(sev):
    classes = {
        "CRITICAL": "background:#3b0000;color:#ff6b6b;border:1px solid #ff6b6b",
        "HIGH":     "background:#2d1b00;color:#ff9f43;border:1px solid #ff9f43",
        "MEDIUM":   "background:#2d2700;color:#ffd43b;border:1px solid #ffd43b",
        "LOW":      "background:#0a2600;color:#51cf66;border:1px solid #51cf66",
    }
    style = classes.get(sev, "")
    return f'<span style="font-size:9px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:3px 8px;border-radius:4px;{style}">{sev}</span>'


class UnifiedHTMLReportGenerator:
    """
    Generates a single HTML report combining:
    - Our scanner results (ATLAS-mapped, with response evidence)
    - Garak findings (enriched with ATLAS + NIST)
    """

    def generate(
        self,
        our_report: ScanReport,
        garak_result: Optional[GarakScanResult] = None
    ) -> str:

        # Compute unified stats
        our_vuln = our_report.probes_vulnerable
        garak_vuln = len([f for f in garak_result.findings if f.vulnerable]) if garak_result else 0
        garak_total = len(garak_result.findings) if garak_result else 0

        total_vuln = our_vuln + garak_vuln
        total_probes = our_report.probes_run + garak_total

        # Unified risk score (weighted average)
        garak_score = 0.0
        if garak_result and garak_total > 0:
            garak_score = round((garak_vuln / garak_total) * 100, 1)

        our_score = our_report.overall_score
        if garak_result and garak_total > 0:
            unified_score = round((our_score + garak_score) / 2, 1)
        else:
            unified_score = our_score

        rating = our_report.risk_rating
        rc = RISK_COLORS.get(rating, "#555")

        has_garak = garak_result is not None and garak_result.success

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Security Scan — {our_report.target_name}</title>
<style>
  :root {{
    --bg:#0d1117; --surface:#161b22; --surface2:#21262d;
    --border:#30363d; --text:#e6edf3; --muted:#8b949e;
    --accent:#58a6ff; --red:#ff6b6b; --orange:#ff9f43;
    --yellow:#ffd43b; --green:#51cf66;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono','Fira Code',monospace;font-size:13px;line-height:1.6}}
  .header{{background:var(--surface);border-bottom:1px solid var(--border);padding:1.8rem 3rem;display:flex;justify-content:space-between;align-items:flex-start}}
  .badge{{font-size:10px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.4rem}}
  .title{{font-size:22px;font-weight:700}}
  .meta{{font-size:11px;color:var(--muted);margin-top:.3rem}}
  .risk-box{{padding:.6rem 1.4rem;border-radius:6px;text-align:center;border:1px solid}}
  .main{{max-width:1100px;margin:0 auto;padding:2rem 3rem}}
  .section{{margin-bottom:2.5rem}}
  .section-title{{font-size:10px;font-weight:700;letter-spacing:.2em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--border);padding-bottom:.5rem;margin-bottom:1.2rem}}
  .grid-5{{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem}}
  .grid-2{{display:grid;grid-template-columns:repeat(2,1fr);gap:1rem}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.2rem}}
  .stat-label{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;margin-bottom:.4rem}}
  .stat-value{{font-size:26px;font-weight:700}}
  .summary-box{{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:8px;padding:1.2rem 1.5rem;white-space:pre-wrap;font-size:12px;line-height:1.8}}
  .source-tag{{font-size:9px;font-weight:700;padding:2px 7px;border-radius:3px;letter-spacing:.08em;text-transform:uppercase;margin-left:6px}}
  .source-ours{{background:#0d2137;color:var(--accent);border:1px solid var(--accent)}}
  .source-garak{{background:#1a0d37;color:#da77f2;border:1px solid #da77f2}}
  .probe-row{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem 1.2rem;margin-bottom:.5rem}}
  .probe-row.vuln{{border-left:3px solid var(--red)}}
  .probe-row.safe{{border-left:3px solid var(--green)}}
  .probe-header{{display:grid;grid-template-columns:auto 1fr auto auto;gap:1rem;align-items:center}}
  .probe-name{{font-size:13px;font-weight:600}}
  .probe-sub{{font-size:10px;color:var(--muted);margin-top:2px}}
  .status-vuln{{font-size:10px;font-weight:700;padding:3px 10px;border-radius:4px;background:#3b0000;color:var(--red)}}
  .status-safe{{font-size:10px;font-weight:700;padding:3px 10px;border-radius:4px;background:#0a2600;color:var(--green)}}
  .detail{{font-size:11px;color:var(--muted);margin-top:.6rem;padding-top:.6rem;border-top:1px solid var(--border)}}
  .detail span{{color:var(--accent)}}
  .atlas-card{{background:#0d1a2d;border:1px solid #1a3a5c;border-radius:6px;padding:.7rem 1rem;margin-top:.5rem}}
  .atlas-id{{font-size:11px;font-weight:700;color:var(--accent);font-family:monospace}}
  .atlas-name{{font-size:12px;font-weight:600;color:var(--text);margin-left:.5rem}}
  .atlas-tactic{{font-size:10px;color:var(--muted);margin-top:2px}}
  .nist-tags{{display:flex;flex-wrap:wrap;gap:.3rem;margin-top:.4rem}}
  .nist-tag{{font-size:9px;padding:2px 7px;border-radius:3px;font-weight:700}}
  .nist-GOVERN{{background:#003180;color:#4dabf7}}
  .nist-MAP{{background:#003319;color:#69db7c}}
  .nist-MEASURE{{background:#2d1500;color:#ffa94d}}
  .nist-MANAGE{{background:#2a0040;color:#da77f2}}
  .remediation{{background:#0d1a0d;border:1px solid #1a3a1a;border-radius:4px;padding:.5rem .7rem;font-size:11px;color:#7ab87a;margin-top:.4rem}}
  .remediation::before{{content:"✓ Remediation: ";font-weight:700}}
  .heatmap{{display:flex;flex-direction:column;gap:.4rem}}
  .hmap-row{{display:flex;align-items:center;gap:.8rem}}
  .hmap-label{{font-size:10px;color:var(--muted);width:220px;text-align:right;flex-shrink:0}}
  .hmap-bg{{flex:1;height:18px;background:var(--surface2);border-radius:3px;overflow:hidden}}
  .hmap-fill{{height:100%;border-radius:3px;display:flex;align-items:center;padding-left:6px}}
  .hmap-score{{font-size:9px;font-weight:700;color:white}}
  .engine-divider{{background:var(--surface2);border-radius:6px;padding:.5rem 1rem;font-size:11px;color:var(--muted);margin:1rem 0;display:flex;align-items:center;gap:.5rem}}
  .footer{{border-top:1px solid var(--border);padding:1.5rem 3rem;text-align:center;font-size:10px;color:var(--muted);margin-top:3rem}}
  details summary{{cursor:pointer;list-style:none}}
  details summary::-webkit-details-marker{{display:none}}
  details summary::before{{content:"▶ ";font-size:9px;color:var(--muted)}}
  details[open] summary::before{{content:"▼ "}}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="badge">Unified LLM Security Scan Report</div>
    <div class="title">{our_report.target_name}</div>
    <div class="meta">
      {our_report.timestamp} &nbsp;·&nbsp; Model: {our_report.model} &nbsp;·&nbsp;
      OWASP LLM Top 10 2025 &nbsp;·&nbsp; MITRE ATLAS v4.5.2 &nbsp;·&nbsp; NIST AI RMF 1.0
      {f"&nbsp;·&nbsp; garak {garak_result.garak_version}" if has_garak else ""}
    </div>
  </div>
  <div class="risk-box" style="background:{rc}22;color:{rc};border-color:{rc};">
    <div style="font-size:11px;font-weight:700;letter-spacing:.1em;">{rating}</div>
    <div style="font-size:28px;font-weight:700;">{unified_score}</div>
    <div style="font-size:10px;opacity:.7;">/100 unified score</div>
  </div>
</div>

<div class="main">

  <!-- STATS -->
  <div class="section">
    <div class="section-title">Scan Overview</div>
    <div class="grid-5">
      <div class="card">
        <div class="stat-label">Total Probes</div>
        <div class="stat-value" style="color:var(--accent);">{total_probes}</div>
        <div style="font-size:10px;color:var(--muted);">across both engines</div>
      </div>
      <div class="card">
        <div class="stat-label">Vulnerable</div>
        <div class="stat-value" style="color:var(--red);">{total_vuln}</div>
        <div style="font-size:10px;color:var(--muted);">probes succeeded</div>
      </div>
      <div class="card">
        <div class="stat-label">Our Scanner</div>
        <div class="stat-value" style="color:var(--accent);">{our_report.probes_run}</div>
        <div style="font-size:10px;color:var(--muted);">{our_vuln} vulnerable</div>
      </div>
      <div class="card">
        <div class="stat-label">Garak Probes</div>
        <div class="stat-value" style="color:#da77f2;">{garak_total if has_garak else "—"}</div>
        <div style="font-size:10px;color:var(--muted);">{f"{garak_vuln} vulnerable" if has_garak else "not run"}</div>
      </div>
      <div class="card">
        <div class="stat-label">ATLAS Techniques</div>
        <div class="stat-value" style="color:var(--orange);">{self._count_atlas(our_report, garak_result)}</div>
        <div style="font-size:10px;color:var(--muted);">unique techniques</div>
      </div>
    </div>
  </div>

  <!-- SUMMARY -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <div class="summary-box">{self._write_unified_summary(our_report, garak_result, unified_score, rating)}</div>
  </div>

  <!-- HEATMAP -->
  {self._render_heatmap(our_report, garak_result)}

  <!-- OUR FINDINGS -->
  <div class="section">
    <div class="section-title">
      Our Scanner — Vulnerable Findings
      <span class="source-tag source-ours">ATLAS-MAPPED</span>
    </div>
    {self._render_our_findings(our_report)}
  </div>

  <!-- GARAK FINDINGS -->
  {self._render_garak_section(garak_result) if has_garak else self._render_garak_not_installed()}

</div>

<div class="footer">
  Generated by <strong>LLM Security Scanner</strong> — by Tirthankar Dutta &nbsp;·&nbsp;
  github.com/tirthankardutta1983 &nbsp;·&nbsp;
  OWASP LLM Top 10 2025 &nbsp;·&nbsp; MITRE ATLAS v4.5.2 &nbsp;·&nbsp; NIST AI RMF 1.0
  {f"&nbsp;·&nbsp; Powered by garak (NVIDIA)" if has_garak else ""}
</div>
</body></html>"""

    def _count_atlas(self, our_report, garak_result):
        techniques = set()
        for r in our_report.results:
            if r.vulnerable:
                techniques.add(r.probe.atlas_ref)
        if garak_result:
            for f in garak_result.findings:
                if f.vulnerable:
                    techniques.add(f.atlas_id)
        return len(techniques)

    def _write_unified_summary(self, our_report, garak_result, score, rating):
        lines = [
            f"{our_report.target_name} was assessed using a dual-engine approach: "
            f"our agent-focused scanner ({our_report.probes_run} probes) "
            + (f"and NVIDIA garak ({len(garak_result.findings)} probes). " if garak_result else ". "),
            f"Combined vulnerability score: {score}/100 — Risk Rating: {rating}.",
            "",
            our_report.executive_summary,
        ]
        if garak_result and garak_result.findings:
            vuln = [f for f in garak_result.findings if f.vulnerable]
            if vuln:
                top = vuln[:3]
                lines.append(
                    f"\nGarak identified {len(vuln)} additional vulnerabilities including: "
                    + ", ".join(f.probe for f in top) + "."
                )
        return "\n".join(lines)

    def _render_heatmap(self, our_report, garak_result):
        scores = dict(our_report.category_scores)
        # Add garak category scores
        if garak_result:
            cat_counts = {}
            cat_vulns = {}
            for f in garak_result.findings:
                cat = f"[garak] {f.garak_category}"
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
                if f.vulnerable:
                    cat_vulns[cat] = cat_vulns.get(cat, 0) + 1
            for cat, total in cat_counts.items():
                scores[cat] = round((cat_vulns.get(cat, 0) / total) * 100, 1)

        if not scores:
            return ""

        rows = []
        for cat, score in sorted(scores.items(), key=lambda x: -x[1]):
            color = _score_color(score)
            is_garak = cat.startswith("[garak]")
            label = cat.replace("[garak] ", "")
            tag = '<span style="font-size:8px;color:#da77f2;margin-left:4px;">garak</span>' if is_garak else ""
            rows.append(f"""
      <div class="hmap-row">
        <div class="hmap-label">{label}{tag}</div>
        <div class="hmap-bg">
          <div class="hmap-fill" style="width:{score}%;background:{color};">
            <span class="hmap-score">{score:.0f}%</span>
          </div>
        </div>
      </div>""")

        return f"""
  <div class="section">
    <div class="section-title">Category Vulnerability Heatmap (Unified)</div>
    <div class="heatmap">{"".join(rows)}</div>
  </div>"""

    def _render_our_findings(self, report):
        vuln = [r for r in report.results if r.vulnerable and not r.error]
        if not vuln:
            return '<div style="color:var(--muted);font-size:12px;">No vulnerabilities found by our scanner.</div>'
        html = []
        for r in vuln:
            nist_tags = self._nist_tags(["MANAGE-1.1", "MEASURE-2.2"])
            html.append(f"""
    <div class="probe-row vuln">
      <div class="probe-header">
        {_sev_pill(r.probe.severity)}
        <div>
          <div class="probe-name">{r.probe.name} <span class="source-tag source-ours">OUR SCANNER</span></div>
          <div class="probe-sub">{r.probe.id} · {r.probe.category} · {r.probe.owasp_ref}</div>
        </div>
        <span class="status-vuln">VULNERABLE</span>
        <div style="font-size:10px;color:var(--muted);">{int(r.confidence*100)}% conf</div>
      </div>
      <div class="detail">
        <div class="atlas-card">
          <span class="atlas-id">{r.probe.atlas_ref}</span>
          <span class="atlas-name">{r.probe.atlas_ref}</span>
          <div class="atlas-tactic">Tactic: matched via agent attribute analysis</div>
          <div class="nist-tags">{nist_tags}</div>
        </div>
        <div class="remediation">{r.probe.remediation}</div>
      </div>
    </div>""")
        return "\n".join(html)

    def _render_garak_section(self, garak_result):
        if not garak_result:
            return ""
        vuln = [f for f in garak_result.findings if f.vulnerable]
        safe = [f for f in garak_result.findings if not f.vulnerable]

        html = [f"""
  <div class="section">
    <div class="section-title">
      Garak — Vulnerable Findings ({len(vuln)})
      <span class="source-tag source-garak">GARAK + ATLAS</span>
    </div>"""]

        if not vuln:
            html.append('<div style="color:var(--muted);font-size:12px;padding:.5rem 0;">No vulnerabilities found by garak.</div>')
        else:
            for f in vuln:
                nist_tags = self._nist_tags(f.nist_controls)
                secondary = ""
                if f.secondary_atlas:
                    secondary = f'<div class="atlas-tactic" style="margin-top:3px;">Secondary: {", ".join(f.secondary_atlas)}</div>'
                html.append(f"""
    <div class="probe-row vuln">
      <div class="probe-header">
        {_sev_pill(f.severity)}
        <div>
          <div class="probe-name">{f.probe} <span class="source-tag source-garak">GARAK</span></div>
          <div class="probe-sub">{f.garak_category} · {f.owasp_ref} — {f.owasp_name}</div>
        </div>
        <span class="status-vuln">VULNERABLE</span>
        <div style="font-size:10px;color:var(--muted);">{int(f.confidence*100)}% conf</div>
      </div>
      <div class="detail">
        <div style="font-size:11px;margin-bottom:.4rem;">{f.description}</div>
        <div class="atlas-card">
          <span class="atlas-id">{f.atlas_id}</span>
          <span class="atlas-name">{f.atlas_name}</span>
          <div class="atlas-tactic">Tactic: {f.tactic}</div>
          {secondary}
          <div class="nist-tags">{nist_tags}</div>
        </div>
        <div class="remediation">{f.remediation}</div>
      </div>
    </div>""")

        # Resistant findings collapsed
        if safe:
            html.append(f"""
    <div style="margin-top:1.5rem;">
      <div class="section-title">Garak — Resistant ({len(safe)})</div>""")
            for f in safe:
                html.append(f"""
      <div class="probe-row safe">
        <details>
          <summary style="font-size:11px;">
            {_sev_pill(f.severity)} &nbsp; {f.probe} &nbsp;
            <span style="color:var(--green);font-size:10px;">RESISTANT</span>
            &nbsp;<span style="color:var(--muted);font-size:10px;">· {f.atlas_id} · {f.owasp_ref}</span>
          </summary>
          <div class="detail">
            <div>{f.description}</div>
            <div class="remediation">{f.remediation}</div>
          </div>
        </details>
      </div>""")
            html.append("</div>")

        html.append("</div>")
        return "\n".join(html)

    def _render_garak_not_installed(self):
        return """
  <div class="section">
    <div class="section-title">Garak — Not Run</div>
    <div class="card" style="border-color:#30363d;">
      <div style="font-size:13px;font-weight:600;margin-bottom:.5rem;">
        Extend this scan with garak's 37+ probe modules
      </div>
      <div style="font-size:11px;color:var(--muted);line-height:1.8;">
        Install garak to run an additional 37+ probe modules covering DAN jailbreaks,
        encoding bypasses, package hallucination, malware generation, toxicity,
        XSS exfiltration, and more — all enriched with MITRE ATLAS and NIST AI RMF mappings.
      </div>
      <div style="margin-top:1rem;background:var(--surface2);border-radius:4px;padding:.7rem 1rem;font-family:monospace;font-size:12px;">
        pip install garak<br>
        python3 cli.py --provider openai --api-key sk-... --with-garak
      </div>
    </div>
  </div>"""

    def _nist_tags(self, controls):
        tags = []
        for c in controls[:4]:
            fn = c.split("-")[0] if "-" in c else "GOVERN"
            tags.append(f'<span class="nist-tag nist-{fn}">{c}</span>')
        return "".join(tags)


class JSONUnifiedReportGenerator:
    def generate(self, our_report: ScanReport, garak_result=None) -> str:
        out = {
            "metadata": {
                "tool": "LLM Security Scanner (Unified)",
                "version": "1.0.0",
                "timestamp": our_report.timestamp,
                "frameworks": ["OWASP LLM Top 10 2025", "MITRE ATLAS v4.5.2", "NIST AI RMF 1.0"],
                "engines": ["LLM Security Scanner"] + (["garak"] if garak_result else []),
            },
            "target": {
                "name": our_report.target_name,
                "model": our_report.model,
            },
            "summary": {
                "overall_score": our_report.overall_score,
                "risk_rating": our_report.risk_rating,
                "our_scanner": {
                    "probes_run": our_report.probes_run,
                    "vulnerable": our_report.probes_vulnerable,
                },
                "garak": {
                    "probes_run": len(garak_result.findings) if garak_result else 0,
                    "vulnerable": len([f for f in garak_result.findings if f.vulnerable]) if garak_result else 0,
                } if garak_result else None,
            },
            "our_scanner_findings": [
                {
                    "probe_id": r.probe.id,
                    "name": r.probe.name,
                    "category": r.probe.category,
                    "severity": r.probe.severity,
                    "vulnerable": r.vulnerable,
                    "confidence": r.confidence,
                    "atlas_id": r.probe.atlas_ref,
                    "owasp_ref": r.probe.owasp_ref,
                    "remediation": r.probe.remediation,
                }
                for r in our_report.results
            ],
            "garak_findings": [
                {
                    "probe": f.probe,
                    "category": f.garak_category,
                    "severity": f.severity,
                    "vulnerable": f.vulnerable,
                    "confidence": f.confidence,
                    "atlas_id": f.atlas_id,
                    "atlas_name": f.atlas_name,
                    "tactic": f.tactic,
                    "owasp_ref": f.owasp_ref,
                    "nist_controls": f.nist_controls,
                    "remediation": f.remediation,
                }
                for f in (garak_result.findings if garak_result else [])
            ],
        }
        return json.dumps(out, indent=2)
