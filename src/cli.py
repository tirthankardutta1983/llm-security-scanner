#!/usr/bin/env python3
"""
LLM Security Scanner v1.0.0
Interactive menu + CLI mode
"""

import sys
import os
import argparse
import time

sys.path.insert(0, os.path.dirname(__file__))

from scanner import (LLMSecurityScanner, OpenAIConnector, AnthropicConnector,
                     OllamaConnector, MockConnector)
from report_generator import ScanReportHTMLGenerator, JSONReportGenerator
from probe_library import CATEGORIES, PROBE_LIBRARY, SEVERITY_WEIGHTS


class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    RED="\033[91m"; ORANGE="\033[38;5;208m"; YELLOW="\033[93m"
    GREEN="\033[92m"; CYAN="\033[96m"; GRAY="\033[90m"
    WHITE="\033[97m"; MAGENTA="\033[95m"; BG_SURFACE="\033[48;5;235m"


# ── Helpers ───────────────────────────────────────────────────────────────────

def banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ╔══════════════════════════════════════════════════════════════════╗
  ║              LLM SECURITY SCANNER  v1.0.0                       ║
  ║     OWASP LLM Top 10  ×  MITRE ATLAS  ×  NIST AI RMF           ║
  ║                                                                  ║
  ║          Developed by  Tirthankar Dutta                         ║
  ╚══════════════════════════════════════════════════════════════════╝
{C.RESET}
  {C.GRAY}Active probing · Agent-focused · Framework-mapped findings{C.RESET}
""")


def divider(title=""):
    if title:
        pad = (62 - len(title) - 2) // 2
        print(f"\n  {C.GRAY}{'─'*pad} {C.CYAN}{title}{C.RESET} {C.GRAY}{'─'*pad}{C.RESET}\n")
    else:
        print(f"\n  {C.GRAY}{'─'*64}{C.RESET}\n")


def ask(prompt, default=""):
    val = input(f"  {C.BOLD}{prompt}{C.RESET} ").strip()
    return val if val else default


def choose(prompt, options, default=1):
    """
    Display numbered options and return the user's choice index (0-based).
    options = list of (label, description) tuples
    """
    print(f"  {C.BOLD}{prompt}{C.RESET}\n")
    for i, (label, desc) in enumerate(options, 1):
        print(f"  {C.CYAN}[{i}]{C.RESET}  {C.WHITE}{label:<35}{C.RESET}  {C.GRAY}{desc}{C.RESET}")
    print()
    while True:
        raw = input(f"  {C.BOLD}Enter choice [1-{len(options)}] (default {default}):{C.RESET} ").strip()
        if not raw:
            return default - 1
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1
        print(f"  {C.RED}Invalid — enter a number between 1 and {len(options)}{C.RESET}")


def progress(current, total, name):
    pct = int(current / total * 32)
    bar = f"{C.CYAN}{'█'*pct}{C.GRAY}{'░'*(32-pct)}{C.RESET}"
    print(f"\r  [{bar}] {current}/{total}  {C.GRAY}{name[:42]:<42}{C.RESET}", end="", flush=True)


def sev_color(sev):
    return {
        "CRITICAL": C.RED, "HIGH": C.ORANGE,
        "MEDIUM": C.YELLOW, "LOW": C.GREEN
    }.get(sev, C.WHITE)


# ── Scan mode menu ────────────────────────────────────────────────────────────

SCAN_MODES = [
    (
        "Our Scanner Only",
        "17 agent-focused probes, ATLAS+NIST mapped, agentic attacks"
    ),
    (
        "Garak Only  (requires: pip install garak)",
        "37+ probes, all enriched with ATLAS+NIST via our mapping layer"
    ),
    (
        "Our Scanner + Garak  [UNIFIED]",
        "Both engines, single report — maximum coverage"
    ),
    (
        "Enrich existing Garak report",
        "Parse a .jsonl file from a previous garak run, add ATLAS+NIST"
    ),
]

PROVIDER_OPTIONS = [
    ("OpenAI  (GPT-4, GPT-4o, GPT-4o-mini)", "Requires OPENAI_API_KEY or --api-key"),
    ("Anthropic  (Claude models)",             "Requires ANTHROPIC_API_KEY or --api-key"),
    ("Ollama  (local models)",                 "Runs locally, no API key needed"),
    ("Mock  (demo / testing)",                 "No API key, simulates vulnerable model"),
]

GARAK_PRESET_OPTIONS = [
    ("Fast    (~2 min,  7 probes)",  "DAN, prompt injection, encoding, leakage basics"),
    ("Standard (~10 min, 8 categories)", "Covers jailbreaks, encoding, XSS, leakage, continuation"),
    ("Full    (~30+ min, all probes)",   "Every garak probe — use with care on paid APIs"),
]

SEVERITY_OPTIONS = [
    ("All severities",       "Run every probe"),
    ("CRITICAL + HIGH only", "Skip MEDIUM and LOW"),
    ("CRITICAL only",        "Fastest — highest-risk probes only"),
]


# ── Interactive wizard ────────────────────────────────────────────────────────

def interactive_wizard():
    """
    Guides the user through scan setup via an interactive menu.
    Returns a config dict used by run_scan().
    """
    banner()
    divider("SCAN SETUP WIZARD")

    # ── Step 1: Scan mode ──
    mode_idx = choose("What would you like to run?", SCAN_MODES, default=1)
    mode = ["ours_only", "garak_only", "unified", "enrich_garak"][mode_idx]

    # ── Step 2: Garak report path (enrich mode only) ──
    if mode == "enrich_garak":
        divider("GARAK REPORT")
        path = ask("Path to garak .jsonl report file:")
        if not path or not os.path.exists(path):
            print(f"\n  {C.RED}File not found: {path}{C.RESET}\n")
            sys.exit(1)
        out_html = ask("Save HTML report to (leave blank to skip):", "")
        out_json = ask("Save JSON report to (leave blank to skip):", "enriched_garak.json")
        return {"mode": "enrich_garak", "garak_report": path,
                "output_html": out_html, "output_json": out_json}

    # ── Step 3: LLM Provider ──
    divider("LLM TARGET")
    prov_idx = choose("Which LLM provider are you scanning?", PROVIDER_OPTIONS, default=4)
    provider = ["openai", "anthropic", "ollama", "mock"][prov_idx]

    api_key = ""
    model = ""

    if provider == "openai":
        api_key = ask("OpenAI API key (or set OPENAI_API_KEY env var):",
                      os.environ.get("OPENAI_API_KEY", ""))
        model = ask("Model name [gpt-4o-mini]:", "gpt-4o-mini")
    elif provider == "anthropic":
        api_key = ask("Anthropic API key (or set ANTHROPIC_API_KEY env var):",
                      os.environ.get("ANTHROPIC_API_KEY", ""))
        model = ask("Model name [claude-3-haiku-20240307]:", "claude-3-haiku-20240307")
    elif provider == "ollama":
        model = ask("Model name [llama3]:", "llama3")
        host = ask("Ollama host [http://localhost:11434]:", "http://localhost:11434")
    else:
        model = "mock-vulnerable"
        print(f"\n  {C.YELLOW}Mock mode — simulating a vulnerable model for demo purposes{C.RESET}")

    target = ask("Target name (for report header) [My LLM Agent]:", "My LLM Agent")

    system_prompt = ask("System prompt to use during scan (leave blank for none):", "")

    # ── Step 4: Our scanner options ──
    if mode in ("ours_only", "unified"):
        divider("OUR SCANNER OPTIONS")
        sev_idx = choose("Which severity levels to run?", SEVERITY_OPTIONS, default=1)
        severity = [None, "HIGH", "CRITICAL"][sev_idx]

        print(f"\n  {C.BOLD}Probe categories available:{C.RESET}\n")
        cats = list(CATEGORIES.keys())
        for i, cat in enumerate(cats, 1):
            count = len(CATEGORIES[cat])
            print(f"  {C.CYAN}[{i}]{C.RESET}  {cat}  {C.GRAY}({count} probes){C.RESET}")
        print(f"  {C.CYAN}[A]{C.RESET}  All categories  {C.GRAY}(default){C.RESET}")
        print()
        raw = input(f"  {C.BOLD}Enter category numbers to run (e.g. 1,3,5) or press Enter for all:{C.RESET} ").strip()
        selected_cats = None
        if raw and raw.upper() != "A":
            indices = [int(x.strip()) - 1 for x in raw.split(",")
                       if x.strip().isdigit() and 0 <= int(x.strip())-1 < len(cats)]
            selected_cats = [cats[i] for i in indices] if indices else None

        thorough = False
        t = ask("Run all prompts per probe for thorough scan? [y/N]:", "n")
        if t.lower() == "y":
            thorough = True
            print(f"  {C.YELLOW}Thorough mode — this will use more API calls{C.RESET}")

    else:
        severity = None
        selected_cats = None
        thorough = False

    # ── Step 5: Garak options ──
    garak_preset = "standard"
    if mode in ("garak_only", "unified"):
        divider("GARAK OPTIONS")
        preset_idx = choose("Garak probe preset?", GARAK_PRESET_OPTIONS, default=1)
        garak_preset = ["fast", "standard", "full"][preset_idx]

        print(f"\n  {C.GRAY}Note: Full preset on paid APIs (OpenAI/Anthropic) may cost $5-20+{C.RESET}")

    # ── Step 6: Output ──
    divider("OUTPUT")
    out_html = ask("Save HTML report to [scan_report.html]:", "scan_report.html")
    out_json = ask("Save JSON report to (leave blank to skip):", "")

    print()
    return {
        "mode": mode,
        "provider": provider,
        "api_key": api_key,
        "model": model,
        "host": locals().get("host", "http://localhost:11434"),
        "target": target,
        "system_prompt": system_prompt,
        "severity": severity,
        "categories": selected_cats,
        "thorough": thorough,
        "garak_preset": garak_preset,
        "output_html": out_html,
        "output_json": out_json,
    }


# ── Scan runner ───────────────────────────────────────────────────────────────

def build_connector(config):
    p = config["provider"]
    if p == "openai":
        return OpenAIConnector(api_key=config["api_key"], model=config["model"])
    elif p == "anthropic":
        return AnthropicConnector(api_key=config["api_key"], model=config["model"])
    elif p == "ollama":
        return OllamaConnector(model=config["model"], host=config["host"])
    else:
        c = MockConnector(vulnerable=True)
        c.model = "mock-vulnerable"
        return c


def run_scan(config):
    report = None
    garak_result = None

    # ── Enrich existing garak report ──
    if config["mode"] == "enrich_garak":
        from garak_bridge import GarakBridge
        divider("ENRICHING GARAK REPORT")
        print(f"  {C.GRAY}Reading: {config['garak_report']}{C.RESET}\n")
        bridge = GarakBridge()
        garak_result = bridge.run_from_existing_report(config["garak_report"])
        _print_garak_findings(garak_result)
        _save_outputs(None, garak_result, config)
        return

    # ── Our scanner ──
    if config["mode"] in ("ours_only", "unified"):
        divider("OUR SCANNER")
        connector = build_connector(config)
        scanner = LLMSecurityScanner(
            connector=connector,
            target_name=config["target"],
            target_endpoint=config.get("host", config["provider"]),
            system_prompt=config.get("system_prompt", ""),
            categories=config.get("categories"),
            severity_filter=config.get("severity"),
            delay_between_probes=0.3,
        )
        probe_count = len([p for p in PROBE_LIBRARY
                          if _probe_passes_filter(p, config)])
        print(f"  {C.BOLD}Target:{C.RESET} {config['target']}  |  "
              f"Model: {config['model']}  |  Probes: {probe_count}\n")
        try:
            report = scanner.scan_all_prompts(progress_callback=progress) \
                     if config.get("thorough") \
                     else scanner.scan(progress_callback=progress)
            print()  # newline after progress bar
        except KeyboardInterrupt:
            print(f"\n\n  {C.YELLOW}Scan aborted.{C.RESET}\n")
            sys.exit(130)
        _print_our_results(report)

    # ── Garak ──
    if config["mode"] in ("garak_only", "unified"):
        from garak_bridge import GarakBridge
        bridge = GarakBridge()

        if not bridge.is_available():
            print(f"\n  {C.RED}✗ garak is not installed.{C.RESET}")
            print(f"  {C.GRAY}Run:  pip install garak{C.RESET}")
            print(f"  {C.GRAY}Then re-run this scan with garak enabled.{C.RESET}\n")
            if config["mode"] == "garak_only":
                sys.exit(1)
        else:
            divider("GARAK SCAN")
            model_str = f"{config['provider']}/{config['model']}"
            print(f"  {C.BOLD}Running garak against:{C.RESET} {model_str}")
            print(f"  {C.BOLD}Preset:{C.RESET} {config['garak_preset']}  "
                  f"| {C.GRAY}This may take several minutes...{C.RESET}\n")

            garak_result = bridge.run(
                model=model_str,
                api_key=config.get("api_key", ""),
                probe_preset=config["garak_preset"],
            )

            if garak_result.success:
                vuln = [f for f in garak_result.findings if f.vulnerable]
                print(f"  {C.GREEN}✓ Garak complete{C.RESET}  "
                      f"Probes: {len(garak_result.findings)}  |  "
                      f"Vulnerable: {C.RED}{len(vuln)}{C.RESET}\n")
                _print_garak_findings(garak_result)
            else:
                print(f"  {C.RED}✗ Garak failed: {garak_result.error}{C.RESET}\n")
                garak_result = None

    # ── Save outputs ──
    _save_outputs(report, garak_result, config)


def _probe_passes_filter(probe, config):
    if config.get("severity"):
        if SEVERITY_WEIGHTS.get(probe.severity, 0) < SEVERITY_WEIGHTS.get(config["severity"], 0):
            return False
    if config.get("categories"):
        from probe_library import CATEGORIES
        allowed = set()
        for cat in config["categories"]:
            allowed.update(CATEGORIES.get(cat, []))
        if probe.id not in allowed:
            return False
    return True


def _print_our_results(report):
    rc = sev_color(report.risk_rating)
    divider("OUR SCANNER RESULTS")
    print(f"  {C.BOLD}Risk Rating:{C.RESET}  {rc}{C.BOLD}{report.risk_rating}{C.RESET}  "
          f"({report.overall_score}/100)\n")
    print(f"  {C.RED}● Vulnerable  {report.probes_vulnerable}{C.RESET}   "
          f"{C.GREEN}● Resistant  {report.probes_resistant}{C.RESET}   "
          f"{C.GRAY}● Errored  {report.probes_errored}{C.RESET}\n")

    if report.category_scores:
        print(f"  {C.BOLD}Category Breakdown:{C.RESET}")
        for cat, score in sorted(report.category_scores.items(), key=lambda x: -x[1]):
            color = sev_color("CRITICAL" if score>=70 else "HIGH" if score>=45 else "MEDIUM" if score>=20 else "LOW")
            bar_f = int(score / 100 * 28)
            bar = f"{color}{'█'*bar_f}{C.GRAY}{'░'*(28-bar_f)}{C.RESET}"
            print(f"  {C.GRAY}{cat:<32}{C.RESET}  {bar}  {score:.0f}%")
        print()

    vuln = [r for r in report.results if r.vulnerable]
    if vuln:
        print(f"  {C.BOLD}Vulnerabilities Found ({len(vuln)}):{C.RESET}\n")
        for r in vuln:
            sc = sev_color(r.probe.severity)
            print(f"  {sc}▶ {r.probe.severity:<8}{C.RESET}  "
                  f"{C.WHITE}{r.probe.id}{C.RESET}  {r.probe.name}")
            print(f"            {C.GRAY}{r.probe.owasp_ref}  ·  "
                  f"{r.probe.atlas_ref}  ·  {int(r.confidence*100)}% confidence{C.RESET}")
            print(f"            {C.GREEN}✓ {r.probe.remediation[:75]}...{C.RESET}\n")


def _print_garak_findings(garak_result):
    vuln = [f for f in garak_result.findings if f.vulnerable]
    safe = [f for f in garak_result.findings if not f.vulnerable]

    if not vuln:
        print(f"  {C.GREEN}✓ No vulnerabilities found by garak.{C.RESET}\n")
        return

    print(f"  {C.BOLD}Garak Vulnerabilities ({len(vuln)}) — ATLAS Enriched:{C.RESET}\n")
    for f in vuln:
        sc = sev_color(f.severity)
        print(f"  {sc}▶ {f.severity:<8}{C.RESET}  "
              f"{C.WHITE}{f.probe}{C.RESET}  "
              f"{C.GRAY}[{f.garak_category}]{C.RESET}")
        print(f"            {C.CYAN}ATLAS:{C.RESET} {f.atlas_id} — {f.atlas_name}")
        print(f"            {C.CYAN}Tactic:{C.RESET} {f.tactic}  "
              f"{C.CYAN}OWASP:{C.RESET} {f.owasp_ref}")
        nist = "  ".join(f.nist_controls[:3])
        print(f"            {C.CYAN}NIST:{C.RESET}  {nist}")
        print(f"            {C.GREEN}✓ {f.remediation[:75]}...{C.RESET}\n")

    if safe:
        print(f"  {C.GRAY}Resistant: {len(safe)} probes passed  "
              f"(run with --verbose to see details){C.RESET}\n")


def _save_outputs(report, garak_result, config):
    out_html = config.get("output_html", "")
    out_json = config.get("output_json", "")

    if not out_html and not out_json:
        return

    divider("SAVING REPORTS")

    if out_html:
        if report and garak_result:
            from unified_report import UnifiedHTMLReportGenerator
            html = UnifiedHTMLReportGenerator().generate(report, garak_result)
        elif report:
            html = ScanReportHTMLGenerator().generate(report)
        elif garak_result:
            # Garak-only or enrich mode — build minimal stub
            from scanner import ScanReport
            from unified_report import UnifiedHTMLReportGenerator
            stub = ScanReport(
                target_name=config.get("target", "Garak Scan"),
                target_endpoint="", timestamp=_now(),
                model=garak_result.model,
                probes_run=0, probes_vulnerable=0,
                probes_resistant=0, probes_errored=0,
                overall_score=_garak_score(garak_result),
                risk_rating=_garak_rating(garak_result),
            )
            html = UnifiedHTMLReportGenerator().generate(stub, garak_result)
        else:
            return

        with open(out_html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"  {C.GREEN}✓ HTML report saved:{C.RESET} {os.path.abspath(out_html)}")

    if out_json:
        if report and garak_result:
            from unified_report import JSONUnifiedReportGenerator
            j = JSONUnifiedReportGenerator().generate(report, garak_result)
        elif report:
            j = JSONReportGenerator().generate(report)
        elif garak_result:
            import json
            j = json.dumps({
                "source": "garak",
                "findings": [{
                    "probe": f.probe, "category": f.garak_category,
                    "vulnerable": f.vulnerable, "severity": f.severity,
                    "atlas": {"id": f.atlas_id, "name": f.atlas_name, "tactic": f.tactic},
                    "owasp": {"ref": f.owasp_ref, "name": f.owasp_name},
                    "nist_controls": f.nist_controls,
                    "remediation": f.remediation,
                } for f in garak_result.findings]
            }, indent=2)
        else:
            return

        with open(out_json, "w", encoding="utf-8") as f:
            f.write(j)
        print(f"  {C.GREEN}✓ JSON report saved:{C.RESET} {os.path.abspath(out_json)}")

    print()
    if out_html:
        print(f"  {C.CYAN}Open your report:{C.RESET}")
        print(f"  {C.GRAY}open {os.path.abspath(out_html)}{C.RESET}\n")


def _now():
    from datetime import datetime
    return datetime.utcnow().isoformat() + "Z"


def _garak_score(gr):
    total = len(gr.findings)
    if not total:
        return 0.0
    return round(len([f for f in gr.findings if f.vulnerable]) / total * 100, 1)


def _garak_rating(gr):
    score = _garak_score(gr)
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"


# ── Main entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="LLM Security Scanner — interactive menu or CLI flags",
        add_help=True,
    )
    parser.add_argument("--no-menu", action="store_true",
                        help="Skip interactive menu (use CLI flags directly)")
    parser.add_argument("--provider", "-p", default="mock",
                        choices=["openai","anthropic","ollama","mock"])
    parser.add_argument("--api-key", "-k", default="")
    parser.add_argument("--model", "-m", default="")
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--target", "-t", default="Target LLM")
    parser.add_argument("--system-prompt", "-s", default="")
    parser.add_argument("--categories", nargs="+", choices=list(CATEGORIES.keys()))
    parser.add_argument("--severity", choices=["LOW","MEDIUM","HIGH","CRITICAL"])
    parser.add_argument("--thorough", action="store_true")
    parser.add_argument("--output-html", default="scan_report.html")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--vulnerable-mock", action="store_true")
    parser.add_argument("--with-garak", action="store_true")
    parser.add_argument("--garak-only", action="store_true")
    parser.add_argument("--garak-report", metavar="PATH")
    parser.add_argument("--garak-preset", default="standard",
                        choices=["fast","standard","full"])
    parser.add_argument("--list-probes", action="store_true")

    args = parser.parse_args()

    if args.list_probes:
        print(f"\n  {'ID':<10} {'SEVERITY':<10} {'CATEGORY':<32} NAME")
        print(f"  {'─'*82}")
        for p in PROBE_LIBRARY:
            print(f"  {p.id:<10} {p.severity:<10} {p.category:<32} {p.name}")
        print()
        sys.exit(0)

    # ── Interactive menu mode (default when no key flags passed) ──
    cli_flags_used = any([
        args.no_menu, args.with_garak, args.garak_only,
        args.garak_report, args.provider != "mock",
        args.api_key, args.model
    ])

    if not cli_flags_used:
        # Launch interactive wizard
        config = interactive_wizard()
    else:
        # Build config from CLI flags directly
        banner()
        mode = "unified" if args.with_garak else \
               "garak_only" if args.garak_only else \
               "enrich_garak" if args.garak_report else "ours_only"
        config = {
            "mode": mode,
            "provider": args.provider,
            "api_key": args.api_key or os.environ.get("OPENAI_API_KEY",""),
            "model": args.model or ("mock-vulnerable" if args.provider=="mock" else "gpt-4o-mini"),
            "host": args.host,
            "target": args.target,
            "system_prompt": args.system_prompt,
            "severity": args.severity,
            "categories": args.categories,
            "thorough": args.thorough,
            "garak_preset": args.garak_preset,
            "garak_report": args.garak_report,
            "output_html": args.output_html,
            "output_json": args.output_json,
            "vulnerable_mock": args.vulnerable_mock,
        }

    run_scan(config)


if __name__ == "__main__":
    main()
