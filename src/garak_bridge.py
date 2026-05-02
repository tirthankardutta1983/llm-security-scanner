"""
Garak Bridge — Runs garak scans and enriches findings with MITRE ATLAS + NIST AI RMF
Requires: pip install garak  (optional — scanner works without it)
"""

import json
import subprocess
import shutil
import os
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple

from garak_mappings import GarakMapping, get_mapping_by_probe, GARAK_MAPPINGS


@dataclass
class GarakFinding:
    """A single enriched finding from garak output."""
    probe: str                      # garak probe name e.g. dan.Dan_11_0
    detector: str                   # garak detector used
    passed: bool                    # True = model resisted, False = vulnerable
    score: float                    # garak score (0=vulnerable, 1=safe)
    vulnerable: bool                # inverse of passed for consistency
    confidence: float               # our confidence score

    # ATLAS enrichment
    atlas_id: str
    atlas_name: str
    tactic: str
    secondary_atlas: List[str]

    # Framework mapping
    owasp_ref: str
    owasp_name: str
    severity: str
    nist_controls: List[str]
    remediation: str

    # Metadata
    garak_category: str
    description: str
    raw: dict = field(default_factory=dict)


@dataclass
class GarakScanResult:
    """Complete result from a garak scan run."""
    success: bool
    garak_version: str
    model: str
    probes_run: int
    findings: List[GarakFinding]
    error: Optional[str] = None
    raw_report_path: Optional[str] = None


class GarakBridge:
    """
    Orchestrates garak scans and enriches findings with MITRE ATLAS
    and NIST AI RMF mappings.

    Usage:
        bridge = GarakBridge()
        if bridge.is_available():
            result = bridge.run(model="openai/gpt-4o-mini", api_key="sk-...")
            for finding in result.findings:
                print(f"{finding.probe} → {finding.atlas_id} [{finding.severity}]")
        else:
            print("Install garak: pip install garak")
    """

    GARAK_PROBE_CATEGORIES = {
        "fast": [
            "dan.Dan_11_0",
            "dan.Dan_10_0",
            "promptinjection.HijackHatespeech",
            "encoding.InjectBase64",
            "leakage.LeakPersonalInfoSURName",
            "packagehallucination.Python",
            "xss.MarkdownExfilBasic",
        ],
        "standard": [
            "dan", "promptinjection", "encoding",
            "leakage", "xss", "continuation",
            "misleading", "grandma",
        ],
        "full": [],  # empty = all probes
    }

    def is_available(self) -> bool:
        """Check if garak is installed and accessible."""
        return shutil.which("garak") is not None or self._check_python_module()

    def _check_python_module(self) -> bool:
        try:
            import importlib
            return importlib.util.find_spec("garak") is not None
        except Exception:
            return False

    def get_version(self) -> str:
        """Get installed garak version."""
        try:
            result = subprocess.run(
                ["python3", "-m", "garak", "--version"],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip() or result.stderr.strip() or "unknown"
        except Exception:
            return "unknown"

    def run(
        self,
        model: str,
        api_key: str = "",
        probe_preset: str = "standard",
        custom_probes: Optional[List[str]] = None,
        output_dir: Optional[str] = None,
        timeout: int = 300,
    ) -> GarakScanResult:
        """
        Run a garak scan and return enriched findings.

        Args:
            model: Model string e.g. "openai/gpt-4o-mini", "huggingface/mistralai/Mistral-7B-v0.1"
            api_key: API key (also reads from OPENAI_API_KEY env var)
            probe_preset: "fast" | "standard" | "full"
            custom_probes: List of specific probe names to run
            output_dir: Where to save garak report files
            timeout: Max seconds to wait for garak scan
        """
        if not self.is_available():
            return GarakScanResult(
                success=False,
                garak_version="not installed",
                model=model,
                probes_run=0,
                findings=[],
                error="garak is not installed. Run: pip install garak"
            )

        # Set up output directory
        work_dir = output_dir or tempfile.mkdtemp(prefix="garak_scan_")
        os.makedirs(work_dir, exist_ok=True)

        # Build garak command
        cmd = self._build_command(model, probe_preset, custom_probes, work_dir)

        # Set environment
        env = os.environ.copy()
        if api_key:
            env["OPENAI_API_KEY"] = api_key
            env["ANTHROPIC_API_KEY"] = api_key

        try:
            proc = subprocess.run(
                cmd, env=env, capture_output=True, text=True,
                timeout=timeout, cwd=work_dir
            )
        except subprocess.TimeoutExpired:
            return GarakScanResult(
                success=False,
                garak_version=self.get_version(),
                model=model,
                probes_run=0,
                findings=[],
                error=f"Garak scan timed out after {timeout}s"
            )
        except Exception as e:
            return GarakScanResult(
                success=False,
                garak_version=self.get_version(),
                model=model,
                probes_run=0,
                findings=[],
                error=str(e)
            )

        # Parse output
        report_file = self._find_report_file(work_dir)
        if not report_file:
            return GarakScanResult(
                success=False,
                garak_version=self.get_version(),
                model=model,
                probes_run=0,
                findings=[],
                error=f"No garak report file found in {work_dir}. stderr: {proc.stderr[:500]}"
            )

        findings = self._parse_and_enrich(report_file)
        return GarakScanResult(
            success=True,
            garak_version=self.get_version(),
            model=model,
            probes_run=len(findings),
            findings=findings,
            raw_report_path=report_file
        )

    def run_from_existing_report(self, report_path: str) -> GarakScanResult:
        """
        Parse and enrich an existing garak .jsonl or .report.jsonl file.
        Use this if you've already run garak separately.

        Usage:
            bridge = GarakBridge()
            result = bridge.run_from_existing_report("my_garak_run.report.jsonl")
        """
        findings = self._parse_and_enrich(report_path)
        return GarakScanResult(
            success=True,
            garak_version="from existing report",
            model="from existing report",
            probes_run=len(findings),
            findings=findings,
            raw_report_path=report_path
        )

    def _build_command(
        self,
        model: str,
        preset: str,
        custom_probes: Optional[List[str]],
        work_dir: str
    ) -> List[str]:
        """Build the garak CLI command."""
        provider, model_name = model.split("/", 1) if "/" in model else ("openai", model)

        cmd = [
            "python3", "-m", "garak",
            "--model_type", provider,
            "--model_name", model_name,
            "--report_prefix", os.path.join(work_dir, "garak_report"),
            "--extended_detectors",
        ]

        if custom_probes:
            cmd += ["--probes", ",".join(custom_probes)]
        elif preset == "fast":
            cmd += ["--probes", ",".join(self.GARAK_PROBE_CATEGORIES["fast"])]
        elif preset == "standard":
            cmd += ["--probes", ",".join(self.GARAK_PROBE_CATEGORIES["standard"])]
        # full = no --probes flag = all probes

        return cmd

    def _find_report_file(self, work_dir: str) -> Optional[str]:
        """Find the garak report .jsonl file in the output directory."""
        for root, _, files in os.walk(work_dir):
            for f in files:
                if f.endswith(".report.jsonl") or f.endswith(".jsonl"):
                    return os.path.join(root, f)
        return None

    def _parse_and_enrich(self, report_path: str) -> List[GarakFinding]:
        """
        Parse garak's JSONL report and enrich each finding with
        MITRE ATLAS, OWASP, severity, NIST controls, and remediation.
        """
        findings = []
        seen_probes = set()

        try:
            with open(report_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # Garak report format varies by version
                    # Handle both probe-level and attempt-level records
                    probe = self._extract_probe_name(record)
                    if not probe or probe in seen_probes:
                        continue

                    passed = record.get("passed", record.get("status") == "passed")
                    score = record.get("score", 1.0 if passed else 0.0)
                    vulnerable = not passed

                    # Enrich with our mapping
                    mapping = get_mapping_by_probe(probe)
                    confidence = self._score_to_confidence(score, vulnerable)

                    finding = GarakFinding(
                        probe=probe,
                        detector=record.get("detector", ""),
                        passed=passed,
                        score=score,
                        vulnerable=vulnerable,
                        confidence=confidence,
                        atlas_id=mapping.atlas_id,
                        atlas_name=mapping.atlas_name,
                        tactic=mapping.tactic,
                        secondary_atlas=mapping.secondary_atlas,
                        owasp_ref=mapping.owasp_ref,
                        owasp_name=mapping.owasp_name,
                        severity=mapping.severity,
                        nist_controls=mapping.nist_controls,
                        remediation=mapping.remediation,
                        garak_category=mapping.garak_category,
                        description=mapping.description,
                        raw=record,
                    )
                    findings.append(finding)
                    seen_probes.add(probe)

        except FileNotFoundError:
            pass

        return findings

    def _extract_probe_name(self, record: dict) -> Optional[str]:
        """Extract probe name from various garak report formats."""
        for key in ["probe", "probe_name", "probe_classname", "module"]:
            if key in record:
                val = record[key]
                if isinstance(val, str) and val:
                    return val
        return None

    def _score_to_confidence(self, score: float, vulnerable: bool) -> float:
        """Convert garak's 0-1 score to our confidence metric."""
        if vulnerable:
            # Lower score = more vulnerable = higher confidence in finding
            return round(min(1.0, 0.5 + (1.0 - score) * 0.5), 2)
        else:
            return round(min(1.0, 0.5 + score * 0.5), 2)

    def enrich_report_file(self, report_path: str, output_path: str) -> dict:
        """
        Standalone utility: take any garak .jsonl report,
        enrich it with ATLAS+NIST, save enriched JSON.
        Returns summary dict.
        """
        result = self.run_from_existing_report(report_path)
        enriched = {
            "source": "garak",
            "original_report": report_path,
            "total_findings": len(result.findings),
            "vulnerable": len([f for f in result.findings if f.vulnerable]),
            "findings": [
                {
                    "probe": f.probe,
                    "category": f.garak_category,
                    "vulnerable": f.vulnerable,
                    "score": f.score,
                    "confidence": f.confidence,
                    "severity": f.severity,
                    "atlas": {
                        "id": f.atlas_id,
                        "name": f.atlas_name,
                        "tactic": f.tactic,
                        "secondary": f.secondary_atlas,
                    },
                    "owasp": {
                        "ref": f.owasp_ref,
                        "name": f.owasp_name,
                    },
                    "nist_controls": f.nist_controls,
                    "remediation": f.remediation,
                    "description": f.description,
                }
                for f in result.findings
            ]
        }
        with open(output_path, "w") as out:
            json.dump(enriched, out, indent=2)

        return {
            "total": len(result.findings),
            "vulnerable": enriched["vulnerable"],
            "output": output_path
        }
