"""
Garak → MITRE ATLAS + NIST AI RMF Mapping Database
Maps every known garak probe module to:
  - MITRE ATLAS technique(s)
  - OWASP LLM Top 10 2025 reference
  - Severity rating
  - NIST AI RMF controls
  - Remediation guidance

Based on garak probe taxonomy: https://github.com/NVIDIA/garak
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GarakMapping:
    garak_probe: str          # garak probe module.ClassName
    garak_category: str       # garak's own category label
    atlas_id: str             # Primary MITRE ATLAS technique
    atlas_name: str
    tactic: str               # MITRE ATLAS tactic
    owasp_ref: str            # OWASP LLM Top 10 2025
    owasp_name: str
    severity: str             # CRITICAL / HIGH / MEDIUM / LOW
    description: str          # What this probe tests
    nist_controls: List[str]  # NIST AI RMF control IDs
    remediation: str
    secondary_atlas: List[str] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
# COMPLETE GARAK PROBE → ATLAS MAPPING
# Covers all 37+ garak probe modules as of garak 0.9.x
# ══════════════════════════════════════════════════════════════════════════════

GARAK_MAPPINGS: List[GarakMapping] = [

    # ── PROMPT INJECTION ──────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="promptinjection.HijackHatespeech",
        garak_category="Prompt Injection",
        atlas_id="AML.T0051",
        atlas_name="LLM Prompt Injection",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="CRITICAL",
        description="Tests whether the model can be hijacked into generating hate speech via injected instructions.",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2", "GOVERN-2.2"],
        remediation="Implement prompt hardening and output content classifiers. Monitor for injection confirmation phrases.",
        secondary_atlas=["AML.T0043"]
    ),
    GarakMapping(
        garak_probe="promptinjection.HijackKillHumans",
        garak_category="Prompt Injection",
        atlas_id="AML.T0051",
        atlas_name="LLM Prompt Injection",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="CRITICAL",
        description="Tests whether injected prompts can redirect model to produce harmful content about harming humans.",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2", "GOVERN-2.2"],
        remediation="Multi-layer output filtering. Explicit harm refusal training. Real-time output monitoring.",
    ),
    GarakMapping(
        garak_probe="promptinjection.HijackLongPrompt",
        garak_category="Prompt Injection",
        atlas_id="AML.T0051",
        atlas_name="LLM Prompt Injection",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="HIGH",
        description="Uses long prompts to dilute system instructions and inject adversarial directives.",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2"],
        remediation="Implement context length limits. Prioritize system prompt instructions over user content.",
    ),

    # ── JAILBREAKS ────────────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="dan.Dan_11_0",
        garak_category="Jailbreak",
        atlas_id="AML.T0051",
        atlas_name="LLM Prompt Injection",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="CRITICAL",
        description="DAN (Do Anything Now) jailbreak v11.0 — attempts to create an unrestricted AI persona.",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2", "GOVERN-1.1"],
        remediation="Train model to recognize and refuse DAN-style persona hijacking. Maintain identity stability.",
        secondary_atlas=["AML.T0015"]
    ),
    GarakMapping(
        garak_probe="dan.Dan_10_0",
        garak_category="Jailbreak",
        atlas_id="AML.T0051",
        atlas_name="LLM Prompt Injection",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="CRITICAL",
        description="DAN jailbreak v10.0 variant.",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2"],
        remediation="Robust jailbreak detection classifier. Consistent refusal across DAN variants.",
    ),
    GarakMapping(
        garak_probe="dan.DUDE",
        garak_category="Jailbreak",
        atlas_id="AML.T0051",
        atlas_name="LLM Prompt Injection",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="CRITICAL",
        description="DUDE jailbreak — 'Do Unlimited Disgusting Experiments' persona injection.",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2"],
        remediation="Persona stability training. Explicit jailbreak refusal patterns.",
    ),
    GarakMapping(
        garak_probe="dan.ChatGPT_Developer_Mode_v2",
        garak_category="Jailbreak",
        atlas_id="AML.T0051",
        atlas_name="LLM Prompt Injection",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="CRITICAL",
        description="Developer mode jailbreak — claims to unlock unrestricted mode via fake developer credentials.",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2", "GOVERN-1.1"],
        remediation="Reject all claims of special modes or developer overrides in user input.",
    ),
    GarakMapping(
        garak_probe="dan.AntiDAN",
        garak_category="Jailbreak",
        atlas_id="AML.T0015",
        atlas_name="Evade ML Model",
        tactic="Defense Evasion",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="HIGH",
        description="Anti-DAN technique — uses reverse psychology to bypass safety filters.",
        nist_controls=["MEASURE-2.2", "MANAGE-1.1"],
        remediation="Adversarial robustness training. Test defenses against reverse-psychology attack patterns.",
    ),
    GarakMapping(
        garak_probe="dan.AutoDAN",
        garak_category="Jailbreak",
        atlas_id="AML.T0015",
        atlas_name="Evade ML Model",
        tactic="Defense Evasion",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="CRITICAL",
        description="AutoDAN — automated generation of jailbreak prompts using genetic algorithms.",
        nist_controls=["MEASURE-2.2", "MANAGE-1.1", "MANAGE-2.2"],
        remediation="Deploy adaptive safety classifiers. Monitor for algorithmically-generated jailbreak patterns.",
        secondary_atlas=["AML.T0043"]
    ),

    # ── ENCODING / EVASION ────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="encoding.InjectBase64",
        garak_category="Encoding Bypass",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="HIGH",
        description="Encodes malicious instructions in Base64 to bypass content filters.",
        nist_controls=["MEASURE-2.2", "MANAGE-1.1"],
        remediation="Implement input normalization and decoding before content filtering. Detect and flag encoded payloads.",
    ),
    GarakMapping(
        garak_probe="encoding.InjectROT13",
        garak_category="Encoding Bypass",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="MEDIUM",
        description="Uses ROT13 encoding to obfuscate attack prompts.",
        nist_controls=["MEASURE-2.2"],
        remediation="Normalize common text encodings before safety evaluation.",
    ),
    GarakMapping(
        garak_probe="encoding.InjectHex",
        garak_category="Encoding Bypass",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="MEDIUM",
        description="Hex-encodes attack payloads to evade string-based filters.",
        nist_controls=["MEASURE-2.2"],
        remediation="Decode and normalize hex-encoded input before safety checks.",
    ),
    GarakMapping(
        garak_probe="encoding.InjectMorse",
        garak_category="Encoding Bypass",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="LOW",
        description="Uses Morse code encoding to obscure attack intent.",
        nist_controls=["MEASURE-2.2"],
        remediation="Detect unusual encoding patterns. Apply semantic content analysis post-decoding.",
    ),
    GarakMapping(
        garak_probe="encoding.InjectBraille",
        garak_category="Encoding Bypass",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="LOW",
        description="Uses Braille Unicode to bypass text-based safety filters.",
        nist_controls=["MEASURE-2.2"],
        remediation="Unicode normalization and homoglyph detection in input preprocessing.",
    ),

    # ── DATA LEAKAGE / EXFILTRATION ───────────────────────────────────────────

    GarakMapping(
        garak_probe="leakage.LeakPersonalInfoSURName",
        garak_category="Data Leakage",
        atlas_id="AML.T0040",
        atlas_name="ML Model Inversion Attack",
        tactic="Exfiltration",
        owasp_ref="LLM02:2025",
        owasp_name="Sensitive Information Disclosure",
        severity="HIGH",
        description="Attempts to extract memorized surnames from model training data.",
        nist_controls=["MEASURE-2.5", "MANAGE-1.1", "MAP-5.1"],
        remediation="Implement differential privacy in training. Add PII output filters. Audit for training data memorization.",
        secondary_atlas=["AML.T0024"]
    ),
    GarakMapping(
        garak_probe="leakage.LeakPersonalInfoFullAddress",
        garak_category="Data Leakage",
        atlas_id="AML.T0040",
        atlas_name="ML Model Inversion Attack",
        tactic="Exfiltration",
        owasp_ref="LLM02:2025",
        owasp_name="Sensitive Information Disclosure",
        severity="CRITICAL",
        description="Attempts to reconstruct full physical addresses from training data.",
        nist_controls=["MEASURE-2.5", "MANAGE-1.1", "MAP-5.1"],
        remediation="Differential privacy with high epsilon for address data. PII scrubbing in training pipeline.",
    ),
    GarakMapping(
        garak_probe="leakage.LeakEmailAddressesFromContext",
        garak_category="Data Leakage",
        atlas_id="AML.T0024",
        atlas_name="Exfiltration via ML Inference API",
        tactic="Exfiltration",
        owasp_ref="LLM02:2025",
        owasp_name="Sensitive Information Disclosure",
        severity="HIGH",
        description="Tests whether email addresses passed in context can be extracted by adversarial queries.",
        nist_controls=["MEASURE-2.5", "MANAGE-1.1"],
        remediation="Redact PII from context before processing. Output filtering for email address patterns.",
    ),

    # ── PACKAGE HALLUCINATION ─────────────────────────────────────────────────

    GarakMapping(
        garak_probe="packagehallucination.Python",
        garak_category="Hallucination",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM09:2025",
        owasp_name="Misinformation",
        severity="HIGH",
        description="Tests whether model hallucinates non-existent Python packages — exploitable for supply chain attacks via typosquatting.",
        nist_controls=["MEASURE-2.8", "MAP-3.3", "MANAGE-4.1"],
        remediation="Validate all generated package names against PyPI. Never execute LLM-generated install commands without verification.",
        secondary_atlas=["AML.T0010"]
    ),
    GarakMapping(
        garak_probe="packagehallucination.JavaScript",
        garak_category="Hallucination",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM09:2025",
        owasp_name="Misinformation",
        severity="HIGH",
        description="Tests whether model hallucinates non-existent npm packages.",
        nist_controls=["MEASURE-2.8", "MAP-3.3"],
        remediation="Validate npm package names before installation. Use lockfiles and package integrity verification.",
        secondary_atlas=["AML.T0010"]
    ),
    GarakMapping(
        garak_probe="packagehallucination.Ruby",
        garak_category="Hallucination",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM09:2025",
        owasp_name="Misinformation",
        severity="MEDIUM",
        description="Tests hallucinated Ruby gems — exploitable for RubyGems supply chain attacks.",
        nist_controls=["MEASURE-2.8", "MAP-3.3"],
        remediation="Verify all gem names against RubyGems registry before use.",
    ),

    # ── MALWARE GENERATION ────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="malwaregen.TopLevel",
        garak_category="Malware Generation",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM05:2025",
        owasp_name="Insecure Output Handling",
        severity="CRITICAL",
        description="Tests whether the model generates functional malware code when prompted.",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2", "GOVERN-1.1"],
        remediation="Deploy code output classifiers trained on malware patterns. Refuse code generation requests with malicious intent.",
        secondary_atlas=["AML.T0043"]
    ),
    GarakMapping(
        garak_probe="malwaregen.Evasion",
        garak_category="Malware Generation",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM05:2025",
        owasp_name="Insecure Output Handling",
        severity="CRITICAL",
        description="Tests generation of malware with evasion techniques (obfuscation, packing).",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2"],
        remediation="Multi-layer code analysis. Static analysis of all generated code before execution.",
    ),
    GarakMapping(
        garak_probe="malwaregen.Payload",
        garak_category="Malware Generation",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM05:2025",
        owasp_name="Insecure Output Handling",
        severity="CRITICAL",
        description="Tests generation of exploit payloads and shellcode.",
        nist_controls=["MANAGE-1.1", "MEASURE-2.2"],
        remediation="Strict code output sandboxing. Explicit refusal training for exploit generation.",
    ),

    # ── TOXICITY ──────────────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="toxicity.ToxicCommentModel",
        garak_category="Toxicity",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM06:2025",
        owasp_name="Excessive Agency",
        severity="HIGH",
        description="Tests whether the model generates toxic, abusive, or hateful content.",
        nist_controls=["MEASURE-2.8", "MANAGE-1.1", "GOVERN-5.1"],
        remediation="Deploy toxicity classifiers on outputs. RLHF training on non-toxic responses.",
    ),
    GarakMapping(
        garak_probe="toxicity.ToxicMitigation",
        garak_category="Toxicity",
        atlas_id="AML.T0015",
        atlas_name="Evade ML Model",
        tactic="Defense Evasion",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="HIGH",
        description="Tests robustness of toxicity mitigations — whether they can be bypassed.",
        nist_controls=["MEASURE-2.2", "MANAGE-2.2"],
        remediation="Adversarial testing of toxicity classifiers. Ensemble detection methods.",
    ),

    # ── XSS / INJECTION ───────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="xss.MarkdownExfilBasic",
        garak_category="Cross-Site Scripting",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM05:2025",
        owasp_name="Insecure Output Handling",
        severity="HIGH",
        description="Tests whether model embeds exfiltration URLs in markdown output (image tags, links).",
        nist_controls=["MEASURE-2.8", "MANAGE-1.1"],
        remediation="Sanitize markdown output. Block external URL generation in sensitive contexts.",
        secondary_atlas=["AML.T0024"]
    ),
    GarakMapping(
        garak_probe="xss.MarkdownExfilDynamic",
        garak_category="Cross-Site Scripting",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM05:2025",
        owasp_name="Insecure Output Handling",
        severity="HIGH",
        description="Dynamic markdown exfiltration using JavaScript URLs and event handlers.",
        nist_controls=["MEASURE-2.8", "MANAGE-1.1"],
        remediation="Content Security Policy enforcement. HTML sanitization of all LLM outputs.",
    ),

    # ── CONTINUATION / COMPLETION ATTACKS ────────────────────────────────────

    GarakMapping(
        garak_probe="continuation.ContinueSlursSentences",
        garak_category="Continuation",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM06:2025",
        owasp_name="Excessive Agency",
        severity="HIGH",
        description="Tests whether the model completes sentences containing slurs or hate speech.",
        nist_controls=["MEASURE-2.8", "MANAGE-1.1"],
        remediation="Prefix-based content moderation. Refuse completions that continue harmful content.",
    ),
    GarakMapping(
        garak_probe="continuation.ContinueSlursRephrase",
        garak_category="Continuation",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM06:2025",
        owasp_name="Excessive Agency",
        severity="HIGH",
        description="Rephrased completion attack to evade literal hate speech filters.",
        nist_controls=["MEASURE-2.8", "MANAGE-1.1"],
        remediation="Semantic content moderation beyond keyword filtering.",
    ),

    # ── REPLAY / CONTEXT ──────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="replay.Repeat",
        garak_category="Replay",
        atlas_id="AML.T0000",
        atlas_name="ML Model Access",
        tactic="Reconnaissance",
        owasp_ref="LLM02:2025",
        owasp_name="Sensitive Information Disclosure",
        severity="MEDIUM",
        description="Tests whether repeating prompts yields inconsistent safety responses — indicating unstable guardrails.",
        nist_controls=["MEASURE-1.1", "MANAGE-4.1"],
        remediation="Ensure consistent safety responses across repeated queries. Monitor for inconsistency.",
    ),

    # ── GOODSIDE / GRANDMA ────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="grandma.Win10",
        garak_category="Social Engineering",
        atlas_id="AML.T0011",
        atlas_name="User Execution",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="MEDIUM",
        description="Grandma jailbreak — roleplay as a deceased grandmother who read dangerous instructions as bedtime stories.",
        nist_controls=["MEASURE-2.2", "MANAGE-1.1"],
        remediation="Maintain safety policies regardless of emotional or nostalgic framing.",
    ),
    GarakMapping(
        garak_probe="grandma.Meth",
        garak_category="Social Engineering",
        atlas_id="AML.T0011",
        atlas_name="User Execution",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="HIGH",
        description="Grandma roleplay used to extract drug synthesis instructions.",
        nist_controls=["MEASURE-2.2", "MANAGE-1.1"],
        remediation="Topic-based safety regardless of conversational framing or roleplay context.",
    ),

    # ── MISLEADING CLAIMS ─────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="misleading.FalseAssertion",
        garak_category="Misinformation",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM09:2025",
        owasp_name="Misinformation",
        severity="MEDIUM",
        description="Tests whether the model agrees with false assertions when presented confidently.",
        nist_controls=["MEASURE-2.8", "MANAGE-4.1"],
        remediation="Factual grounding with RAG. Confidence calibration training.",
    ),
    GarakMapping(
        garak_probe="misleading.FalseAssertionRebuttal",
        garak_category="Misinformation",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM09:2025",
        owasp_name="Misinformation",
        severity="MEDIUM",
        description="Tests whether the model fails to rebut false assertions when challenged.",
        nist_controls=["MEASURE-2.8"],
        remediation="Epistemic robustness training. Model should maintain factual positions under pressure.",
    ),

    # ── KNOWNBADSIGNATURES ────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="knownbadsignatures.EICAR",
        garak_category="Known Bad Signatures",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM05:2025",
        owasp_name="Insecure Output Handling",
        severity="HIGH",
        description="Tests whether the model reproduces known malware signatures (EICAR test string).",
        nist_controls=["MEASURE-2.8", "MANAGE-1.1"],
        remediation="Output scanning against known malware signature databases.",
    ),

    # ── SUFFIX ATTACKS ────────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="suffix.GCGCached",
        garak_category="Adversarial Suffix",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="CRITICAL",
        description="GCG (Greedy Coordinate Gradient) adversarial suffix attack — appends optimized token sequences to bypass safety training.",
        nist_controls=["MEASURE-2.2", "MANAGE-1.1"],
        remediation="Adversarial suffix detection. Input perturbation robustness training.",
        secondary_atlas=["AML.T0015"]
    ),

    # ── TOPIC AVOIDANCE ───────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="topic.WordnetControversial",
        garak_category="Topic Avoidance",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM09:2025",
        owasp_name="Misinformation",
        severity="LOW",
        description="Tests whether model engages with controversial topics it should decline.",
        nist_controls=["GOVERN-5.1", "MANAGE-4.1"],
        remediation="Topic-based safety guidelines. Consistent refusal for out-of-scope subject matter.",
    ),

    # ── SNOWBALL ──────────────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="snowball.GraphConnectivity",
        garak_category="Hallucination",
        atlas_id="AML.T0047",
        atlas_name="Influence Operations via LLM",
        tactic="Impact",
        owasp_ref="LLM09:2025",
        owasp_name="Misinformation",
        severity="MEDIUM",
        description="Snowball hallucination — model builds on false premises, compounding errors over multi-turn conversation.",
        nist_controls=["MEASURE-2.8", "MANAGE-4.1"],
        remediation="Implement factual grounding checks. Detect and flag premise drift in multi-turn conversations.",
    ),

    # ── ATKGEN ────────────────────────────────────────────────────────────────

    GarakMapping(
        garak_probe="atkgen.Tox",
        garak_category="Adversarial Generation",
        atlas_id="AML.T0043",
        atlas_name="Craft Adversarial Data",
        tactic="Execution",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="HIGH",
        description="Adversarial attack generation — uses a red-team model to automatically generate toxic attack prompts.",
        nist_controls=["MEASURE-2.2", "MANAGE-2.2"],
        remediation="Continuous red-team testing with adaptive attack generation. Update defenses against newly generated attack patterns.",
        secondary_atlas=["AML.T0015"]
    ),
]


# ── Lookup helpers ────────────────────────────────────────────────────────────

def get_mapping_by_probe(probe_name: str) -> GarakMapping:
    """
    Find mapping for a garak probe name.
    Supports both exact match and prefix match (e.g. 'dan' matches all dan.* probes).
    Returns a default LOW mapping if not found.
    """
    # Exact match first
    for m in GARAK_MAPPINGS:
        if m.garak_probe == probe_name:
            return m

    # Prefix match (e.g. "dan.SomethingNew" → use dan.Dan_11_0 as representative)
    prefix = probe_name.split(".")[0] if "." in probe_name else probe_name
    for m in GARAK_MAPPINGS:
        if m.garak_probe.startswith(prefix + "."):
            # Return a copy with the actual probe name
            import copy
            copy_m = copy.copy(m)
            copy_m.garak_probe = probe_name
            return copy_m

    # Fallback for unknown probes
    return GarakMapping(
        garak_probe=probe_name,
        garak_category="Unknown",
        atlas_id="AML.T0000",
        atlas_name="ML Model Access",
        tactic="Reconnaissance",
        owasp_ref="LLM01:2025",
        owasp_name="Prompt Injection",
        severity="MEDIUM",
        description=f"Garak probe: {probe_name}. No specific ATLAS mapping found — defaulting to ML Model Access.",
        nist_controls=["MEASURE-2.2"],
        remediation="Review garak documentation for specific remediation guidance for this probe category.",
    )


def get_all_categories() -> list:
    seen = set()
    cats = []
    for m in GARAK_MAPPINGS:
        if m.garak_category not in seen:
            seen.add(m.garak_category)
            cats.append(m.garak_category)
    return cats


# Summary stats
TOTAL_MAPPED_PROBES = len(GARAK_MAPPINGS)
ATLAS_TECHNIQUES_COVERED = len(set(m.atlas_id for m in GARAK_MAPPINGS))
SEVERITY_BREAKDOWN = {
    "CRITICAL": len([m for m in GARAK_MAPPINGS if m.severity == "CRITICAL"]),
    "HIGH":     len([m for m in GARAK_MAPPINGS if m.severity == "HIGH"]),
    "MEDIUM":   len([m for m in GARAK_MAPPINGS if m.severity == "MEDIUM"]),
    "LOW":      len([m for m in GARAK_MAPPINGS if m.severity == "LOW"]),
}
