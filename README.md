# LLM Security Scanner

Active LLM security scanner — OWASP LLM Top 10 × MITRE ATLAS × NIST AI RMF

## Quick Start

```bash
cd src
python3 cli.py
```

## Features
- 17 agent-focused probes across 8 attack categories
- OWASP LLM Top 10 2025 + MITRE ATLAS + NIST AI RMF mapping
- Garak integration with ATLAS enrichment (39 probe mappings)
- Interactive scan mode menu
- HTML + JSON report generation
- Zero external dependencies (pure Python 3.8+)
- Supports OpenAI, Anthropic, Ollama, Mock connectors

## Usage

```bash
# Interactive menu (recommended)
python3 cli.py

# Direct CLI
python3 cli.py --provider openai --api-key sk-... --target "My Bot"
python3 cli.py --provider anthropic --api-key sk-ant-... --target "Claude Bot"
python3 cli.py --provider ollama --model llama3 --target "Local Model"
python3 cli.py --provider mock --vulnerable-mock --output-html report.html

# With garak (requires: pip install garak)
python3 cli.py --provider openai --api-key sk-... --with-garak
```

## Author
Tirthankar Dutta — github.com/tirthankardutta1983
## Screenshots

### Terminal Output
![Terminal Output](docs/screenshot_terminal.png)

### Security Report Dashboard
![Security Report](docs/screenshot_report.png)

### Vulnerability Heatmap
![Heatmap](docs/screenshot_heatmap.png)
## Related Projects
- [agent-security-auditor](https://github.com/tirthankardutta1983/agent-security-auditor) — 
  Audit AI agent architectures against MITRE ATLAS before deployment
  
