# AI-Powered Unified VAPT Agent (Hackathon prototype)

Conversational agent: request -> scope check -> plan (LLM or rules) -> human-approved scans -> normalise/correlate -> risk rank -> approval gate -> PDF report.

## Setup
```
python -m venv venv
venv\Scripts\activate        (Windows)   |   source venv/bin/activate (Linux/Mac)
pip install -r requirements.txt
# optional LLM planner:  set ANTHROPIC_API_KEY=your_key   (Windows)  | export ANTHROPIC_API_KEY=... (Linux/Mac)
streamlit run app.py
```
## Demo
Sidebar: scope `192.168.56.0/24`, mode `import`. Chat: `Run a full assessment of 192.168.56.101`.
Try `scan 8.8.8.8` to see scope rejection. Live mode needs nmap/nikto installed and a lab VM (e.g. Metasploitable/DVWA).

## Integration matrix (honest)
| Tool | Status |
|---|---|
| Nmap | Live + Import |
| Nikto | Live + Import |
| OWASP ZAP | Import-only (JSON report) |
| Nessus, Burp | Unsupported (commercial) |
| OpenVAS | Planned |
| Metasploit | Planned - approval gate only, NO exploit executed |

## Notes
- `sample_data/` files are SYNTHETIC examples, not real scans. Disclose this in the demo.
- Risk score = (CVSS or severity base) x exposure x asset impact x confidence weight, capped at 10. CVEs are only reported if a tool printed them.
- Duplicates merge by (asset, port, category); all tool evidence is kept. 2+ tools => confirmed/high confidence.
- Audit trail: `audit_log.jsonl`. Licences: Streamlit (Apache-2.0), ReportLab (BSD), Anthropic SDK (MIT).
