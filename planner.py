"""Adaptive planner. LLM (Claude) proposes next tools + rationale; output is VALIDATED
against allowed tools and discovered services. Falls back to deterministic rules if no API key."""
import json
import os

ALLOWED = {"nmap", "nikto", "zap"}
WEB_NAMES = {"http", "https", "http-proxy", "http-alt"}


def web_ports(services):
    return sorted({s["port"] for s in services if s["name"] in WEB_NAMES})


def rule_plan(stage, request, services, done):
    if stage == 1:
        return [{"tool": "nmap", "port": None,
                 "rationale": "Host/port/service discovery first; every later choice depends on what is exposed."}]
    steps, ports = [], web_ports(services)
    if not ports:
        return [{"tool": "none", "port": None,
                 "rationale": "No web services discovered, so Nikto/ZAP are skipped (avoids unnecessary scans)."}]
    for p in ports:
        if "nikto" not in done:
            steps.append({"tool": "nikto", "port": p, "rationale": f"HTTP found on {p}: check server config / known issues."})
        if "zap" not in done:
            steps.append({"tool": "zap", "port": p, "rationale": f"HTTP found on {p}: web-app/API weakness scan."})
    return steps


def llm_plan(stage, request, services, done):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        prompt = (
            "You plan an AUTHORISED lab-only security assessment. Choose next tools ONLY from "
            f"{sorted(ALLOWED)}. Already run: {sorted(done)}. Stage: {stage}. Analyst request: {request!r}. "
            f"Discovered services: {json.dumps(services)}. "
            'Reply ONLY JSON list: [{"tool":"nikto","port":80,"rationale":"..."}]. '
            "Stage 1 must be nmap only. Do not repeat done tools. Skip web tools if no web service exists "
            '(then return [{"tool":"none","port":null,"rationale":"..."}]).'
        )
        r = client.messages.create(model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6"),
                                   max_tokens=800, messages=[{"role": "user", "content": prompt}])
        txt = r.content[0].text.strip().strip("`").replace("json\n", "", 1)
        steps = json.loads(txt)
        valid_ports = {s["port"] for s in services}
        out = []
        for s in steps:
            if s.get("tool") == "none":
                return [s]
            if s.get("tool") in ALLOWED and (s["tool"] == "nmap" or s.get("port") in valid_ports):
                out.append(s)
        return out or None
    except Exception:
        return None


def make_plan(stage, request, services, done):
    p = llm_plan(stage, request, services, done)
    if p:
        return p, "LLM (validated)"
    return rule_plan(stage, request, services, done), "rule-based fallback"


def llm_summary(findings):
    """Executive summary grounded ONLY in the findings list; template fallback."""
    sev = {}
    for f in findings:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    top = findings[:3]
    base = (f"{len(findings)} consolidated findings were identified "
            f"({', '.join(f'{v} {k}' for k, v in sev.items())}). Highest priority: "
            + "; ".join(f"{t['id']} {t['title']} on {t['asset']}:{t['port']}" for t in top) + ".")
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return base
    try:
        import anthropic
        slim = [{k: f[k] for k in ("id", "title", "asset", "port", "severity", "risk_score", "status", "cve")} for f in findings[:15]]
        r = anthropic.Anthropic(api_key=key).messages.create(
            model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6"), max_tokens=500,
            messages=[{"role": "user", "content": "Write a 4-sentence executive summary for a client VAPT report. "
                       "Use ONLY these findings; do not invent CVEs, scores or facts:\n" + json.dumps(slim)}])
        return r.content[0].text.strip()
    except Exception:
        return base
