"""Client-ready PDF VAPT report (ReportLab)."""
from xml.sax.saxutils import escape
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from adapters import INTEGRATIONS

SEV_COL = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#f59e0b", "low": "#2563eb", "info": "#6b7280"}


def P(t, s):
    return Paragraph(escape(str(t)), s)


def build_pdf(path, scope, findings, runs, approvals, summary, request, exposure):
    st = getSampleStyleSheet()
    h1, h2, body = st["Heading1"], st["Heading2"], st["BodyText"]
    small = st["BodyText"].clone("small", fontSize=8, leading=10)
    doc = SimpleDocTemplate(path, pagesize=A4, title="VAPT Report")
    el = [P("Vulnerability Assessment & Penetration Test Report", st["Title"]),
          P("AI-assisted, lab-only assessment. Findings are grounded in tool evidence.", body), Spacer(1, 12)]

    el += [P("1. Executive Summary", h1), P(summary, body),
           P(f"Scope: {', '.join(scope.targets)} | Exclusions: {', '.join(scope.exclusions) or 'none'} | Exposure assumption: {exposure}", body),
           P(f"Analyst request: {request}", body)]

    el += [P("2. Assessment Methodology", h1),
           P("Approach follows NIST SP 800-115 phases (discovery, scanning, analysis, reporting) and references OWASP Top 10, CVE, CVSS, CWE. "
             "This does not claim formal compliance with any standard.", body),
           P("Rules of engagement: lab targets only; scope checked before every action; active validation needs explicit human approval.", body),
           P("Tool execution summary", h2)]
    rows = [["Tool", "Port", "Mode", "Status", "Note"]] + [[r["tool"], r["port"] or "-", r["mode"], r["status"], r.get("note", "")[:70]] for r in runs]
    t = Table([[P(c, small) for c in r] for r in rows], colWidths=[50, 35, 45, 60, 300])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), .3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
    el += [t]
    el += [P("Integration status", h2)]
    t = Table([[P(c, small) for c in r] for r in [("Tool", "Status", "Notes")] + INTEGRATIONS], colWidths=[100, 110, 280])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), .3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
    el += [t]

    el += [P("3. Severity Distribution & Prioritised Findings", h1)]
    dist = {}
    for f in findings:
        dist[f["severity"]] = dist.get(f["severity"], 0) + 1
    el += [P("; ".join(f"{k}: {v}" for k, v in dist.items()), body)]
    rows = [["ID", "Title", "Asset", "Sev", "Risk", "Status"]] + [[f["id"], f["title"][:50], f"{f['asset']}:{f['port']}", f["severity"], f["risk_score"], f["status"]] for f in findings]
    t = Table([[P(c, small) for c in r] for r in rows], colWidths=[45, 200, 90, 45, 35, 65])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), .3, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey)]))
    el += [t, P("Risk score = (CVSS or severity base) x exposure x asset impact x confidence weight, capped at 10.", small), PageBreak()]

    el += [P("4. Detailed Vulnerability Findings", h1)]
    for f in findings:
        el += [P(f"{f['id']} - {f['title']}", h2),
               P(f"Asset: {f['asset']}:{f['port']} | Severity: {f['severity']} | CVSS: {f['cvss'] or 'n/a'} | Risk: {f['risk_score']}", body),
               P(f"CVE: {', '.join(f['cve']) or 'n/a'} | CWE: {f['cwe'] or 'n/a'} | Confidence: {f['confidence']} | Status: {f['status']} | Validation: {f['validation']}", body),
               P(f"Type: {f['kind']} | Reported by: {', '.join(f['tools'])}", body),
               P(f"Description: {f['description']}", body), P("Evidence:", body)]
        for e in f["evidence"]:
            el += [P(f"[{e['tool']}] {e['evidence']}  (ref: {e['raw_ref']}, {e['timestamp']})", small)]
        el += [Spacer(1, 8)]

    el += [P("5. Impact and Remediation", h1)]
    for f in findings:
        if f["severity"] == "info":
            continue
        el += [P(f"{f['id']}: {f['title']}", h2), P(remediation(f), body)]
    el += [P("References: OWASP Top 10, NIST SP 800-115, MITRE CVE/CWE, vendor advisories.", small)]

    el += [P("6. Assessment Limitations", h1),
           P("Results depend on tool coverage and (if imported) recorded outputs. Findings marked 'suspected' are not validated. "
             "No exploitation was performed by this agent. Scan failures are listed in the tool execution table.", body),
           P("Human approvals", h2)]
    if approvals:
        for a in approvals:
            el += [P(f"{a['ts']} | {a['finding']} | {a['decision']} by {a['by']} | outcome: {a['outcome']}", small)]
    else:
        el += [P("No active validation requested or approved.", body)]
    SimpleDocTemplate.build(doc, el)


def remediation(f):
    t = f["title"].lower()
    if "x-frame" in t or "clickjack" in t:
        return "Impact: UI redress/clickjacking. Fix: send 'X-Frame-Options: DENY' or CSP frame-ancestors."
    if "directory" in t:
        return "Impact: information disclosure. Fix: disable directory indexing (Options -Indexes)."
    if "sql" in t:
        return "Impact: data theft/modification. Fix: parameterised queries, input validation, least-privilege DB account."
    if "httponly" in t:
        return "Impact: session theft via XSS. Fix: set HttpOnly (and Secure) on session cookies."
    if "cve-" in t or f["cve"]:
        return f"Impact: known vulnerability ({', '.join(f['cve'])}). Fix: upgrade/patch the affected component and verify the version."
    if "legacy" in t or "risky" in t:
        return "Impact: cleartext/legacy service increases attack surface. Fix: disable or replace with encrypted alternative; restrict by firewall."
    if "outdated" in t:
        return "Impact: unpatched known issues likely. Fix: upgrade to a supported version."
    return "Review and apply vendor hardening guidance."
