"""Tool adapters -> common finding schema.
Nmap : LIVE (needs nmap installed) or IMPORT (XML)
Nikto: LIVE (needs nikto installed) or IMPORT (JSON)
ZAP  : IMPORT only (JSON report)
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from audit import now

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

RISKY_PORTS = {
    21: "FTP (cleartext credentials)", 23: "Telnet (cleartext remote shell)",
    512: "rexec (legacy r-service)", 513: "rlogin (legacy r-service)", 514: "rsh (legacy r-service)",
    3306: "MySQL exposed to network", 5900: "VNC remote desktop exposed", 445: "SMB exposed",
}


def finding(tool, asset, port, title, desc, severity, evidence, raw_ref,
            cvss=None, cve=None, cwe=None, confidence="medium", status="suspected", kind="observed"):
    return {
        "source_tool": tool, "asset": asset, "port": port, "title": title, "description": desc,
        "severity": severity, "cvss": cvss, "cve": cve or [], "cwe": cwe,
        "evidence": evidence, "raw_ref": raw_ref, "timestamp": now(),
        "confidence": confidence, "status": status,
        "kind": kind,  # observed = seen in tool output, inferred = agent/rule inference
    }


# ---------------------------------------------------------------- NMAP
def parse_nmap_xml(path):
    root = ET.parse(path).getroot()
    services, findings = [], []
    for h in root.findall("host"):
        addr = h.find("address").get("addr")
        for p in h.findall("./ports/port"):
            if p.find("state").get("state") != "open":
                continue
            port, proto = int(p.get("portid")), p.get("protocol")
            sv = p.find("service")
            name = sv.get("name", "?") if sv is not None else "?"
            prod = (sv.get("product", "") if sv is not None else "")
            ver = (sv.get("version", "") if sv is not None else "")
            banner = f"{prod} {ver}".strip()
            services.append({"host": addr, "port": port, "proto": proto, "name": name, "banner": banner})
            ref = f"{os.path.basename(path)}#{addr}:{port}/{proto}"
            findings.append(finding("nmap", addr, port, f"Open port {port}/{proto} ({name})",
                                    f"Port {port}/{proto} is open running {name} {banner}.", "info",
                                    f"state=open service={name} banner='{banner}'", ref,
                                    confidence="high", status="confirmed"))
            if port in RISKY_PORTS:
                findings.append(finding("nmap", addr, port, f"Legacy/risky service exposed: {RISKY_PORTS[port]}",
                                        f"Rule-based inference: {RISKY_PORTS[port]} is reachable.", "medium",
                                        f"open port {port} service={name}", ref, confidence="medium",
                                        status="suspected", kind="inferred"))
            # CVEs only if a script (e.g. vulners) actually printed them -> never fabricated
            for sc in p.findall("script"):
                for cve, score in re.findall(r"(CVE-\d{4}-\d{4,7})\s+(\d+\.\d)", sc.get("output", "")):
                    sc_f = float(score)
                    sev = "critical" if sc_f >= 9 else "high" if sc_f >= 7 else "medium" if sc_f >= 4 else "low"
                    findings.append(finding("nmap", addr, port, f"{cve} reported for {name} {banner}",
                                            f"Nmap script '{sc.get('id')}' reported {cve}.", sev,
                                            sc.get("output", "")[:300], ref, cvss=sc_f, cve=[cve],
                                            confidence="medium", status="suspected"))
    return services, findings


def run_nmap(target, mode, sample_dir):
    if mode == "import":
        return parse_nmap_xml(os.path.join(sample_dir, "nmap_sample.xml")) + ("imported sample (synthetic)",)
    if not shutil.which("nmap"):
        raise RuntimeError("nmap not installed / not in PATH")
    host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    out = os.path.join(tempfile.gettempdir(), "nmap_live.xml")
    subprocess.run(["nmap", "-sV", "-T3", "--top-ports", "1000", "-oX", out, host],
                   check=True, timeout=600, capture_output=True)
    return parse_nmap_xml(out) + ("live scan",)


# ---------------------------------------------------------------- NIKTO
def _nikto_sev(msg):
    m = msg.lower()
    if any(k in m for k in ("outdated", "vulnerable", "remote code", "backdoor")):
        return "medium"
    if any(k in m for k in ("directory indexing", "directory listing", "phpinfo", "config")):
        return "medium"
    return "low"


def parse_nikto_json(path):
    data = json.load(open(path, encoding="utf-8"))
    blocks = data if isinstance(data, list) else [data]
    out = []
    for b in blocks:
        host, port = b.get("host") or b.get("ip"), int(b.get("port", 80))
        for v in b.get("vulnerabilities", []):
            msg = v.get("msg", "")
            out.append(finding("nikto", host, port, msg[:90], msg, _nikto_sev(msg),
                               f"{v.get('method','GET')} {v.get('url','/')} -> {msg}",
                               f"{os.path.basename(path)}#id={v.get('id')}", confidence="low", status="suspected"))
    return out


def run_nikto(target, port, mode, sample_dir):
    if mode == "import":
        return parse_nikto_json(os.path.join(sample_dir, "nikto_sample.json")), "imported sample (synthetic)"
    if not shutil.which("nikto"):
        raise RuntimeError("nikto not installed / not in PATH")
    host = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    out = os.path.join(tempfile.gettempdir(), "nikto_live.json")
    if os.path.exists(out):
        os.remove(out)
    subprocess.run(["nikto", "-h", host, "-p", str(port), "-Format", "json", "-o", out, "-nointeractive"],
                   check=False, timeout=900, capture_output=True)
    return parse_nikto_json(out), "live scan"


# ---------------------------------------------------------------- ZAP (import only)
ZAP_SEV = {"0": "info", "1": "low", "2": "medium", "3": "high"}
ZAP_CONF = {"0": "low", "1": "low", "2": "medium", "3": "high"}


def parse_zap_json(path):
    data = json.load(open(path, encoding="utf-8"))
    out = []
    for site in data.get("site", []):
        m = re.match(r"https?://([^:/]+):?(\d+)?", site.get("@name", ""))
        host, port = (m.group(1), int(m.group(2) or 80)) if m else ("?", 80)
        for a in site.get("alerts", []):
            inst = a.get("instances", [{}])[0]
            cwe = a.get("cweid")
            out.append(finding("zap", host, port, a.get("alert"), re.sub("<[^>]+>", "", a.get("desc", "")),
                               ZAP_SEV.get(str(a.get("riskcode")), "info"),
                               f"{inst.get('method','')} {inst.get('uri','')} param={inst.get('param','')} "
                               f"evidence={inst.get('evidence','')}",
                               f"{os.path.basename(path)}#pluginid={a.get('pluginid')}",
                               cwe=f"CWE-{cwe}" if cwe and cwe != "-1" else None,
                               confidence=ZAP_CONF.get(str(a.get("confidence")), "medium"), status="suspected"))
    return out


def run_zap(target, port, mode, sample_dir):
    # Honest: live ZAP is NOT implemented here. Import of a ZAP JSON report only.
    return parse_zap_json(os.path.join(sample_dir, "zap_sample.json")), "imported sample (synthetic)"


INTEGRATIONS = [
    ("Nmap", "Live + Import", "Requires nmap binary for live mode"),
    ("Nikto", "Live + Import", "Requires nikto binary for live mode"),
    ("OWASP ZAP", "Import-only", "ZAP JSON report import; live API not implemented"),
    ("Nessus", "Unsupported", "Commercial licence required; not integrated"),
    ("OpenVAS / Greenbone", "Planned", "GMP API adapter planned"),
    ("Burp Suite", "Unsupported", "Commercial; analyst-assisted only, not integrated"),
    ("Metasploit", "Planned (approval gate only)", "Approval workflow exists; NO exploit is executed"),
]
