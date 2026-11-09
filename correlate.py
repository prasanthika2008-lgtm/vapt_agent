"""Normalisation, correlation (dedupe w/o hiding evidence) and transparent risk scoring."""
import re
from adapters import SEV_ORDER

CATEGORY_RULES = [
    (r"x-frame-options|clickjacking", "missing-x-frame-options"),
    (r"x-content-type-options", "missing-x-content-type-options"),
    (r"directory (indexing|listing|browsing)", "directory-listing"),
    (r"httponly", "cookie-no-httponly"),
    (r"sql injection", "sql-injection"),
    (r"outdated", "outdated-component"),
]
SEV_BASE = {"info": 0.5, "low": 3.0, "medium": 5.5, "high": 8.0, "critical": 9.5}
CONF_W = {"low": 0.7, "medium": 0.85, "high": 1.0}


def category(title):
    t = title.lower()
    for rx, cat in CATEGORY_RULES:
        if re.search(rx, t):
            return cat
    return t


def score(f, exposure_mult, asset_impact):
    base = f["cvss"] if f.get("cvss") else SEV_BASE[f["severity"]]
    s = base * exposure_mult * asset_impact * CONF_W[f["confidence"]]
    return round(min(10.0, s), 1)


def correlate(raw, exposure="internal", asset_impact=1.0):
    exposure_mult = {"internal": 1.0, "internet-facing": 1.2}[exposure]
    groups = {}
    for f in raw:
        key = (f["asset"], f["port"], category(f["title"]))
        groups.setdefault(key, []).append(f)
    merged = []
    for (asset, port, cat), items in groups.items():
        items.sort(key=lambda x: -SEV_ORDER[x["severity"]])
        p = items[0]
        tools = sorted({i["source_tool"] for i in items})
        conf = p["confidence"]
        status = p["status"]
        if len(tools) >= 2:
            conf, status = "high", "confirmed"   # corroborated by independent tools
        m = {
            "asset": asset, "port": port, "title": p["title"], "description": p["description"],
            "severity": p["severity"], "cvss": p["cvss"],
            "cve": sorted({c for i in items for c in i["cve"]}),
            "cwe": next((i["cwe"] for i in items if i["cwe"]), None),
            "confidence": conf, "status": status, "tools": tools,
            "kind": "observed" if all(i["kind"] == "observed" for i in items) else "inferred (rule-based)",
            "evidence": [{"tool": i["source_tool"], "evidence": i["evidence"],
                          "raw_ref": i["raw_ref"], "timestamp": i["timestamp"]} for i in items],
            "validation": "not validated",
        }
        m["risk_score"] = score({**m, "confidence": conf}, exposure_mult, asset_impact)
        merged.append(m)
    merged.sort(key=lambda x: -x["risk_score"])
    for i, m in enumerate(merged, 1):
        m["id"] = f"VAPT-{i:03d}"
    return merged
