"""Orchestration used by both the UI and the CLI test."""
import traceback
from adapters import run_nmap, run_nikto, run_zap
from scope import Scope
from audit import log, now


def execute_step(step, target, mode, sample_dir, scope, runs):
    tool, port = step["tool"], step.get("port")
    rec = {"tool": tool, "port": port, "mode": mode, "started": now(), "status": "running", "note": ""}
    runs.append(rec)
    ok, why = scope.check(target)
    if not ok:                                  # scope re-checked right before execution
        rec.update(status="BLOCKED", note=why, ended=now())
        log("agent", "blocked_out_of_scope", {"tool": tool, "target": target, "reason": why})
        return [], []
    try:
        log("agent", "tool_start", {"tool": tool, "target": target, "port": port, "mode": mode})
        services, findings = [], []
        if tool == "nmap":
            services, findings, note = run_nmap(target, mode, "sample_data")
        elif tool == "nikto":
            findings, note = run_nikto(target, port, mode, "sample_data")
        elif tool == "zap":
            findings, note = run_zap(target, port, "import", "sample_data")
            note = note + " (ZAP is import-only)"
        else:
            note = "nothing to run"
        # drop any finding whose asset is outside scope (imported files too)
        kept = [f for f in findings if scope.check(f["asset"])[0]]
        dropped = len(findings) - len(kept)
        rec.update(status="success", note=f"{note}; {len(kept)} findings" + (f"; {dropped} dropped (out of scope)" if dropped else ""), ended=now())
        log("agent", "tool_done", {"tool": tool, "findings": len(kept)})
        return services, kept
    except Exception as e:
        rec.update(status="FAILED", note=str(e)[:200], ended=now())
        log("agent", "tool_failed", {"tool": tool, "error": str(e)[:200]})
        return [], []
