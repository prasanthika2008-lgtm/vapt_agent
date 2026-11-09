import json
import os
import re
import streamlit as st
import pandas as pd
from scope import Scope, extract_target
from audit import log, now, read_all
from planner import make_plan, llm_summary
from pipeline import execute_step
from correlate import correlate
from report import build_pdf
from adapters import INTEGRATIONS

st.set_page_config(page_title="AI VAPT Agent", layout="wide")
S = st.session_state
for k, v in dict(stage=0, request="", target=None, plan=[], planner="", runs=[], services=[], raw=[],
                 findings=[], approvals=[], chat=[], done=set()).items():
    S.setdefault(k, v)

# ---------------- sidebar: scope + settings
with st.sidebar:
    st.header("Authorised scope (lab only)")
    targets = st.text_area("Targets (IP / CIDR / host, one per line)", "192.168.56.0/24").splitlines()
    excl = st.text_area("Exclusions", "192.168.56.1").splitlines()
    mode = st.radio("Tool mode", ["import", "live"], help="import = recorded SYNTHETIC sample; live = needs nmap/nikto installed")
    exposure = st.selectbox("Exposure assumption", ["internal", "internet-facing"])
    impact = st.slider("Asset impact multiplier", 0.5, 1.5, 1.0, 0.1)
    st.caption("LLM: " + ("Claude API key found" if os.environ.get("ANTHROPIC_API_KEY") else "no API key -> rule-based planner"))
    if st.button("Reset assessment"):
        for k in list(S.keys()):
            del S[k]
        st.rerun()
scope = Scope(targets, excl)

st.title("AI-Powered Unified VAPT Agent")
tab1, tab2, tab3, tab4 = st.tabs(["Assessment", "Findings", "Audit trail", "Integration matrix"])

with tab1:
    for role, msg in S.chat:
        st.chat_message(role).write(msg)
    req = st.chat_input("e.g. Run a full assessment of 192.168.56.101")
    if req and S.stage == 0:
        S.chat.append(("user", req))
        tgt = extract_target(req)
        if not tgt:
            S.chat.append(("assistant", "Please include an authorised target (IP/host) in your request."))
        else:
            ok, why = scope.check(tgt)
            log("analyst", "request", {"text": req, "target": tgt, "scope_ok": ok, "reason": why})
            if not ok:
                S.chat.append(("assistant", f"REJECTED: {why}"))
            else:
                S.request, S.target = req, tgt
                S.plan, S.planner = make_plan(1, req, [], S.done)
                S.stage = 1
                S.chat.append(("assistant", f"Scope OK: {why} Plan ready ({S.planner}). Please review and approve below."))
        st.rerun()

    if S.stage in (1, 2):
        st.subheader(f"Stage {S.stage} plan - source: {S.planner}")
        st.table(pd.DataFrame(S.plan))
        if S.plan and S.plan[0]["tool"] != "none":
            if st.button(f"Approve & run stage {S.stage}"):
                log("analyst", "plan_approved", {"stage": S.stage, "plan": S.plan})
                for step in S.plan:
                    sv, fs = execute_step(step, S.target, mode, "sample_data", scope, S.runs)
                    S.services += sv
                    S.raw += fs
                    S.done.add(step["tool"])
                if S.stage == 1:
                    S.plan, S.planner = make_plan(2, S.request, S.services, S.done)
                    S.stage = 2
                else:
                    S.stage = 3
                if S.stage == 3 or (S.plan and S.plan[0]["tool"] == "none"):
                    S.stage = 3
                if S.stage == 3:
                    S.findings = correlate(S.raw, exposure, impact)
                st.rerun()
        else:
            st.info("Nothing more to run. " + (S.plan[0]["rationale"] if S.plan else ""))
            if st.button("Finish & correlate"):
                S.findings = correlate(S.raw, exposure, impact)
                S.stage = 3
                st.rerun()
    if S.runs:
        st.subheader("Tool execution status")
        st.dataframe(pd.DataFrame(S.runs), use_container_width=True)

with tab2:
    if not S.findings:
        st.info("Run the assessment first.")
    else:
        df = pd.DataFrame([{k: f[k] for k in ("id", "title", "asset", "port", "severity", "risk_score", "confidence", "status", "kind", "tools", "validation")} for f in S.findings])
        st.dataframe(df, use_container_width=True)
        st.caption("kind: 'observed' = directly in tool output; 'inferred' = rule/AI inference.")
        for f in S.findings:
            with st.expander(f"{f['id']} {f['title']} ({f['severity']}, risk {f['risk_score']})"):
                st.write(f["description"])
                st.write("CVE:", f["cve"] or "n/a", "| CWE:", f["cwe"] or "n/a", "| CVSS:", f["cvss"] or "n/a")
                st.json(f["evidence"])
        st.subheader("Human-in-the-loop: active validation (Metasploit gate)")
        st.warning("Lab only. This prototype records the approval decision; it does NOT run any exploit.")
        cand = [f["id"] for f in S.findings if f["severity"] in ("high", "critical")]
        if cand:
            fid = st.selectbox("Finding to validate", cand)
            who = st.text_input("Analyst name", "analyst")
            c1, c2 = st.columns(2)
            if c1.button("Approve active validation"):
                a = dict(ts=now(), finding=fid, decision="APPROVED", by=who,
                         outcome="Approved and recorded. Metasploit adapter not implemented - no exploit executed.")
                S.approvals.append(a); log(who, "validation_approved", a)
                next(f for f in S.findings if f["id"] == fid)["validation"] = "approved, not executed (adapter planned)"
            if c2.button("Deny"):
                a = dict(ts=now(), finding=fid, decision="DENIED", by=who, outcome="No action taken.")
                S.approvals.append(a); log(who, "validation_denied", a)
        st.table(pd.DataFrame(S.approvals)) if S.approvals else None

        st.subheader("Report")
        if st.button("Generate PDF report"):
            summary = llm_summary(S.findings)
            build_pdf("vapt_report.pdf", scope, S.findings, S.runs, S.approvals, summary, S.request, exposure)
            log("agent", "report_generated", {"findings": len(S.findings)})
        if os.path.exists("vapt_report.pdf"):
            st.download_button("Download vapt_report.pdf", open("vapt_report.pdf", "rb").read(), "vapt_report.pdf")

with tab3:
    st.dataframe(pd.DataFrame(read_all()), use_container_width=True)

with tab4:
    st.table(pd.DataFrame(INTEGRATIONS, columns=["Tool", "Status", "Notes"]))
