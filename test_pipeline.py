from scope import Scope, extract_target
from pipeline import execute_step
from planner import make_plan, llm_summary
from correlate import correlate
from report import build_pdf
sc = Scope(["192.168.56.0/24"], ["192.168.56.1"])
print(sc.check("192.168.56.101"), sc.check("8.8.8.8"), sc.check("192.168.56.1"))
runs, raw, svc, done = [], [], [], set()
plan, src = make_plan(1, "scan", [], done); print(plan, src)
for s in plan:
    a, b = execute_step(s, "192.168.56.101", "import", "sample_data", sc, runs); svc += a; raw += b; done.add(s["tool"])
plan, src = make_plan(2, "scan", svc, done); print(plan, src)
for s in plan:
    a, b = execute_step(s, "192.168.56.101", "import", "sample_data", sc, runs); svc += a; raw += b; done.add(s["tool"])
f = correlate(raw)
for x in f: print(x["id"], x["title"][:45], x["severity"], x["risk_score"], x["status"], x["tools"])
build_pdf("vapt_report.pdf", sc, f, runs, [], llm_summary(f), "test", "internal")
print("pdf ok", len(raw), "raw ->", len(f))
