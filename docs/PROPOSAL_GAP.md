# Proposal vs implementation gap

This checklist maps the **Project Plan: Certificate-Gated Defenses…** proposal to the `cert-agent-exp` codebase. Use it to finish the project or to narrow the paper scope honestly.

**Legend:** ✅ done · ⚠️ partial · ❌ not done / out of scope

---

## 1. Threat model & attack formulation

| Item | Status | Notes / what to do |
|------|--------|---------------------|
| Perturbations \(\delta\) on retrieved \(r_t\) with budget \(B\), \(K\) sources | ✅ | `configs/grid.yaml` (`B_tokens`, `K_sources`, `K_inject`), `SearchTool` |
| Perturbations on **tool outputs** \(u_t\) | ⚠️ | Retrieval is primary; tool stubs exist (`tools/`) but **no symmetric “inject \(u_t\)” grid** — either implement poisoning of tool returns in `05_run_grid.py` **or** state scope = **retrieval IPI only** |
| Objective \(\max_\delta \mathbb{E}[\sum_t \mathbf{1}\{a_t\in\mathcal{B}\} - \lambda \ell_{\text{task}}]\) | ⚠️ | `attacks/optimizer.py` + `scripts/17_formal_attack_optimization.py` — discrete search, not full optimization over \(\delta\) |
| Sweep \((B,K)\) in evaluation | ✅ | Ensure **published tables** match the **same** `grid*.yaml` used for `runs/logs/grid_run.jsonl` |
| \(\mathcal{L}_{\text{bad}}(o)\), \(\Delta\mathcal{L}_{\text{bad}}\)** vs attack rates | ⚠️ | `scripts/18_lbad_correlation.py` uses **taint as proxy**, not \(\sum_{\tau\in\mathcal{T}_{\text{bad}}} p_\theta(\tau\mid o)\) — **rename in paper** or add logit-based estimator |
| Verifier + \(\mathcal{G}\) in trusted base | ✅ | — |

---

## 2. Certificate-gated authorization (verifier \(V(a,\phi;\mathcal{G})\))

| Condition (proposal) | Status | Notes / what to do |
|----------------------|--------|---------------------|
| (1) \(\tau(a)\) / capability constraints | ✅ | `defense/allowlist.py`, wired in `scripts/05_run_grid.py` |
| (2) \(g \in \Gamma(\mathcal{G})\) | ⚠️ | `validate_certificate()` runs when the model emits **`certificate`** JSON (`api`/`ollama` + `certificate_gating`); **mock** grid has no \(\phi\) |
| (3) No taint in **constraints** \(C\) | ⚠️ | Taint on **`content`** always; **additional** taint pass on **`certificate.constraints`** when present |
| (4) Untrusted content only in quoted **evidence** \(E\) | ⚠️ | **Evidence IDs ⊆ trusted** (exposed \ injected) via `validate_certificate`; not full quote-span matching |
| Taint: n-gram + embedding cosine | ✅ | `verifier/taint.py`, `configs/verifier.yaml` |
| Constrained policy \(\tilde{\pi}_\theta\) as renormalized mixture over \(\phi\) | ⚠️ | Implemented as **hard block** of disallowed executions, not resampling over \(\phi\) |

**To match the proposal more literally (optional backlog):**

- [x] Model output JSON with **`certificate`: `{goal, evidence, constraints}`** when `certificate_gating` and model mode ≠ mock (`prompts.CERTIFICATE_JSON_SUFFIX`, `parse_action`).
- [x] Run `validate_certificate()` on that object for `certificate_gating` (after taint checks).
- [x] Run taint on **`certificate.constraints`** when non-empty (in addition to `content`).
- [ ] Add rule: evidence chunk IDs match quoting/provenance spans (not just ID ⊆ trusted).

---

## 3. \(\widehat{\Delta}_{\text{auth}}\) (authorization gap)

| Item | Status | Notes |
|------|--------|------|
| Metric computed | ✅ | `eval/metrics.py`, `06_compute_metrics.py` |
| Narrative aligned with definition | ⚠️ | Confirm paper definition matches `delta_auth` in code (certificate_gating cells only). |

---

## 4. Adaptive attackers (certificate forgery)

| Item | Status | Notes |
|------|--------|------|
| Goal / evidence / policy mimicry | ✅ | Templates + grid strategies |
| Extra strategies (e.g. subtle_redirect, footnote) | ✅ | Either add to proposal text or restrict experiments to **three** named strategies |
| \(R_{\text{forge}} = \Pr[a\in\mathcal{B} \land V=1]\) | ⚠️ | `verifier_decision=True` means pass; `18_lbad_correlation.py` now reports **per-defense `R_forge`** |

---

## 5. Estimators & mechanism analysis

| Item | Status | Notes |
|------|--------|------|
| \(\widehat{R}_{\text{bad}}\), \(\widehat{R}_{\text{bad\_outcome}}\) | ✅ | |
| \(\widehat{R}_{\text{forge}}\) | ✅ | |
| Bootstrap CIs on reported metrics | ⚠️ | Confirm figures use `eval/bootstrap.py` on **canonical** `grid_run.jsonl` |
| Correlate **\(R_{\text{forge}}\)** with \(\Delta\mathcal{L}_{\text{bad}}\) | ⚠️ | `18_lbad_correlation.py` reports **`r(ΔL_bad, R_forge)`** per defense table + JSON (proxy still taint-based) |
| Rejection modes & token attribution | ⚠️ | `verifier_debug`, `runs/proof/` — refresh from canonical run |

---

## 6. Experimental system

| Item | Status | Notes |
|------|--------|------|
| Single-agent (primary) | ✅ | `RetrievalEchoAgent`, etc. |
| Planner–executor (secondary) | ⚠️ | `agent/planner_executor.py`, `19_planner_executor_experiment.py` — need **`runs/logs/grid_planner_executor.jsonl`** from a real PE grid (no duplicate-ReAct fallback) |
| Baselines (quote, provenance, allowlist, combos) | ✅ | |
| \(\tau\) sensitivity / security–utility | ✅ | `tau_sensitivity.png` etc. — regenerate from frozen config |
| Open benchmark + traces | ⚠️ | Traces in `runs/logs/*.jsonl` — add **README + manifest + license** for “open release” |

---

## 7. Proposal timeline (weeks 1–12) — practical closure

| Phase | Status |
|-------|--------|
| Harness + logging | ✅ |
| Injection corpus + adaptive strategies | ✅ (retrieval-first) |
| Certificate + verifier + integration | ⚠️ (structured \(\phi\) end-to-end for **live** models; mock remains taint-only) |
| Comparative eval + ablations | ⚠️ (scripts ✅ — need **one frozen run** covering all) |
| Write-up + release | ⚠️ (`REPORT.md` / LaTeX / `results (*)` must match **one** run) |

---

## 8. Explicit future work (proposal)

- [ ] **Joint training** / robustness when models adapt to the verifier — **not implemented** (by design).

---

## 9. Release checklist (recommended “done” definition)

- [ ] Pick **one** canonical commit + `grid*.yaml` + `grid_run.jsonl` (note `n`, model, seeds).
- [ ] Regenerate `06` → figures → `09_proof` → `16–19` from that log.
- [ ] Update `REPORT.md` and any LaTeX tables to **only** that run.
- [ ] Remove or relabel stale exports (e.g. broken metrics in some `results (*)` folders).
- [ ] Optional: add `docs/BENCHMARK.md` with SHA256 of task file + injection manifest + index.

---

## Quick reference: main code paths

| Topic | Path |
|-------|------|
| Grid / defenses | `scripts/05_run_grid.py` |
| Metrics | `scripts/06_compute_metrics.py`, `src/cert_agent_exp/eval/metrics.py` |
| Taint | `src/cert_agent_exp/verifier/taint.py` |
| Verifier | `src/cert_agent_exp/verifier/verifier.py` |
| Certificates | `src/cert_agent_exp/verifier/certificate.py` |
| Formal objective | `scripts/17_formal_attack_optimization.py` |
| L_bad proxy | `scripts/18_lbad_correlation.py` |
| Planner–executor | `scripts/19_planner_executor_experiment.py` |
