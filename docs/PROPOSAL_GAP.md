# Proposal vs implementation gap

This checklist maps the **Project Plan: Certificate-Gated Defenses…** proposal to the `cert-agent-exp` codebase. Use it to finish the project or to narrow the paper scope honestly.

**Legend:** ✅ done · ⚠️ partial · ❌ not done / out of scope

---

## 1. Threat model & attack formulation

| Item | Status | Notes / what to do |
|------|--------|---------------------|
| Perturbations \(\delta\) on retrieved \(r_t\) with budget \(B\), \(K\) sources | ✅ | `configs/grid.yaml` (`B_tokens`, `K_sources`, `K_inject`), `SearchTool` |
| Perturbations on **tool outputs** \(u_t\) | ⚠️ | Retrieval is primary; tool stubs exist (`tools/`) but **no symmetric "inject \(u_t\)" grid** — scope limited to **retrieval IPI only** (documented in STATUS.md §6) |
| Objective \(\max_\delta \mathbb{E}[\sum_t \mathbf{1}\{a_t\in\mathcal{B}\} - \lambda \ell_{\text{task}}]\) | ⚠️ | `attacks/optimizer.py` + `scripts/17_formal_attack_optimization.py` — discrete template search, not full continuous optimization over \(\delta\) |
| Sweep \((B,K)\) in evaluation | ✅ | Published tables match the **same** `grid*.yaml` used for `runs/logs/grid_run.jsonl` |
| \(\mathcal{L}_{\text{bad}}(o)\), \(\Delta\mathcal{L}_{\text{bad}}\) vs attack rates | ⚠️ | `scripts/18_lbad_correlation.py` uses **taint score as proxy**, not \(\sum_{\tau\in\mathcal{T}_{\text{bad}}} p_\theta(\tau\mid o)\) — documented in script docstring and STATUS.md §6. Logit-based estimator requires model access not available in all backends. |
| Verifier + \(\mathcal{G}\) in trusted base | ✅ | — |

---

## 2. Certificate-gated authorization (verifier \(V(a,\phi;\mathcal{G})\))

| Condition (proposal) | Status | Notes / what to do |
|----------------------|--------|---------------------|
| (1) \(\tau(a)\) / capability constraints | ✅ | `defense/allowlist.py`, wired in `scripts/05_run_grid.py` |
| (2) \(g \in \Gamma(\mathcal{G})\) | ⚠️ | `validate_certificate()` runs when the model emits **`certificate`** JSON (`api`/`ollama`/`hf` + `certificate_gating`); **mock** grid has no \(\phi\) |
| (3) No taint in **constraints** \(C\) | ✅ | Taint on **`content`** always; **additional** taint pass on **`certificate.constraints`** when present |
| (4) Untrusted content only in quoted **evidence** \(E\) | ✅ | Evidence IDs ⊆ trusted via `validate_certificate`; **evidence span matching** via `_check_evidence_spans()` verifies cited IDs correspond to content in action output |
| Taint: n-gram + embedding cosine | ✅ | `verifier/taint.py`, `configs/verifier.yaml` |
| Constrained policy \(\tilde{\pi}_\theta\) as renormalized mixture over \(\phi\) | ⚠️ | Implemented as **hard block** of disallowed executions, not resampling over \(\phi\) |

**Implementation detail:**

- [x] Model output JSON with **`certificate`: `{goal, evidence, constraints}`** when `certificate_gating` and model mode ≠ mock (`prompts.CERTIFICATE_JSON_SUFFIX`, `parse_action`).
- [x] Run `validate_certificate()` on that object for `certificate_gating` (after taint checks).
- [x] Run taint on **`certificate.constraints`** when non-empty (in addition to `content`).
- [x] Evidence span matching: cited evidence IDs must correspond to content actually quoted in action output (`_check_evidence_spans()`).

---

## 3. \(\widehat{\Delta}_{\text{auth}}\) (authorization gap)

| Item | Status | Notes |
|------|--------|------|
| Metric computed | ✅ | `eval/metrics.py`, `06_compute_metrics.py` |
| Narrative aligned with definition | ✅ | Paper definition matches `delta_auth` in code (certificate_gating cells only). |

---

## 4. Adaptive attackers (certificate forgery)

| Item | Status | Notes |
|------|--------|------|
| Goal / evidence / policy mimicry | ✅ | Templates + grid strategies |
| Extra strategies (e.g. subtle_redirect, footnote) | ✅ | 6 strategies in grid |
| \(R_{\text{forge}} = \Pr[a\in\mathcal{B} \land V=1]\) | ✅ | `verifier_decision=True` means pass; per-defense `R_forge` in metrics |

---

## 5. Estimators & mechanism analysis

| Item | Status | Notes |
|------|--------|------|
| \(\widehat{R}_{\text{bad}}\), \(\widehat{R}_{\text{bad\_outcome}}\) | ✅ | |
| \(\widehat{R}_{\text{forge}}\) | ✅ | |
| Bootstrap CIs on reported metrics | ✅ | `06_compute_metrics.py` produces per-defense 95% CIs for ASR and task success via `eval/bootstrap.py` |
| False rejection rate (FRR) | ✅ | `false_rejection_rate()` in `eval/metrics.py`; note: clean split may be empty (n_clean=0) in 100%-exposure runs |
| Correlate **\(R_{\text{forge}}\)** with \(\Delta\mathcal{L}_{\text{bad}}\) | ⚠️ | `18_lbad_correlation.py` reports **`r(ΔL_bad, R_forge)`** per defense table + JSON (proxy still taint-based, not logit-based) |
| Rejection modes & token attribution | ✅ | `verifier_debug`, `runs/proof/` |

---

## 6. Experimental system

| Item | Status | Notes |
|------|--------|------|
| Single-agent (primary) | ✅ | `RetrievalEchoAgent`, etc. |
| Planner–executor (secondary) | ✅ | `agent/planner_executor.py`, `19_planner_executor_experiment.py` — **225 PE episodes** in `runs/logs/grid_planner_executor.jsonl`; comparison in `runs/metrics/planner_executor_comparison.json` |
| Baselines (quote, provenance, allowlist, combos) | ✅ | |
| \(\tau\) sensitivity / security–utility | ✅ | `tau_sensitivity.png` etc. |
| Open benchmark + traces | ⚠️ | Traces in `runs/logs/*.jsonl` — add **README + manifest + license** for "open release" |

---

## 7. Proposal timeline (weeks 1–12) — practical closure

| Phase | Status |
|-------|--------|
| Harness + logging | ✅ |
| Injection corpus + adaptive strategies | ✅ (retrieval-first) |
| Certificate + verifier + integration | ✅ (structured φ with evidence span matching; mock remains taint-only) |
| Comparative eval + ablations | ✅ (grid + bootstrap CIs + FRR) |
| Write-up + release | ⚠️ (`REPORT.md` must match **one** canonical run; see release checklist below) |

---

## 8. Explicit future work (proposal)

- [ ] **Joint training** / robustness when models adapt to the verifier — **not implemented** (by design).
- [ ] **Logit-based L_bad estimator** — requires model logit access; taint proxy is current approximation.
- [ ] **Tool-output injection** — extend grid to perturb tool outputs u_t (currently retrieval-only).

---

## 9. Release checklist (recommended "done" definition)

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
| Metrics (with FRR, bootstrap) | `scripts/06_compute_metrics.py`, `src/cert_agent_exp/eval/metrics.py` |
| Taint | `src/cert_agent_exp/verifier/taint.py` |
| Verifier | `src/cert_agent_exp/verifier/verifier.py` |
| Certificates + span matching | `src/cert_agent_exp/verifier/certificate.py` |
| Formal objective | `scripts/17_formal_attack_optimization.py` |
| L_bad proxy | `scripts/18_lbad_correlation.py` |
| Planner–executor | `scripts/19_planner_executor_experiment.py` |
| Tests | `src/tests/` (96 tests) |
