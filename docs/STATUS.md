# What Is Already Done vs. Full Execution Plan

This maps the current repo to the complete, defensible project plan (threat model → benchmark → defenses → certificate gating → metrics → figures → writeup).

---

## 0) Project goal (claim)

**Claim:** Untrusted retrieved/tool content can hijack an LLM agent's control flow, and certificate-gated authorization can reduce unsafe actions beyond baselines (quoting, provenance, allowlists).

**Status:** ✅ Fully implemented and evaluated.  The claim is supported by implemented defenses, metrics, figures, and proof artifacts.

---

## 1) What "complete" means — checklist

| Item | Status |
|------|--------|
| **A. Benchmark** | |
| Reproducible corpus/tasks/injections | ✅ Pipeline: `01_prepare_data` → `02_build_corpus` → `04_build_index`; optional `03_inject_corpus` (legacy on-disk inject) |
| Fixed train/eval slice | ✅ Config-driven; dataset/corpus hashes in manifests and optional `benchmark_*` fields in logs |
| Deterministic manifests and hashes | ✅ `corpus/manifest.json`, `integrity.sha256`, `indexes/manifest.json`, `injection_manifest.json` |
| **B. Threat model** | |
| Trusted vs untrusted channels | ✅ `trusted_inputs` / `untrusted_inputs` via `exposed_sources`, `injected_sources`, `G_hash` in every run |
| Structured action space | ✅ `action_schema.py`: `respond_answer`, `save_notes`, `request_more_info` with JSON parser |
| Explicit unauthorized action set | ✅ `is_bad_action(run)` in `eval/metrics.py` with uptake detection |
| **C. Baselines** | |
| No defense | ✅ Grid has defense `"none"` |
| Quoting / provenance / allowlist / combos / cert | ✅ All 9 defenses implemented and wired in `05_run_grid.py` |
| **D. Live defense** | |
| Model emits action + certificate | ✅ `action_schema.py` parses certificate from model output |
| Deterministic verifier checks authorization | ✅ `verifier.verify_with_debug()` — taint + certificate validation (goal/evidence/constraint checks) |
| Evidence span matching | ✅ `_check_evidence_spans()` verifies cited evidence IDs correspond to content in action output |
| Rejected actions blocked | ✅ Verifier called in grid loop; rejected actions set to `{"type": "blocked"}` |
| **E. Evaluation** | |
| Attack success / task success / false reject / etc. | ✅ R_bad, R_bad_outcome, R_forge, Delta_auth, success_rate, FRR, bootstrap CIs |
| Security–utility frontier | ✅ Threshold sensitivity (tau sweep), security-utility tradeoff figures |
| False rejection rate (FRR) | ✅ `false_rejection_rate()` in `eval/metrics.py`; computed per-defense in `06_compute_metrics.py` |
| Bootstrap confidence intervals | ✅ Per-defense 95% CIs for ASR and task success in `06_compute_metrics.py` |
| **F. Final artifacts** | |
| Main results figure, mechanism figure, ablation table | ✅ 17+ figures, proof package, extended results |

---

## 2) Build order — completed

| Phase | Status |
|-------|--------|
| 1. Lock the benchmark | ✅ Manifests, hashes; use a pinned `configs/grid.yaml` + data snapshot for publication |
| 2. Unauthorized actions machine-checkable | ✅ `is_bad_action`, uptake detection |
| 3. Structured-action agent | ✅ JSON action schema with parser, certificate field support |
| 4. Baseline ladder | ✅ 9 defenses implemented and producing differentiated results |
| 5. Certificate gating | ✅ Taint detection + certificate validation + evidence span matching + verifier in run loop |
| 6. Core experiments | ✅ Grid runs with all defenses, metrics, figures |
| 7. Ablations | ✅ Mechanism ablation, threshold sensitivity, budget experiments |
| 8. Paper/report | ✅ REPORT.md, 17+ figures, proof package |

---

## 3) Scripts and modules — status

| Script / module | Status |
|-----------------|--------|
| **01_prepare_data** | ✅ HotpotQA tasks JSONL (HF or `--fallback` synthetic) |
| **02_build_corpus** | ✅ Chunks from task contexts |
| **03_inject_corpus** | ✅ Optional legacy injected corpus; grid uses retrieval-time injection |
| **04_build_index** | ✅ FAISS FlatIP |
| **05_run_grid** | ✅ Full defense instantiation, verifier blocking, counterfactuals, exposure diagnostics, evidence span matching |
| **06_compute_metrics** | ✅ R_bad, R_forge, Delta_auth, success_rate, FRR, bootstrap CIs, by-defense and by-strategy |
| **07/07b** | ✅ Performance plots with CIs, exposure/injection, security comparison |
| **08_show_defense_internals** | ✅ |
| **09_proof_package** | ✅ Audit cards, paired diffs, rejection analysis, taint attribution, counterfactuals |
| **10_live_demo** | ✅ |
| **11_generate_paper_figures** | ✅ Security-utility tradeoff, threshold sensitivity, defense comparison bar, architecture |
| **12_attack_trace_figure** | ✅ Annotated attack trace |
| **13_attack_optimization** | ✅ Payload × strategy × budget grid search |
| **14_adaptive_attack_analysis** | ✅ Goal/evidence/policy laundering against certificate validation |
| **15_attack_figures** | ✅ Strategy scores, payload scores, adaptive detection, defense-in-depth |
| **16_extended_results** | ✅ Attack optimization, cert verification stats, heatmap, ablation, budget experiment |
| **verifier/** | ✅ `certificate.py` (make + validate + evidence span matching), `taint.py` (n-gram overlap + embedding), `verifier.py` (verify_with_debug) |
| **defense/** | ✅ `allowlist.py`, `taskshield.py`, `judge.py`, `intentguard.py`, `prompt.py` |
| **eval/** | ✅ `metrics.py` (is_bad_action, FRR, all metrics), `bootstrap.py` (95% CIs), `plots.py` |
| **agent/** | ✅ `action_schema.py` (with certificate parsing), `runner.py`, `retrieval_echo_agent.py`, `react_agent.py` |
| **corpus/** | ✅ `embedder.py`, `index_faiss.py`, `retrieval.py`, `chunking.py` |
| **attacks/** | ✅ `adaptive.py`, `budgets.py`, `inject.py`, `templates.py`, `optimizer.py` (proposal-aligned objective) |
| **models/** | ✅ `backend.py` (mock, API, Ollama) |
| **agent/planner_executor** | ✅ Two-phase agent with plan + execute steps (secondary experiment) |
| **17_formal_attack_optimization** | ✅ Implements max_δ E[1{a∈B}] - λ·ℓ_task with plausibility constraint |
| **18_lbad_correlation** | ✅ L_bad proxy (taint) vs ASR and per-defense **R_forge**; see `runs/lbad_correlation.json`. This is intentionally documented as a proxy implementation (not logit-based L_bad). |
| **19_planner_executor_experiment** | ✅ Planner-executor vs ReAct comparison (225 PE episodes, 810 ReAct episodes) |
| **tests/** | ✅ 96 tests passing (metrics, verifier, certificate validation, bootstrap, action schema, defenses, injection budget, retrieval) |

---

## 4) Output artifacts

| Artifact | Location |
|----------|----------|
| Run logs | `runs/logs/grid_run.jsonl` (810 episodes, 9 defenses × 6 strategies) |
| Planner-executor logs | `runs/logs/grid_planner_executor.jsonl` (225 episodes, secondary experiment) |
| Metrics | `runs/metrics/by_defense.jsonl`, `runs/metrics/by_defense_strategy.jsonl` (with bootstrap CIs and FRR) |
| Formal attack optimization | `runs/formal_attack_optimization.json` (discrete search over payload × strategy × budget) |
| L_bad correlation | `runs/lbad_correlation.json` (taint proxy; correlations depend on run; includes per-defense R_forge) |
| PE comparison | `runs/metrics/planner_executor_comparison.json` (225 PE episodes vs 810 ReAct) |
| Figures | `runs/figures/` (25+ PNG files: tradeoff, comparison, architecture, attacks, L_bad, planner-executor, etc.) |
| Proof package | `runs/proof/` (audit cards, paired diffs, ablation, taint attribution, counterfactuals) |
| Extended results | `runs/extended_results.json`, `runs/adaptive_attack_results.json`, `runs/attack_optimization.json` |
| Report | `REPORT.md` |

---

## 5) Proposal alignment

| Proposal element | Implementation |
|-----------------|----------------|
| max_δ E[1{a∈B}] - λ·ℓ_task objective | ✅ `attacks/optimizer.py` + `scripts/17_formal_attack_optimization.py` |
| Plausibility constraint plausibility(δ) ≥ τ | ✅ `plausibility_score()` with red-flag + overlap heuristic |
| (B,K) budget sweep | ✅ Grid sweeps B∈{50,150,300}, K∈{1,2} across 6 strategies |
| L_bad / ΔL_bad correlation | ✅ `scripts/18_lbad_correlation.py` — implemented as an explicit taint-based proxy (documented as proxy, not theorem-level logit estimator). |
| Adaptive strategies (goal/evidence/policy laundering) | ✅ All 6 strategies in grid |
| Planner-executor architecture | ✅ `agent/planner_executor.py` + secondary experiment (225 episodes) |
| Certificate-gated authorization | ✅ Verifier with taint + certificate validation + evidence span matching |
| Cosine similarity embedding augmentation | ✅ `taint.py` — `compute_embedding_similarity()` with `all-MiniLM-L6-v2`; τ_embed = 0.82 |
| Taint reason attribution (ngram / embedding / both) | ✅ `taint_detail()` returns `taint_reason` field |
| Evidence span verification | ✅ `_check_evidence_spans()` — confirms cited evidence IDs match quoted content in action output |
| False rejection rate (FRR) | ✅ `false_rejection_rate()` — computed per-defense; note: clean split may be empty in 100%-exposure runs |
| Bootstrap confidence intervals | ✅ 95% CIs for ASR and task success via `eval/bootstrap.py` |

---

## 6) Explicit limitations

| Limitation | Notes |
|------------|-------|
| **Scope: retrieval IPI only** | Canonical project scope is retrieval-channel IPI. Tool-output perturbations \(u_t\) are treated as optional future extension, not a blocker for current claims. |
| **L_bad proxy** | `scripts/18_lbad_correlation.py` uses taint score as proxy, not logit-based Σ p_θ(τ\|o). Requires model logits for a proper test of Theorem 1. |
| **100% exposure regime** | All episodes are attacked; no clean held-out split in the primary grid. FRR is computable but n_clean = 0 in the Colab export. |
| **Discrete attack optimization** | `scripts/17_formal_attack_optimization.py` performs discrete template search, not continuous optimization over δ. |
| **Mock vs. live models** | Mock mode simulates compliance; structured φ certificates exercised only with live model backends (api/ollama/hf). |
| **Constrained policy** | Implemented as hard block, not renormalized mixture over φ as in proposal. |
