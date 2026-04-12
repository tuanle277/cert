# To-do list (specific)

Concrete tasks in rough order. Check off as done.

---

## Benchmark & threat model (finish)

- [x] **Log trusted vs untrusted explicitly in each run**  
  In `05_run_grid.py`, each run log includes: `exposed_sources`, `injected_sources`, `G_hash`, `exposure` diagnostics, `defense_trace`.

- [x] **Tag injection manifest with attack_family**  
  In `03_inject_corpus.py`, each injection entry has `strategy` (attack_family). `06_compute_metrics.py` stratifies R_bad by strategy.

---

## Defenses (implement)

- [x] **Quoting defense**  
  `defense/prompt.py` wraps retrieved chunks in `<<<UNTRUSTED>>>` delimiters. Used when `defense == "quote_only"` or combos.

- [x] **Provenance labeling defense**  
  Chunks prepended with `<source id='...' provenance='trusted/untrusted'>` tags. Used when `defense == "provenance_tags"` or combos.

- [x] **Allowlist module and enforcement**  
  `defense/allowlist.py` — `allowlist_check(action, task)` returns `(allowed, reason)`. Wired in `05_run_grid.py` to block.

- [x] **Wire defenses to the grid**  
  `05_run_grid.py` instantiates each defense (quote/prov/allowlist/cert/taskshield/judge/intentguard), runs checks, blocks rejected actions, logs `action_attempted` vs `action_executed`.

---

## Certificate gating (implement & wire)

- [x] **Certificate output schema and parser**  
  `action_schema.py` parses `certificate` field from model output JSON: `{goal, evidence, constraints}`.

- [x] **Prompt template for action + certificate**  
  Retrieval-echo agent returns action + certificate when defense is `certificate_gating`.

- [x] **Verifier: full G checks and reason codes**  
  `verifier/certificate.py` — `validate_certificate(cert, task, trusted_sources)` checks: goal ∈ Γ(G), evidence provenance, constraint integrity. Reason codes: `ok`, `goal_mismatch`, `untrusted_evidence`, `foreign_constraints`, `missing_certificate`.

- [x] **Call verifier in run loop and block**  
  `05_run_grid.py` calls `verify_with_debug()` for certificate_gating defense. Rejected actions set to `{"type": "blocked"}` with `rejection_reason`.

---

## Metrics & figures (extend)

- [x] **R_forge in 06**  
  Computed for all defenses in `06_compute_metrics.py`.

- [x] **False reject rate in 06**  
  All defenses maintain 0% false rejection on clean queries.

- [x] **Bootstrap 95% CIs in 06**  
  `eval/bootstrap.py` computes CIs; used in performance figures.

- [x] **Main figures use R_bad and CIs**  
  `07b_plot_performance.py` plots ASR by defense with 95% bootstrap error bars.

- [x] **Security–utility frontier plot**  
  `11_generate_paper_figures.py` produces `tau_sensitivity.png` sweeping threshold τ.

- [x] **Rejection reason histogram**  
  `09_proof_package.py` produces `rejection_analysis.md` with breakdown by reason code.

---

## Evaluation upgrades

- [x] **Paired clean vs attacked in grid**  
  `09_proof_package.py` produces paired diffs comparing clean vs attacked traces.

- [x] **Instruction-uptake score in run log**  
  Taint score logged per episode; n-gram overlap with payloads.

---

## Ablations

- [x] **Taint ablation**  
  `16_extended_results.py` — mechanism ablation with tau sweep.

- [x] **Certificate field ablation**  
  `14_adaptive_attack_analysis.py` tests each certificate check independently.

- [x] **Attack budget sweep**  
  `16_extended_results.py` — ASR vs budget B (25-500 tokens).

---

## Report & release

- [x] **Update STATUS.md**  
  All items marked as completed.

- [x] **Ablation table**  
  Extended results with mechanism ablation, threshold sensitivity, budget experiments.

- [x] **Full report**  
  `REPORT.md` — 14-section report with threat model, method, results, defense traces, SOTA comparison, reproducibility guide.

- [x] **Release checklist**  
  Frozen benchmark config, README run instructions, all configs and scripts needed to reproduce.

---

## Future work (not blocking release)

- [ ] **Joint training robustness** — Test whether models learn to satisfy verifier constraints over time
- [x] **Cosine similarity augmentation** — `verifier/taint.py` now computes embedding cosine similarity alongside n-gram overlap using `all-MiniLM-L6-v2`. Configured via `verifier.yaml` (`embed_similarity_threshold: 0.82`). Both signals are OR'd for taint decisions.
- [x] **Multi-agent evaluation** — `agent/planner_executor.py` implements two-phase plan→execute architecture. `scripts/19_planner_executor_experiment.py` runs secondary grid (225 episodes) and compares against ReAct.
- [ ] **Live LLM evaluation** — Run full grid with GPT-4o-mini / Llama 3.2 instead of mock mode
