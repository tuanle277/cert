# What Is Already Done vs. Full Execution Plan

This maps the current repo to the complete, defensible project plan (threat model → benchmark → defenses → certificate gating → metrics → figures → writeup).

---

## 0) Project goal (claim)

**Claim:** Untrusted retrieved/tool content can hijack an LLM agent’s control flow, and certificate-gated authorization can reduce unsafe actions beyond baselines (quoting, provenance, allowlists).

**Status:** Scaffold and pipeline exist; the claim is not yet fully supported by implemented defenses and metrics.

---

## 1) What “complete” means — checklist

| Item | Status |
|------|--------|
| **A. Benchmark** | |
| Reproducible corpus/tasks/injections | ✅ Pipeline: 00→01→02→03 |
| Fixed train/eval slice | ⚠️ Config-driven (max_examples, max_tasks); no frozen “benchmark v1” hash |
| Deterministic manifests and hashes | ✅ `corpus/manifest.json`, `integrity.sha256`, `indexes/manifest.json`, `injection_manifest.json` |
| **B. Threat model** | |
| Trusted vs untrusted channels | ⚠️ Implicit (retrieval/tool = untrusted); not in run log as `trusted_inputs` / `untrusted_inputs` |
| Structured action space | ❌ No; agent returns free-form `final_answer` |
| Explicit unauthorized action set | ❌ No `is_bad_action(run)` or B defined |
| **C. Baselines** | |
| No defense | ✅ Grid has defense `"none"` |
| Quoting / provenance / allowlist / combos / cert | ⚠️ Names in `defenses.yaml` only; **no prompt rendering or enforcement** |
| **D. Live defense** | |
| Model emits action + certificate | ❌ No structured action/cert output or parser |
| Deterministic verifier checks authorization | ✅ `verifier.verify()` exists (taint + cert checks) |
| Rejected actions blocked | ❌ Verifier not called in run loop; no blocking |
| **E. Evaluation** | |
| Attack success / task success / false reject / etc. | ⚠️ Task success only; no R_bad, R_forge, false reject, rejection reasons |
| Security–utility frontier | ⚠️ Plots are success-rate only |
| **F. Final artifacts** | |
| Main results figure, mechanism figure, ablation table | ⚠️ Performance/exposure figures exist; not aligned to R_bad/R_forge/defense ladder |

---

## 2) Build order — where you are

| Phase | Status |
|-------|--------|
| 1. Lock the benchmark | ⚠️ Partially done (manifests, deterministic chunk_id); no single frozen “baseline” config with hashes in logs |
| 2. Unauthorized actions machine-checkable | ❌ Not started |
| 3. Structured-action agent | ❌ Only retrieval_echo + mock ReAct (no JSON action schema) |
| 4. Baseline ladder | ❌ Defense names only; no implementation |
| 5. Certificate gating | ⚠️ Verifier module exists; not wired to agent or run loop |
| 6. Core experiments | ⚠️ Grid runs and logs exist; no real defense conditions |
| 7. Ablations | ❌ Not started |
| 8. Paper/report | ❌ Not started |

---

## 3) Phase I — Benchmark and threat model (detailed)

| Step | Done | Notes |
|------|------|--------|
| **3.1 Freeze one benchmark** | Partial | HotpotQA, distractor/faiss, configs; no frozen “baseline” block in `grid.yaml`, no dataset/corpus/task/attack hashes in run logs |
| **3.2 Trusted vs untrusted explicit** | Partial | `exposed_sources`, `injected_sources` logged; no `trusted_inputs` / `untrusted_inputs` or task_spec_id |
| **3.3 Action space** | No | No structured actions (e.g. `respond_answer`, `save_notes`), no JSON action schema or parser |
| **3.4 Unauthorized actions (B)** | No | No `is_bad_action(run)` or formal B |

---

## 4) Phase II — Show the problem

| Step | Done | Notes |
|------|------|--------|
| **4.1 retrieval_echo + one real agent policy** | Partial | retrieval_echo exists; no structured_qa_agent / retrieval_reasoner with JSON action |
| **4.2 Attack uptake measurable** | Partial | Exposure (exposed_sources, injected_sources) logged; no instruction-uptake score, no behavior-deviation flag |
| **4.3 Clean-vs-attacked paired evaluation** | Partial | 10_plot_attack_example runs clean + injected for one task and shows output diff; grid does not run paired clean+poisoned per task |

---

## 5) Phase III — Baseline defenses

| Step | Done | Notes |
|------|------|--------|
| **5.1 No defense** | Yes | Defense `"none"` in grid |
| **5.2 Quoting / delimiting** | No | No prompt wrapping of untrusted content |
| **5.3 Provenance labeling** | No | No `[Source: untrusted_retrieval \| chunk_id=...]` in prompts |
| **5.4 Static allowlist** | No | No `allowlist_check(action, task_spec)` or blocking |
| **5.5 Combine (quote+prov+allowlist)** | No | Defenses are names only |

---

## 6) Phase IV — Certificate-gated authorization

| Step | Done | Notes |
|------|------|--------|
| **6.1 Task spec G (allowed_actions, goal_refs, constraints)** | No | Tasks have goal, allowed_tools, expected_answer; no G with goal_refs, allowed_actions, constraints |
| **6.2 Model emits action + certificate** | No | No cert-output prompt or parser |
| **6.3 Deterministic verifier** | Partial | `verifier.verify()` + taint; not full goal/evidence/constraint checks, no reason codes |
| **6.4 Block rejected actions** | No | Verifier not invoked in 05_run_grid; no blocking |
| **6.5 Taint detection** | Yes | ngram + optional embedding in `verifier/taint.py`; configurable in verifier.yaml |

---

## 7) Phase V — Attack suite

| Step | Done | Notes |
|------|------|--------|
| **7.1 Non-adaptive attacks** | Partial | Templates (direct_override, evidence_laundering, etc.); no attack_family tag in injection manifest |
| **7.2 Adaptive (goal/evidence/policy mimicry)** | Partial | Templates exist; not tagged or stratified in metrics |

---

## 8) Phase VI — Metrics and analysis

| Step | Done | Notes |
|------|------|--------|
| **8.1 Core metrics** | Partial | Task success rate by defense; no R_bad, R_forge, exposure rate, conditional attack success, false reject |
| **8.2 Bootstrap CIs** | Partial | `eval.bootstrap` exists; not used in 06_compute_metrics or main figures |
| **8.3 Paired clean-vs-attack** | Partial | In attack_example script only; not in grid or 06 |

---

## 9) Scripts and modules — concrete status

| Script / module | Done | Missing |
|-----------------|------|--------|
| **00_download_datasets** | ✅ | — |
| **01_build_corpus** | ✅ Manifest, integrity, stable chunk_id | Log corpus/task hashes in run (or in a benchmark manifest) |
| **02_generate_tasks** | ✅ context_titles, supporting_facts, context_paragraphs | Task spec G: goal_refs, allowed_actions, constraints |
| **03_inject_corpus** | ✅ injection_manifest (chunk_id, strategy, placement, B, payload_hash) | attack_family tag |
| **04_run_episode** | ✅ | — |
| **05_run_grid** | ✅ use_injected_corpus, retriever, exposed_sources, injected_sources, verifier_* fields | Defense instantiation (quote/prov/allowlist), verifier call, blocking, action/cert parsing |
| **06_compute_metrics** | ✅ success_rate by defense | R_bad, R_forge, false reject, bootstrap CI, paired stats |
| **07 / 07b / 08 / 10** | ✅ Frontiers, performance, pipeline, attack example, output comparison | Align to R_bad / task success / defense ladder |
| **verifier/** | ✅ certificate, taint, verify() | Reason codes, full G checks, integration in runner |
| **task_spec** | ✅ make_task_instance, schema | G fields: goal_refs, allowed_actions, constraints |
| **agent** | ✅ retrieval_echo, mock ReAct | Structured-action agent, action+cert output |
| **eval** | ✅ success rate, bootstrap | is_bad_action, R_forge, false reject |
| **defense/** | — | No module; allowlist + prompt rendering (quote/prov) not implemented |

---

## 10) Immediate next 10 tasks (from the plan)

1. **Freeze one baseline config in grid.yaml** — Add a `frozen_baseline` block and log dataset/corpus/task/attack hashes.
2. **Add task_spec G into task JSON** — goal_refs, allowed_actions, constraints in 02 and task_spec.
3. **Structured action schema** — respond_answer (and optionally save_notes), JSON schema + parser.
4. **One structured-action agent** — Retrieval + emit parsed action (and later cert).
5. **Implement is_bad_action(run)** — Deterministic bad-action detection (type, uptake, grounding).
6. **Allowlist enforcement** — allowlist_check(action, task_spec); block and log.
7. **Prompt rendering: quoting + provenance** — Wrap untrusted content; add source labels.
8. **Certificate output schema + parser** — Model outputs action + certificate; parse and validate.
9. **Verifier in loop + block** — Call verify(); on reject, set action to blocked and log.
10. **06_compute_metrics** — R_bad, R_forge, false reject, bootstrap CIs; feed main figures.

---

## 11) One-sentence summary

**Done:** Reproducible data pipeline (download → corpus → tasks → injection), deterministic manifests and chunk IDs, retrieval from injected corpus (attacks every run), exposure/injection logging, verifier and taint module, retrieval_echo agent, and figures for pipeline, attack example, and performance.  
**Not done:** Frozen benchmark hashes in logs, structured actions and unauthorized-action set, any real defense (quoting/provenance/allowlist/cert) implemented and blocking, certificate output and verifier in the run loop, and the full metric set (R_bad, R_forge, false reject, CIs) plus report-ready figures and writeup.
