#!/usr/bin/env bash
# Run the full experiment pipeline end-to-end.
# Usage: bash scripts/07_run_all.sh [--light] [--fallback]
#
# Flags:
#   --light     Minimal grid (1 defense, 1 seed, 1 task) for quick smoke test
#   --fallback  Use synthetic tasks instead of downloading HotpotQA

set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="${PWD}/src:${PYTHONPATH:-}"

LIGHT=""
FALLBACK=""
for arg in "$@"; do
    case $arg in
        --light)    LIGHT="--light" ;;
        --fallback) FALLBACK="--fallback" ;;
    esac
done

echo "================================================================"
echo "  CERT-AGENT-EXP: Full Pipeline"
echo "================================================================"

echo ""
echo "--- Step 1: Prepare data ---"
python scripts/01_prepare_data.py $FALLBACK

echo ""
echo "--- Step 2: Build corpus ---"
python scripts/02_build_corpus.py

echo ""
echo "--- Step 3: (Optional) Legacy on-disk inject: python scripts/03_inject_corpus.py ---"
echo "  Skipped — retrieval-time injection uses SearchTool + strategy payloads."

echo ""
echo "--- Step 4: Build FAISS index ---"
PYTHONPATH=src python scripts/04_build_index.py --config configs/datasets.yaml --corpus data/corpus/chunks.jsonl

echo ""
echo "--- Step 5: Run grid ---"
PYTHONPATH=src python scripts/05_run_grid.py --config configs/grid.yaml $LIGHT

echo ""
echo "--- Step 6: Compute metrics ---"
PYTHONPATH=src python scripts/06_compute_metrics.py --config configs/grid.yaml

echo ""
echo "--- Step 7: Performance plots (bootstrap ASR, exposure, security) ---"
PYTHONPATH=src python scripts/07b_plot_performance.py --config configs/grid.yaml

echo ""
echo "--- Step 8: Paper + trace figures ---"
PYTHONPATH=src python scripts/11_generate_paper_figures.py

echo ""
echo "--- Step 9: Attack trace figure ---"
PYTHONPATH=src python scripts/12_attack_trace_figure.py

echo ""
echo "--- Step 10: Attack optimization ---"
PYTHONPATH=src python scripts/13_attack_optimization.py

echo ""
echo "--- Step 11: Adaptive attack analysis ---"
PYTHONPATH=src python scripts/14_adaptive_attack_analysis.py

echo ""
echo "--- Step 12: Attack figures ---"
PYTHONPATH=src python scripts/15_attack_figures.py

echo ""
echo "--- Step 13: Extended results ---"
PYTHONPATH=src python scripts/16_extended_results.py

echo ""
echo "--- Step 14: Formal attack optimization (proposal-aligned) ---"
PYTHONPATH=src python scripts/17_formal_attack_optimization.py

echo ""
echo "--- Step 15: L_bad / ΔL_bad correlation analysis ---"
PYTHONPATH=src python scripts/18_lbad_correlation.py

echo ""
echo "--- Step 16: Planner-executor secondary experiment ---"
PYTHONPATH=src python scripts/19_planner_executor_experiment.py

echo ""
echo "================================================================"
echo "  PIPELINE COMPLETE"
echo "================================================================"
echo "  Logs:    runs/logs/"
echo "  Metrics: runs/metrics/"
echo "  Figures: runs/figures/"
echo "================================================================"
