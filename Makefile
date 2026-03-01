.PHONY: venv install test fmt download corpus tasks inject one grid metrics plots figures performance-figures attack-visual

# Run scripts with PYTHONPATH=src so cert_agent_exp is importable without pip install -e .
RUN = . .venv/bin/activate && PYTHONPATH=src python

venv:
	python -m venv .venv

install:
	. .venv/bin/activate && pip install -r requirements.txt

test:
	. .venv/bin/activate && PYTHONPATH=src python -m pytest src/tests -q

download:
	$(RUN) scripts/00_download_datasets.py --config configs/datasets.yaml

corpus:
	$(RUN) scripts/01_build_corpus.py --config configs/datasets.yaml

tasks:
	$(RUN) scripts/02_generate_tasks.py --config configs/datasets.yaml

inject:
	$(RUN) scripts/03_inject_corpus.py --config configs/attacks.yaml

one:
	$(RUN) scripts/04_run_episode.py --config configs/grid.yaml --n 1

grid:
	$(RUN) scripts/05_run_grid.py --config configs/grid.yaml

metrics:
	$(RUN) scripts/06_compute_metrics.py --config configs/grid.yaml

plots:
	$(RUN) scripts/07_plot_frontiers.py --config configs/grid.yaml

figures:
	$(RUN) scripts/07_plot_frontiers.py --config configs/grid.yaml
	$(RUN) scripts/07b_plot_performance.py --config configs/grid.yaml
	$(RUN) scripts/08_plot_figures.py --config configs/grid.yaml

performance-figures:
	$(RUN) scripts/07_plot_frontiers.py --config configs/grid.yaml
	$(RUN) scripts/07b_plot_performance.py --config configs/grid.yaml

attack-visual:
	$(RUN) scripts/10_plot_attack_example.py --config configs/grid.yaml
