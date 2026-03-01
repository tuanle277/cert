"""Run a single episode (n tasks) for testing."""

import argparse
import os
import yaml

from cert_agent_exp.common.io import read_jsonl
from cert_agent_exp.agent import run_episode
from cert_agent_exp.tools import SearchTool, ReadDocTool


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--n", type=int, default=1, help="Number of tasks to run")
    args = ap.parse_args()

    cfg = yaml.safe_load(open(args.config, "r"))
    data_dir = cfg["data_dir"]
    runs_dir = cfg.get("runs_dir", "runs")
    agent_cfg = cfg.get("agent", {})
    model_cfg = cfg.get("models", {})

    tasks_path = os.path.join(data_dir, "tasks", "hotpotqa_tasks.jsonl")
    if not os.path.exists(tasks_path):
        print(f"[err] {tasks_path} not found; run 02_generate_tasks first")
        return

    tools = [SearchTool(), ReadDocTool()]
    tasks = list(read_jsonl(tasks_path))[: args.n]
    for task in tasks:
        result = run_episode(
            task,
            tools,
            agent_type=agent_cfg.get("type", "react"),
            max_steps=agent_cfg.get("max_steps", 12),
            model_mode=model_cfg.get("mode", "mock"),
        )
        print(f"task_id={result['task_id']} success={result['success']} answer={result['final_answer'][:60]}...")


if __name__ == "__main__":
    main()
