import json
import os
from typing import Any, Iterable, Iterator


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_jsonl(path: str, rows: Iterable[Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def read_jsonl(path: str) -> Iterator[Any]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)
