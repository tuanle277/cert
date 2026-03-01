from typing import Any, Callable, Iterator

from . import hotpotqa

REGISTRY: dict[str, Callable[[Iterator[dict[str, Any]]], Iterator[dict[str, Any]]]] = {
    "hotpotqa": hotpotqa.iter_documents,
}

TASK_REGISTRY: dict[str, Callable[[Iterator[dict[str, Any]]], Iterator[dict[str, Any]]]] = {
    "hotpotqa": hotpotqa.iter_tasks,
}


def get_iterator(name: str, raw_rows: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    fn = REGISTRY.get(name)
    if not fn:
        raise ValueError(f"Unknown dataset: {name}. Known: {list(REGISTRY)}")
    return fn(raw_rows)


def get_task_iterator(name: str, raw_rows: Iterator[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    fn = TASK_REGISTRY.get(name)
    if not fn:
        raise ValueError(f"No task iterator for dataset: {name}. Known: {list(TASK_REGISTRY)}")
    return fn(raw_rows)
