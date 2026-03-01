"""Bootstrap confidence intervals for metrics (stub)."""

import random
from typing import Callable, TypeVar

T = TypeVar("T")


def bootstrap(
    items: list[T],
    statistic: Callable[[list[T]], float],
    n_bootstrap: int = 1000,
    seed: int = 0,
) -> tuple[float, float, float]:
    """Return (point_estimate, lower, upper)."""
    rng = random.Random(seed)
    point = statistic(items)
    values = []
    n = len(items)
    for _ in range(n_bootstrap):
        sample = [items[rng.randint(0, n - 1)] for _ in range(n)]
        values.append(statistic(sample))
    values.sort()
    lower = values[int(0.025 * n_bootstrap)]
    upper = values[int(0.975 * n_bootstrap)]
    return point, lower, upper
