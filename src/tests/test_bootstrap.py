"""Tests for bootstrap confidence intervals."""

from cert_agent_exp.eval.bootstrap import bootstrap


def test_bootstrap_basic():
    items = [1.0, 0.0, 1.0, 0.0, 1.0]
    point, lower, upper = bootstrap(items, lambda x: sum(x) / len(x))
    assert point == 0.6
    assert lower <= point <= upper
    assert 0.0 <= lower
    assert upper <= 1.0


def test_bootstrap_all_same():
    items = [1.0] * 10
    point, lower, upper = bootstrap(items, lambda x: sum(x) / len(x))
    assert point == 1.0
    assert lower == 1.0
    assert upper == 1.0


def test_bootstrap_deterministic():
    items = list(range(20))
    stat = lambda x: sum(x) / len(x)
    r1 = bootstrap(items, stat, seed=42)
    r2 = bootstrap(items, stat, seed=42)
    assert r1 == r2


def test_bootstrap_ci_contains_point():
    items = [1, 0, 1, 0, 1, 0, 1, 0, 1, 0]
    point, lower, upper = bootstrap(items, lambda x: sum(x) / len(x), n_bootstrap=500)
    assert lower <= point <= upper
