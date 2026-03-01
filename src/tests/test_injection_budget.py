from cert_agent_exp.attacks import apply_budget, inject_into_text

def test_apply_budget():
    p = "one two three four five"
    assert len(apply_budget(p, 3).split()) == 3
    assert apply_budget(p, 10) == p

def test_inject_placement():
    t = "original"
    p = "payload"
    assert inject_into_text(t, p, "prefix").startswith("payload")
    assert inject_into_text(t, p, "suffix").endswith("payload")
    assert "payload" in inject_into_text(t, p, "middle")
