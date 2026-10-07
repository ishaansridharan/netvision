import random
import statistics

from backend.detection.baseline import BaselineTable, EWMABaseline


def test_converges_to_mean_and_std():
    rng = random.Random(1)
    b = EWMABaseline(alpha=0.02, k=3, warmup=30, floor=0, min_std=0.01)
    samples = [rng.gauss(100, 10) for _ in range(3000)]
    for x in samples:
        b.update(x)
    assert abs(b.mean - 100) < 3
    assert 7 < b.std < 13
    assert b.ready


def test_threshold_respects_floor_and_warmup():
    b = EWMABaseline(alpha=0.05, k=3, warmup=10, floor=8, min_std=1)
    assert b.threshold() == 8                    # not warmed up → floor
    for _ in range(10):
        b.update(1.0)
    assert b.threshold() == 8                    # μ + kσ = 1 + 3 < floor
    for _ in range(200):
        b.update(20.0)                           # genuine, lasting shift
    assert b.threshold() > 8


def test_sustained_anomaly_cannot_poison_baseline():
    """
    Clipping at μ + 1σ: a sustained flood at 50× normal must leave the
    baseline close to where it was for the length of a realistic attack.
    """
    rng = random.Random(2)
    b = EWMABaseline(alpha=0.05, k=3, warmup=30, floor=0, min_std=1)
    for _ in range(300):
        b.update(rng.gauss(10, 2))
    thr_before, std_before = b.threshold(), b.std
    for _ in range(60):                         # one minute of attack
        b.update(500.0)
        assert b.is_anomalous(500.0)            # still detected every second
    assert b.std < 2 * std_before + 1           # σ did not explode
    assert b.threshold() < thr_before * 2.5


def test_table_falls_back_to_population_then_per_key():
    t = BaselineTable(alpha=0.05, k=3, warmup=5, floor=2, min_std=1)
    for _ in range(10):
        t.update_population(2.0)
    base, scope = t.for_key("10.0.0.9")
    assert scope == "network"
    for _ in range(5):
        t.update("10.0.0.9", 2.0)
    base, scope = t.for_key("10.0.0.9")
    assert scope == "per-host" and base.ready


def test_warmup_clip_stops_self_training():
    """A new source producing huge values must not teach its own baseline them."""
    t = BaselineTable(alpha=0.05, k=3, warmup=5, floor=8, min_std=1)
    for _ in range(50):
        t.update_population(2.0)
    for _ in range(5):
        t.update("scanner", 300.0)
    own, scope = t.for_key("scanner")
    assert scope == "per-host"
    assert own.is_anomalous(300.0)
    assert own.mean <= t.population.threshold() + 1e-9


def test_warmup_variance_matches_population_variance():
    b = EWMABaseline(alpha=0.05, k=3, warmup=100, floor=0, min_std=0.0)
    xs = [1.0, 4.0, 2.0, 8.0, 5.0]
    for x in xs:
        b.update(x)
    assert abs(b.mean - statistics.mean(xs)) < 1e-9
    assert abs(b.var - statistics.pvariance(xs)) < 1e-9
