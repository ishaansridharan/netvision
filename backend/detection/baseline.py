"""
NetVision — Adaptive Baselines (detection/baseline.py)

The adaptive detectors compare what they observe now against what is
normal for *this* network, instead of against a fixed constant.

EWMA mean and variance
──────────────────────
For each new sample x (one per second):

    d     = x − μ
    μ    ← μ + α·d
    σ²   ← (1 − α)·(σ² + α·d²)

This is the exponentially-weighted moving average and its matching
variance (West, 1979).  α controls the memory: with α = 0.05 the baseline
effectively averages the last ~1/α = 20 samples, with older samples
decaying geometrically.

z-score and adaptive threshold
──────────────────────────────
    z         = (x − μ) / max(σ, σ_min)
    threshold = max(floor, μ + k·σ)

`floor` is an absolute minimum so that a very quiet network (μ ≈ 0, σ ≈ 0)
doesn't alert on trivial activity; `σ_min` stops division by ~0.

Not learning from attacks
─────────────────────────
If samples above the threshold were folded into the baseline, a sustained
attack would raise μ and σ until it looked normal and the alert would
disappear ("baseline poisoning").  update() therefore clips every sample
to μ + 1·σ before learning from it.

Why 1σ and not the alert threshold (kσ)?  Feeding a sample at μ + c·σ
multiplies the variance by (1 − α)(1 + α·c²).  For c = k = 3 and α = 0.05
that is ≈ 1.38 per sample, so a sustained attack would inflate σ
geometrically and hide itself within ~20 s.  For c = 1 the factor is
1 − α² < 1: σ stays bounded and μ creeps upward by at most α·σ per
sample.  Genuine, lasting changes are still learned — over minutes rather
than seconds — while a short attack cannot train the baseline.

Warm-up
───────
Until `warmup` samples have been seen the baseline is not trusted and
callers fall back to the floor (or to a population baseline).  Warm-up
samples are clipped at `cold_clip` — normally the detector's static
threshold — so traffic that static mode would accept is learned in full,
while an attack running at start-up cannot become the baseline.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional


@dataclass
class BaselineView:
    """Read-only summary of a baseline, used in alert explanations."""
    mean: float
    std: float
    samples: int
    ready: bool
    scope: str = "network"

    def to_dict(self) -> dict:
        return {
            "mean": round(self.mean, 3),
            "std": round(self.std, 3),
            "samples": self.samples,
            "ready": self.ready,
            "scope": self.scope,
        }


class EWMABaseline:
    """Exponentially-weighted mean/variance with z-score and clipping."""

    __slots__ = ("alpha", "k", "warmup", "floor", "min_std", "cold_clip", "mean", "var", "n")

    def __init__(
        self,
        alpha: float = 0.05,
        k: float = 3.0,
        warmup: int = 30,
        floor: float = 0.0,
        min_std: float = 1.0,
        cold_clip: Optional[float] = None,
    ) -> None:
        self.alpha = alpha
        self.k = k
        self.warmup = warmup
        self.floor = floor
        self.min_std = min_std
        self.cold_clip = cold_clip
        self.mean = 0.0
        self.var = 0.0
        self.n = 0

    @property
    def std(self) -> float:
        return math.sqrt(max(self.var, 0.0))

    @property
    def ready(self) -> bool:
        return self.n >= self.warmup

    def threshold(self) -> float:
        """Value above which a sample is anomalous."""
        if not self.ready:
            return self.floor
        return max(self.floor, self.mean + self.k * max(self.std, self.min_std))

    def z_score(self, x: float) -> float:
        if self.n == 0:
            return 0.0
        return (x - self.mean) / max(self.std, self.min_std)

    def is_anomalous(self, x: float) -> bool:
        return x >= self.threshold()

    def clip_point(self) -> float:
        """Largest value update() will learn from once warmed up."""
        return self.mean + max(self.std, self.min_std)

    def update(self, x: float, clip_at: Optional[float] = None) -> None:
        """
        Learn from sample *x*.  Once warmed up, x is clipped to μ + 1σ (see
        module docstring).  *clip_at* lets a caller impose an external clip
        point, e.g. a population baseline guarding a per-host warm-up.
        """
        if self.ready:
            x = min(x, self.clip_point())
        elif self.cold_clip is not None:
            x = min(x, self.cold_clip)
        if clip_at is not None:
            x = min(x, clip_at)
        if self.n == 0:
            self.mean = x
            self.var = 0.0
        elif self.n < self.warmup:
            # During warm-up use a cumulative average so early samples are
            # weighted equally instead of the first one dominating.
            n = self.n + 1
            d = x - self.mean
            self.mean += d / n
            self.var += (d * (x - self.mean) - self.var) / n
        else:
            d = x - self.mean
            incr = self.alpha * d
            self.mean += incr
            self.var = (1 - self.alpha) * (self.var + d * incr)
        self.n += 1

    def view(self, scope: str = "network") -> BaselineView:
        return BaselineView(self.mean, self.std, self.n, self.ready, scope)


class BaselineTable:
    """
    One baseline per key (e.g. per source IP) plus a population baseline
    shared by all keys.  New or rarely-seen keys are judged against the
    population until their own baseline has warmed up.
    """

    def __init__(
        self,
        alpha: float,
        k: float,
        warmup: int,
        floor: float,
        min_std: float,
        cold_clip: Optional[float] = None,
        max_keys: int = 5_000,
    ) -> None:
        self._params = dict(alpha=alpha, k=k, warmup=warmup, floor=floor,
                            min_std=min_std, cold_clip=cold_clip)
        self.population = EWMABaseline(**self._params)
        self._per_key: OrderedDict[str, EWMABaseline] = OrderedDict()
        self._max_keys = max_keys

    def get(self, key: str) -> Optional[EWMABaseline]:
        return self._per_key.get(key)

    def for_key(self, key: str) -> tuple[EWMABaseline, str]:
        """The baseline to judge *key* by, and its scope label."""
        own = self._per_key.get(key)
        if own is not None and own.ready:
            return own, "per-host"
        return self.population, "network"

    def update(self, key: str, x: float) -> None:
        own = self._per_key.get(key)
        if own is None:
            own = EWMABaseline(**self._params)
            self._per_key[key] = own
            if len(self._per_key) > self._max_keys:
                self._per_key.popitem(last=False)
        else:
            self._per_key.move_to_end(key)
        # While a host's own baseline warms up it is judged by the network
        # baseline, so it must not learn values the network would flag —
        # otherwise a scanner could train its own baseline during warm-up.
        # (Before the network baseline is ready, cold_clip applies instead.)
        clip = None
        if not own.ready and self.population.ready:
            clip = self.population.threshold()
        own.update(x, clip_at=clip)

    def update_population(self, x: float) -> None:
        self.population.update(x)

    def keys(self) -> list[str]:
        return list(self._per_key.keys())

    def __len__(self) -> int:
        return len(self._per_key)
