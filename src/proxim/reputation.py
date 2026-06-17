"""Reputation — the "how well has it held up" of Proxim.

Identity and signatures tell you *who* produced an output and that it wasn't
altered. They say nothing about whether that agent is any *good*. Reputation
fills the gap: downstream consumers record an outcome each time they rely on an
agent's output (it was correct / it was wrong / something in between), and the
ledger turns that history into a single score in ``[0, 1]``.

Two design choices make the score well-behaved:

* **Time decay.** Recent outcomes matter more than old ones. Each event's weight
  is multiplied by ``0.5 ** (age / half_life)`` so stale evidence fades.
* **A Bayesian prior.** A brand-new agent with zero history scores
  ``prior_mean`` (0.5 by default), not 0 and not 1. A single good or bad outcome
  nudges the score but doesn't slam it to an extreme. This prevents both
  "cold-start distrust" and "one lucky success looks perfect".
"""

from __future__ import annotations

import json
import math
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

# Convenient named outcomes. Any float in [0, 1] is also accepted.
GOOD = 1.0
BAD = 0.0
NEUTRAL = 0.5

_DAY_SECONDS = 86_400.0


@dataclass(frozen=True)
class FeedbackEvent:
    """A single recorded outcome about an agent's output."""

    agent_id: str
    outcome: float  # in [0, 1]; 1 == fully trustworthy, 0 == bad
    weight: float
    at: float
    attestation_id: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "outcome": self.outcome,
            "weight": self.weight,
            "at": self.at,
            "attestation_id": self.attestation_id,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FeedbackEvent":
        return cls(
            agent_id=data["agent_id"],
            outcome=float(data["outcome"]),
            weight=float(data.get("weight", 1.0)),
            at=float(data["at"]),
            attestation_id=data.get("attestation_id"),
            note=data.get("note"),
        )


@dataclass(frozen=True)
class ReputationScore:
    """The computed reputation of an agent at a point in time."""

    agent_id: str
    value: float  # in [0, 1]
    sample_count: int
    effective_evidence: float  # decayed, weighted count of evidence
    last_seen: Optional[float]

    @property
    def is_cold_start(self) -> bool:
        """True when there is essentially no evidence yet (score ≈ the prior)."""
        return self.effective_evidence < 1e-9


class ReputationLedger:
    """An append-only log of feedback events plus a decayed Bayesian score.

    Parameters
    ----------
    half_life_days:
        How quickly evidence loses half its weight. Default 30 days.
    prior_mean:
        The score of an agent with no evidence. Default 0.5 (neutral).
    prior_strength:
        How many "virtual" neutral observations the prior is worth. Larger →
        more evidence needed to move the score. Default 2.0.
    """

    def __init__(
        self,
        *,
        half_life_days: float = 30.0,
        prior_mean: float = NEUTRAL,
        prior_strength: float = 2.0,
    ) -> None:
        if half_life_days <= 0:
            raise ValueError("half_life_days must be positive")
        if not 0.0 <= prior_mean <= 1.0:
            raise ValueError("prior_mean must be in [0, 1]")
        if prior_strength < 0:
            raise ValueError("prior_strength must be non-negative")
        self.half_life_days = half_life_days
        self.prior_mean = prior_mean
        self.prior_strength = prior_strength
        self._events: List[FeedbackEvent] = []

    # -- recording ------------------------------------------------------- #
    def record(
        self,
        agent_id: str,
        outcome: float,
        *,
        weight: float = 1.0,
        at: Optional[float] = None,
        attestation_id: Optional[str] = None,
        note: Optional[str] = None,
    ) -> FeedbackEvent:
        """Append a feedback event. ``outcome`` is clamped into ``[0, 1]``."""
        if weight < 0:
            raise ValueError("weight must be non-negative")
        outcome = min(1.0, max(0.0, float(outcome)))
        event = FeedbackEvent(
            agent_id=agent_id,
            outcome=outcome,
            weight=float(weight),
            at=time.time() if at is None else float(at),
            attestation_id=attestation_id,
            note=note,
        )
        self._events.append(event)
        self._persist()
        return event

    def record_success(self, agent_id: str, **kwargs: Any) -> FeedbackEvent:
        return self.record(agent_id, GOOD, **kwargs)

    def record_failure(self, agent_id: str, **kwargs: Any) -> FeedbackEvent:
        return self.record(agent_id, BAD, **kwargs)

    # -- scoring --------------------------------------------------------- #
    def score(self, agent_id: str, *, now: Optional[float] = None) -> ReputationScore:
        """Compute the current reputation score for ``agent_id``."""
        now = time.time() if now is None else now
        half_life_seconds = self.half_life_days * _DAY_SECONDS

        weighted_outcome = 0.0
        weighted_total = 0.0
        sample_count = 0
        last_seen: Optional[float] = None

        for event in self._events:
            if event.agent_id != agent_id:
                continue
            sample_count += 1
            last_seen = event.at if last_seen is None else max(last_seen, event.at)
            age = max(0.0, now - event.at)
            decay = math.pow(0.5, age / half_life_seconds)
            effective = event.weight * decay
            weighted_outcome += effective * event.outcome
            weighted_total += effective

        numerator = self.prior_mean * self.prior_strength + weighted_outcome
        denominator = self.prior_strength + weighted_total
        value = numerator / denominator if denominator > 0 else self.prior_mean

        return ReputationScore(
            agent_id=agent_id,
            value=value,
            sample_count=sample_count,
            effective_evidence=weighted_total,
            last_seen=last_seen,
        )

    def events_for(self, agent_id: str) -> List[FeedbackEvent]:
        return [e for e in self._events if e.agent_id == agent_id]

    def all_events(self) -> List[FeedbackEvent]:
        return list(self._events)

    def __len__(self) -> int:
        return len(self._events)

    # -- serialization --------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": "proxim-reputation/1",
            "params": {
                "half_life_days": self.half_life_days,
                "prior_mean": self.prior_mean,
                "prior_strength": self.prior_strength,
            },
            "events": [e.to_dict() for e in self._events],
        }

    def load_dict(self, data: Mapping[str, Any]) -> None:
        params = data.get("params") or {}
        self.half_life_days = float(params.get("half_life_days", self.half_life_days))
        self.prior_mean = float(params.get("prior_mean", self.prior_mean))
        self.prior_strength = float(params.get("prior_strength", self.prior_strength))
        self._events = [FeedbackEvent.from_dict(e) for e in data.get("events", [])]

    def _persist(self) -> None:  # pragma: no cover - no-op in base class
        pass


class JsonFileLedger(ReputationLedger):
    """A :class:`ReputationLedger` that mirrors its events to a JSON file."""

    def __init__(self, path: str | os.PathLike[str], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.path = os.fspath(path)
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self.load_dict(json.load(fh))

    def _persist(self) -> None:
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)
