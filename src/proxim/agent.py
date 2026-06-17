"""The ergonomic top-level API: :class:`ProximAgent`.

Everything in Proxim can be used à la carte, but most applications want one
object that bundles an identity together with a verifier, so a single agent can
both *produce* signed outputs and *consume* others' outputs through one handle.
That is :class:`ProximAgent`.

    me = ProximAgent.create("planner")
    att = me.attest(b"the answer is 42")           # produce
    decision = me.trust(att, b"the answer is 42")   # consume / judge
    me.give_feedback(att, outcome=proxim.GOOD)      # update reputation
"""

from __future__ import annotations

import os
import time
from typing import Any, Mapping, Optional, Sequence, Union

from .attestation import Attestation
from .identity import AgentIdentity, PublicIdentity
from .policy import TrustDecision, TrustPolicy
from .registry import InMemoryRegistry
from .reputation import ReputationLedger
from .verifier import VerificationResult, Verifier


class ProximAgent:
    """An identity plus a verifier — one object to sign with and judge against."""

    def __init__(
        self,
        identity: AgentIdentity,
        *,
        registry: Optional[InMemoryRegistry] = None,
        reputation: Optional[ReputationLedger] = None,
        policy: Optional[TrustPolicy] = None,
        register_self: bool = True,
    ) -> None:
        self.identity = identity
        self.verifier = Verifier(registry=registry, reputation=reputation, policy=policy)
        if register_self and not self.verifier.registry.contains(identity.agent_id):
            self.verifier.registry.register(identity.public())

    # -- construction ---------------------------------------------------- #
    @classmethod
    def create(
        cls,
        name: Optional[str] = None,
        *,
        metadata: Optional[Mapping[str, Any]] = None,
        registry: Optional[InMemoryRegistry] = None,
        reputation: Optional[ReputationLedger] = None,
        policy: Optional[TrustPolicy] = None,
        register_self: bool = True,
    ) -> "ProximAgent":
        """Create an agent with a fresh identity."""
        identity = AgentIdentity.generate(name, metadata=metadata)
        return cls(
            identity,
            registry=registry,
            reputation=reputation,
            policy=policy,
            register_self=register_self,
        )

    # -- identity sugar -------------------------------------------------- #
    @property
    def agent_id(self) -> str:
        return self.identity.agent_id

    @property
    def name(self) -> Optional[str]:
        return self.identity.name

    def public(self) -> PublicIdentity:
        return self.identity.public()

    @property
    def registry(self) -> InMemoryRegistry:
        return self.verifier.registry

    @property
    def reputation(self) -> ReputationLedger:
        return self.verifier.reputation

    # -- producing ------------------------------------------------------- #
    def attest(
        self,
        payload: Union[bytes, str],
        *,
        payload_type: Optional[str] = None,
        claims: Optional[Mapping[str, Any]] = None,
        parents: Optional[Sequence[str]] = None,
        ttl_seconds: Optional[float] = None,
        issued_at: Optional[float] = None,
    ) -> Attestation:
        """Sign ``payload`` and return an :class:`Attestation`.

        ``str`` payloads are UTF-8 encoded for convenience (and ``payload_type``
        defaults to ``text/plain``). ``issued_at`` can pin the issue time for
        deterministic tests; normally leave it unset.
        """
        if isinstance(payload, str):
            data = payload.encode("utf-8")
            if payload_type is None:
                payload_type = "text/plain; charset=utf-8"
        else:
            data = bytes(payload)
        return Attestation.create(
            self.identity,
            data,
            payload_type=payload_type,
            claims=claims,
            parents=parents,
            ttl_seconds=ttl_seconds,
            issued_at=issued_at,
        )

    # -- consuming ------------------------------------------------------- #
    def verify(
        self,
        attestation: Attestation,
        payload: Optional[Union[bytes, str]] = None,
        *,
        now: Optional[float] = None,
    ) -> VerificationResult:
        return self.verifier.verify(attestation, _as_bytes(payload), now=now)

    def trust(
        self,
        attestation: Attestation,
        payload: Optional[Union[bytes, str]] = None,
        *,
        policy: Optional[TrustPolicy] = None,
        now: Optional[float] = None,
    ) -> TrustDecision:
        return self.verifier.decide(
            attestation, _as_bytes(payload), policy=policy, now=now
        )

    def accept(
        self,
        attestation: Attestation,
        payload: Optional[Union[bytes, str]] = None,
        *,
        policy: Optional[TrustPolicy] = None,
        now: Optional[float] = None,
    ) -> TrustDecision:
        return self.verifier.accept(
            attestation, _as_bytes(payload), policy=policy, now=now
        )

    # -- learning about peers -------------------------------------------- #
    def know(
        self,
        identity: PublicIdentity,
        *,
        roles: Optional[Sequence[str]] = None,
        trust_anchor: bool = False,
    ) -> None:
        """Register a peer's public identity so its attestations can be trusted."""
        self.registry.register(
            identity, roles=roles or [], trust_anchor=trust_anchor
        )

    def give_feedback(
        self,
        target: Union[Attestation, str],
        outcome: float,
        *,
        weight: float = 1.0,
        note: Optional[str] = None,
        at: Optional[float] = None,
    ) -> None:
        """Record how an agent's output held up, updating its reputation.

        ``target`` may be an :class:`Attestation` (preferred — the feedback is
        linked to the specific output) or a bare agent id.
        """
        if isinstance(target, Attestation):
            agent_id = target.agent_id
            attestation_id: Optional[str] = target.attestation_id
        else:
            agent_id = target
            attestation_id = None
        self.reputation.record(
            agent_id,
            outcome,
            weight=weight,
            attestation_id=attestation_id,
            note=note,
            at=at,
        )

    def reputation_of(self, agent_id: str, *, now: Optional[float] = None) -> float:
        """Convenience: the current reputation score of ``agent_id``."""
        return self.reputation.score(agent_id, now=now).value

    # -- persistence ----------------------------------------------------- #
    def save_identity(self, path: str | os.PathLike[str]) -> None:
        self.identity.save(path)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        label = f" {self.name!r}" if self.name else ""
        return f"<ProximAgent {self.agent_id}{label}>"


def _as_bytes(payload: Optional[Union[bytes, str]]) -> Optional[bytes]:
    if payload is None:
        return None
    if isinstance(payload, str):
        return payload.encode("utf-8")
    return bytes(payload)
