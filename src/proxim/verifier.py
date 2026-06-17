"""The verifier — the component an agent calls before trusting another's output.

This is where the three pillars converge. Given an attestation (and optionally
the payload it covers), the verifier asks:

1. **Crypto** — is the signature valid and the id consistent with the key?
2. **Payload** — does the output in hand match the hash that was signed?
3. **Freshness** — is it expired / too old?
4. **Registry** — is the producer registered? revoked? what roles / anchor?
5. **Reputation** — how has this agent's output held up over time?

It returns a :class:`VerificationResult` of pure facts, then a
:class:`~proxim.policy.TrustPolicy` turns those facts into a
:class:`~proxim.policy.TrustDecision`. The whole thing is designed to run in
milliseconds with no network calls (the public key travels inside the
attestation; the registry and ledger are local).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from .attestation import Attestation
from .errors import UntrustedError
from .policy import TrustDecision, TrustPolicy
from .registry import InMemoryRegistry
from .reputation import ReputationLedger


@dataclass
class VerificationResult:
    """The factual findings about a single attestation. No judgment applied."""

    attestation: Attestation

    # crypto
    signature_valid: bool = False
    identity_consistent: bool = False

    # payload
    payload_checked: bool = False
    payload_matches: bool = False

    # freshness
    expired: bool = False
    age_seconds: Optional[float] = None

    # registry standing
    registered: bool = False
    revoked: bool = False
    trust_anchor: bool = False
    roles: List[str] = field(default_factory=list)

    # reputation
    reputation: float = 0.0
    reputation_samples: int = 0

    @property
    def cryptographically_valid(self) -> bool:
        """True iff the signature is valid and the id matches the key."""
        return self.signature_valid and self.identity_consistent


class Verifier:
    """Bundles a registry, a reputation ledger, and a default policy."""

    def __init__(
        self,
        registry: Optional[InMemoryRegistry] = None,
        reputation: Optional[ReputationLedger] = None,
        policy: Optional[TrustPolicy] = None,
    ) -> None:
        self.registry = registry if registry is not None else InMemoryRegistry()
        self.reputation = reputation if reputation is not None else ReputationLedger()
        self.policy = policy if policy is not None else TrustPolicy()

    # ------------------------------------------------------------------ #
    # Fact gathering
    # ------------------------------------------------------------------ #
    def verify(
        self,
        attestation: Attestation,
        payload: Optional[bytes] = None,
        *,
        now: Optional[float] = None,
    ) -> VerificationResult:
        """Gather all verification facts about ``attestation``.

        If ``payload`` is provided, the output-to-hash binding is checked too;
        omitting it means you trust the hash but haven't seen the bytes.
        """
        now = time.time() if now is None else now
        result = VerificationResult(attestation=attestation)

        # 1. Cryptographic integrity.
        result.identity_consistent = (
            attestation.agent_id
            == _agent_id_of(attestation)
        )
        result.signature_valid = attestation.verify_signature()

        # 2. Payload binding.
        if payload is not None:
            result.payload_checked = True
            result.payload_matches = attestation.matches_payload(payload)

        # 3. Freshness.
        result.expired = attestation.is_expired(now)
        result.age_seconds = attestation.age_seconds(now)

        # 4. Registry standing.
        record = self.registry.get(attestation.agent_id)
        if record is not None:
            result.registered = True
            result.revoked = record.is_revoked
            result.trust_anchor = record.trust_anchor and record.is_active
            result.roles = list(record.roles)

        # 5. Reputation.
        score = self.reputation.score(attestation.agent_id, now=now)
        result.reputation = score.value
        result.reputation_samples = score.sample_count

        return result

    # ------------------------------------------------------------------ #
    # Judgment
    # ------------------------------------------------------------------ #
    def decide(
        self,
        attestation: Attestation,
        payload: Optional[bytes] = None,
        *,
        policy: Optional[TrustPolicy] = None,
        now: Optional[float] = None,
    ) -> TrustDecision:
        """Verify, then apply a policy, returning a :class:`TrustDecision`."""
        result = self.verify(attestation, payload, now=now)
        return (policy or self.policy).evaluate(result)

    def accept(
        self,
        attestation: Attestation,
        payload: Optional[bytes] = None,
        *,
        policy: Optional[TrustPolicy] = None,
        now: Optional[float] = None,
    ) -> TrustDecision:
        """Like :meth:`decide` but raise :class:`UntrustedError` if not trusted.

        Use this at the point where you are about to *act* on another agent's
        output and want a hard guarantee.
        """
        decision = self.decide(attestation, payload, policy=policy, now=now)
        if not decision.trusted:
            raise UntrustedError(
                "attestation not trusted: " + "; ".join(decision.reasons),
                decision=decision,
            )
        return decision


def _agent_id_of(attestation: Attestation) -> str:
    """Recompute the agent id from the attestation's embedded public key."""
    from . import crypto

    return crypto.agent_id_from_public_key(attestation.public_key)
