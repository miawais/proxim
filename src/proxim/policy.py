"""Trust policy — turning facts into a yes/no decision.

A :class:`VerificationResult` is a pile of *facts* (signature valid? registered?
revoked? reputation score?). A :class:`TrustPolicy` is the *judgment* applied to
those facts: the thresholds and requirements that decide whether to actually act
on the output. Separating the two means the same verification can be judged by
different policies — strict for money movements, lenient for suggestions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence


@dataclass(frozen=True)
class TrustDecision:
    """The outcome of applying a policy to a verification result."""

    trusted: bool
    reputation: float
    reasons: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.trusted


@dataclass
class TrustPolicy:
    """Rules for deciding whether a verified attestation may be trusted.

    Parameters
    ----------
    min_reputation:
        Minimum reputation score in ``[0, 1]``. Default 0.5.
    require_registered:
        If True, the producing agent must exist in the registry. Default True.
    allow_revoked:
        If False (default), a revoked agent is never trusted.
    require_unexpired:
        If True (default), expired attestations are rejected.
    max_age_seconds:
        If set, reject attestations issued more than this many seconds ago,
        even if they have no explicit expiry.
    required_roles:
        If set, the agent's registry record must carry all of these roles.
    trust_anchor_bypass:
        If True (default), an agent flagged as a trust anchor in the registry is
        trusted as long as its signature is valid and it isn't revoked —
        reputation and role checks are skipped.
    """

    min_reputation: float = 0.5
    require_registered: bool = True
    allow_revoked: bool = False
    require_unexpired: bool = True
    max_age_seconds: Optional[float] = None
    required_roles: Sequence[str] = field(default_factory=tuple)
    trust_anchor_bypass: bool = True

    def evaluate(self, result: "object") -> TrustDecision:
        """Evaluate a :class:`~proxim.verifier.VerificationResult`."""
        reasons: List[str] = []
        reputation = getattr(result, "reputation", 0.0)

        # 1. Cryptographic integrity is non-negotiable.
        if not getattr(result, "signature_valid", False):
            reasons.append("signature invalid")
        if not getattr(result, "identity_consistent", False):
            reasons.append("agent_id does not match public key")
        if getattr(result, "payload_checked", False) and not getattr(
            result, "payload_matches", False
        ):
            reasons.append("payload does not match attestation")

        # 2. Freshness.
        if self.require_unexpired and getattr(result, "expired", False):
            reasons.append("attestation expired")
        age = getattr(result, "age_seconds", None)
        if self.max_age_seconds is not None and age is not None:
            if age > self.max_age_seconds:
                reasons.append(
                    f"attestation too old ({age:.0f}s > {self.max_age_seconds:.0f}s)"
                )

        # 3. Revocation always blocks (unless explicitly allowed).
        if getattr(result, "revoked", False) and not self.allow_revoked:
            reasons.append("agent is revoked")

        # Trust anchors short-circuit standing/quality checks once integrity,
        # freshness, and revocation have passed.
        if (
            self.trust_anchor_bypass
            and getattr(result, "trust_anchor", False)
            and not reasons
        ):
            return TrustDecision(trusted=True, reputation=reputation, reasons=[])

        # 4. Standing in the registry.
        if self.require_registered and not getattr(result, "registered", False):
            reasons.append("agent is not registered")

        # 5. Roles.
        if self.required_roles:
            have = set(getattr(result, "roles", ()) or ())
            missing = [r for r in self.required_roles if r not in have]
            if missing:
                reasons.append(f"missing required roles: {', '.join(missing)}")

        # 6. Reputation threshold.
        if reputation < self.min_reputation:
            reasons.append(
                f"reputation {reputation:.3f} below minimum {self.min_reputation:.3f}"
            )

        return TrustDecision(trusted=not reasons, reputation=reputation, reasons=reasons)
