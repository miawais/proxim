"""Proxim — trust infrastructure for AI agents.

Three pillars, one import:

* **Identity** — every agent has a cryptographic, self-certifying identity
  (:class:`AgentIdentity` / :class:`PublicIdentity`).
* **Attestation** — every output carries a signed, tamper-evident record
  (:class:`Attestation`).
* **Reputation** — every agent accrues a trust score from how its outputs have
  held up (:class:`ReputationLedger`).

A :class:`Verifier` (or the friendlier :class:`ProximAgent`) checks an incoming
attestation against a :class:`~proxim.registry.InMemoryRegistry` and the ledger,
and a :class:`TrustPolicy` turns the findings into a :class:`TrustDecision`.

Quick start::

    import proxim

    alice = proxim.ProximAgent.create("alice")
    att = alice.attest("hello world")

    bob = proxim.ProximAgent.create("bob", registry=alice.registry,
                                    reputation=alice.reputation)
    decision = bob.trust(att, "hello world")
    assert decision.trusted
"""

from __future__ import annotations

from .agent import ProximAgent
from .attestation import ATTESTATION_VERSION, Attestation
from .errors import (
    CryptoError,
    ExpiredAttestationError,
    IdentityMismatchError,
    PayloadMismatchError,
    ProximError,
    RevokedAgentError,
    SignatureError,
    UnknownAgentError,
    UntrustedError,
)
from .identity import AgentIdentity, PublicIdentity
from .policy import TrustDecision, TrustPolicy
from .registry import (
    STATUS_ACTIVE,
    STATUS_REVOKED,
    AgentRecord,
    InMemoryRegistry,
    JsonFileRegistry,
)
from .reputation import (
    BAD,
    GOOD,
    NEUTRAL,
    FeedbackEvent,
    JsonFileLedger,
    ReputationLedger,
    ReputationScore,
)
from .verifier import VerificationResult, Verifier
from .version import __version__

__all__ = [
    "__version__",
    # high-level
    "ProximAgent",
    # identity
    "AgentIdentity",
    "PublicIdentity",
    # attestation
    "Attestation",
    "ATTESTATION_VERSION",
    # registry
    "InMemoryRegistry",
    "JsonFileRegistry",
    "AgentRecord",
    "STATUS_ACTIVE",
    "STATUS_REVOKED",
    # reputation
    "ReputationLedger",
    "JsonFileLedger",
    "ReputationScore",
    "FeedbackEvent",
    "GOOD",
    "BAD",
    "NEUTRAL",
    # verify + policy
    "Verifier",
    "VerificationResult",
    "TrustPolicy",
    "TrustDecision",
    # errors
    "ProximError",
    "CryptoError",
    "SignatureError",
    "IdentityMismatchError",
    "PayloadMismatchError",
    "ExpiredAttestationError",
    "UnknownAgentError",
    "RevokedAgentError",
    "UntrustedError",
]
