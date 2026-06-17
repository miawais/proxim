"""Exception hierarchy for Proxim.

Every error raised by the library derives from :class:`ProximError`, so callers
can catch the whole family with a single ``except``. The more specific
subclasses let security-sensitive code distinguish *why* trust failed (a bad
signature is a very different situation from a low reputation score).
"""

from __future__ import annotations


class ProximError(Exception):
    """Base class for all Proxim errors."""


class CryptoError(ProximError):
    """A cryptographic primitive failed or received malformed input."""


class SignatureError(CryptoError):
    """An attestation's signature did not verify against its public key."""


class IdentityMismatchError(ProximError):
    """The ``agent_id`` does not match the fingerprint of the public key.

    Agent ids in Proxim are derived from the public key, so a mismatch means the
    record was tampered with or constructed incorrectly.
    """


class PayloadMismatchError(ProximError):
    """The payload presented does not match the hash inside the attestation."""


class ExpiredAttestationError(ProximError):
    """The attestation's ``expires_at`` is in the past."""


class UnknownAgentError(ProximError):
    """The agent is not present in the registry."""


class RevokedAgentError(ProximError):
    """The agent's registry record has been revoked."""


class UntrustedError(ProximError):
    """A trust policy refused to trust an otherwise-valid attestation.

    The attached :class:`~proxim.policy.TrustDecision` explains the reasons.
    """

    def __init__(self, message: str, decision: "object" = None) -> None:
        super().__init__(message)
        self.decision = decision
