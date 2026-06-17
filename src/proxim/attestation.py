"""Attestations — the "what" of Proxim.

An :class:`Attestation` is a signed statement of the form *"agent X produced an
output whose SHA-256 is H, at time T"*, plus optional structured ``claims`` and
a ``parents`` provenance chain linking it to the attestations it was derived
from. Because it is signed over canonical bytes, any change to the output or to
the metadata invalidates it — that is the "tamper-evident" property.

The attestation deliberately carries the producer's ``public_key`` so it can be
verified *standalone*, without a registry round-trip. A registry then adds the
orthogonal questions of *"is this key registered?"* and *"has it been
revoked?"*.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from . import crypto
from ._canonical import canonical_bytes
from .errors import (
    ExpiredAttestationError,
    IdentityMismatchError,
    PayloadMismatchError,
    ProximError,
    SignatureError,
)
from .identity import AgentIdentity

ATTESTATION_VERSION = "proxim-attestation/1"

# Fields that make up the signed body, in no particular order (canonical_bytes
# sorts them). The signature and the derived attestation_id are intentionally
# excluded — they are computed *from* this body.
_BODY_FIELDS = (
    "version",
    "agent_id",
    "public_key",
    "payload_hash",
    "payload_type",
    "claims",
    "parents",
    "issued_at",
    "expires_at",
    "nonce",
)


@dataclass(frozen=True)
class Attestation:
    """A signed, tamper-evident record describing an agent's output."""

    version: str
    agent_id: str
    public_key: bytes
    payload_hash: str  # hex SHA-256 of the payload bytes
    payload_type: Optional[str]
    claims: Mapping[str, Any]
    parents: Sequence[str]
    issued_at: float
    expires_at: Optional[float]
    nonce: str
    signature: bytes
    attestation_id: str

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def create(
        cls,
        identity: AgentIdentity,
        payload: bytes,
        *,
        payload_type: Optional[str] = None,
        claims: Optional[Mapping[str, Any]] = None,
        parents: Optional[Sequence[str]] = None,
        ttl_seconds: Optional[float] = None,
        issued_at: Optional[float] = None,
    ) -> "Attestation":
        """Sign ``payload`` with ``identity`` and return an attestation.

        ``payload`` is hashed, not stored; the raw output never lives inside the
        attestation. ``ttl_seconds`` sets ``expires_at`` relative to issue time.
        ``parents`` is a list of attestation ids this output was derived from,
        forming an auditable provenance chain.
        """
        if not isinstance(payload, (bytes, bytearray)):
            raise ProximError("payload must be bytes; encode text before attesting")

        issued = time.time() if issued_at is None else issued_at
        expires = None if ttl_seconds is None else issued + ttl_seconds

        body = {
            "version": ATTESTATION_VERSION,
            "agent_id": identity.agent_id,
            "public_key": crypto.b64u_encode(identity.public_key),
            "payload_hash": crypto.sha256_hex(bytes(payload)),
            "payload_type": payload_type,
            "claims": dict(claims or {}),
            "parents": list(parents or []),
            "issued_at": issued,
            "expires_at": expires,
            "nonce": crypto.b64u_encode(os.urandom(16)),
        }

        signing_bytes = canonical_bytes(body)
        signature = identity.sign(signing_bytes)
        attestation_id = "att_" + crypto.b64u_encode(crypto.sha256(signing_bytes))

        return cls(
            version=body["version"],
            agent_id=body["agent_id"],
            public_key=identity.public_key,
            payload_hash=body["payload_hash"],
            payload_type=body["payload_type"],
            claims=body["claims"],
            parents=body["parents"],
            issued_at=body["issued_at"],
            expires_at=body["expires_at"],
            nonce=body["nonce"],
            signature=signature,
            attestation_id=attestation_id,
        )

    # ------------------------------------------------------------------ #
    # The exact bytes that were signed (used by both signing and verifying)
    # ------------------------------------------------------------------ #
    def _signing_bytes(self) -> bytes:
        body = {
            "version": self.version,
            "agent_id": self.agent_id,
            "public_key": crypto.b64u_encode(self.public_key),
            "payload_hash": self.payload_hash,
            "payload_type": self.payload_type,
            "claims": dict(self.claims),
            "parents": list(self.parents),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }
        return canonical_bytes(body)

    # ------------------------------------------------------------------ #
    # Verification primitives (each answers one orthogonal question)
    # ------------------------------------------------------------------ #
    def verify_signature(self) -> bool:
        """Return ``True`` iff the signature is valid and the id matches the key.

        This is the standalone, registry-free check. It proves the attestation
        was produced by the holder of the private key for ``public_key`` and has
        not been altered since.
        """
        if crypto.agent_id_from_public_key(self.public_key) != self.agent_id:
            return False
        expected_id = "att_" + crypto.b64u_encode(crypto.sha256(self._signing_bytes()))
        if expected_id != self.attestation_id:
            return False
        return crypto.verify(self.public_key, self._signing_bytes(), self.signature)

    def require_valid_signature(self) -> None:
        """Raise :class:`SignatureError`/:class:`IdentityMismatchError` if invalid."""
        if crypto.agent_id_from_public_key(self.public_key) != self.agent_id:
            raise IdentityMismatchError(
                "attestation agent_id does not match its public key"
            )
        if not self.verify_signature():
            raise SignatureError("attestation signature verification failed")

    def matches_payload(self, payload: bytes) -> bool:
        """Return ``True`` iff ``payload`` hashes to this attestation's hash."""
        return crypto.sha256_hex(bytes(payload)) == self.payload_hash

    def require_payload(self, payload: bytes) -> None:
        """Raise :class:`PayloadMismatchError` if ``payload`` doesn't match."""
        if not self.matches_payload(payload):
            raise PayloadMismatchError(
                "payload does not match attestation payload_hash"
            )

    def is_expired(self, now: Optional[float] = None) -> bool:
        """Return ``True`` iff the attestation has an ``expires_at`` in the past."""
        if self.expires_at is None:
            return False
        now = time.time() if now is None else now
        return now > self.expires_at

    def require_not_expired(self, now: Optional[float] = None) -> None:
        """Raise :class:`ExpiredAttestationError` if expired."""
        if self.is_expired(now):
            raise ExpiredAttestationError(
                f"attestation expired at {self.expires_at}"
            )

    def age_seconds(self, now: Optional[float] = None) -> float:
        """Seconds elapsed since the attestation was issued."""
        now = time.time() if now is None else now
        return now - self.issued_at

    # ------------------------------------------------------------------ #
    # Serialization
    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "agent_id": self.agent_id,
            "public_key": crypto.b64u_encode(self.public_key),
            "payload_hash": self.payload_hash,
            "payload_type": self.payload_type,
            "claims": dict(self.claims),
            "parents": list(self.parents),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "signature": crypto.b64u_encode(self.signature),
            "attestation_id": self.attestation_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Attestation":
        return cls(
            version=data["version"],
            agent_id=data["agent_id"],
            public_key=crypto.b64u_decode(data["public_key"]),
            payload_hash=data["payload_hash"],
            payload_type=data.get("payload_type"),
            claims=dict(data.get("claims") or {}),
            parents=list(data.get("parents") or []),
            issued_at=float(data["issued_at"]),
            expires_at=(
                None if data.get("expires_at") is None else float(data["expires_at"])
            ),
            nonce=data["nonce"],
            signature=crypto.b64u_decode(data["signature"]),
            attestation_id=data["attestation_id"],
        )

    def to_json(self, *, indent: Optional[int] = None) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "Attestation":
        return cls.from_dict(json.loads(text))

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"<Attestation {self.attestation_id} by {self.agent_id} "
            f"hash={self.payload_hash[:12]}…>"
        )
