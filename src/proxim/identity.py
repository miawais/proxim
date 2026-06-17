"""Agent identities — the "who" of Proxim.

A :class:`PublicIdentity` is everything you can safely share: an agent id, its
public key, and some descriptive metadata. A :class:`AgentIdentity` additionally
holds the private key, so it can *sign*. The agent id is derived from the public
key (see :func:`proxim.crypto.agent_id_from_public_key`), which makes identities
self-certifying: possessing a valid signature for an id proves possession of the
matching private key.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

from . import crypto
from .errors import IdentityMismatchError, ProximError


@dataclass(frozen=True)
class PublicIdentity:
    """The shareable, verifying half of an agent identity."""

    agent_id: str
    public_key: bytes
    name: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    created_at: float = 0.0

    def __post_init__(self) -> None:
        expected = crypto.agent_id_from_public_key(self.public_key)
        if self.agent_id != expected:
            raise IdentityMismatchError(
                f"agent_id {self.agent_id!r} does not match public key "
                f"(expected {expected!r})"
            )

    # -- verification ---------------------------------------------------- #
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Return ``True`` iff ``signature`` is valid for ``message``."""
        return crypto.verify(self.public_key, message, signature)

    # -- serialization --------------------------------------------------- #
    @property
    def public_key_b64(self) -> str:
        return crypto.b64u_encode(self.public_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "public_key": self.public_key_b64,
            "name": self.name,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "PublicIdentity":
        return cls(
            agent_id=data["agent_id"],
            public_key=crypto.b64u_decode(data["public_key"]),
            name=data.get("name"),
            metadata=dict(data.get("metadata") or {}),
            created_at=float(data.get("created_at", 0.0)),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> "PublicIdentity":
        return cls.from_dict(json.loads(text))


class AgentIdentity:
    """A full identity, including the private key needed to sign attestations.

    Create one with :meth:`generate`. Persist it with :meth:`save` (the private
    key is written, so protect the file) and reload with :meth:`load`. Share only
    :meth:`public`.
    """

    def __init__(
        self,
        private_key: bytes,
        *,
        name: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        created_at: Optional[float] = None,
    ) -> None:
        crypto._check_len(private_key, crypto.PRIVATE_KEY_LEN, "private key")
        self._private_key = bytes(private_key)
        self._public_key = crypto.public_from_private(self._private_key)
        self.agent_id = crypto.agent_id_from_public_key(self._public_key)
        self.name = name
        self.metadata: dict[str, Any] = dict(metadata or {})
        self.created_at = time.time() if created_at is None else created_at

    # -- construction ---------------------------------------------------- #
    @classmethod
    def generate(
        cls,
        name: Optional[str] = None,
        *,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "AgentIdentity":
        """Generate a brand-new identity with a random keypair."""
        private_raw, _ = crypto.generate_keypair()
        return cls(private_raw, name=name, metadata=metadata)

    # -- signing --------------------------------------------------------- #
    def sign(self, message: bytes) -> bytes:
        """Sign ``message`` with this identity's private key."""
        return crypto.sign(self._private_key, message)

    @property
    def public_key(self) -> bytes:
        return self._public_key

    def public(self) -> PublicIdentity:
        """Return the shareable :class:`PublicIdentity` for this agent."""
        return PublicIdentity(
            agent_id=self.agent_id,
            public_key=self._public_key,
            name=self.name,
            metadata=dict(self.metadata),
            created_at=self.created_at,
        )

    # -- persistence (handle with care: contains the private key) -------- #
    def to_secret_dict(self) -> dict[str, Any]:
        return {
            "version": "proxim-identity/1",
            "agent_id": self.agent_id,
            "private_key": crypto.b64u_encode(self._private_key),
            "name": self.name,
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
        }

    @classmethod
    def from_secret_dict(cls, data: Mapping[str, Any]) -> "AgentIdentity":
        identity = cls(
            crypto.b64u_decode(data["private_key"]),
            name=data.get("name"),
            metadata=dict(data.get("metadata") or {}),
            created_at=float(data.get("created_at", 0.0)) or None,
        )
        declared = data.get("agent_id")
        if declared is not None and declared != identity.agent_id:
            raise IdentityMismatchError(
                f"stored agent_id {declared!r} does not match private key "
                f"(derived {identity.agent_id!r})"
            )
        return identity

    def save(self, path: str | os.PathLike[str]) -> None:
        """Write the identity (including the private key) to ``path`` as JSON.

        On POSIX the file is created with ``0600`` permissions. Treat it like an
        SSH private key.
        """
        data = json.dumps(self.to_secret_dict(), indent=2, sort_keys=True)
        fd = os.open(os.fspath(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(data)
        except Exception:  # pragma: no cover - defensive cleanup
            os.close(fd) if not fd else None
            raise

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "AgentIdentity":
        """Load an identity previously written with :meth:`save`."""
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_secret_dict(json.load(fh))

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        label = f" {self.name!r}" if self.name else ""
        return f"<AgentIdentity {self.agent_id}{label}>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AgentIdentity) and other.agent_id == self.agent_id

    def __hash__(self) -> int:
        return hash(self.agent_id)
