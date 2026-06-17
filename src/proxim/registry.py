"""The agent registry — Proxim's trust directory.

Signatures prove *consistency* ("this output came from whoever holds this key"),
but not *standing* ("should I have heard of this key at all?"). The registry
answers the second question. It maps agent ids to their public identities and
tracks status: ``active``, ``revoked``. Optionally an agent can be marked a
``trust_anchor`` (a known-good, first-party agent) or carry ``roles``.

Two implementations share one interface:

* :class:`InMemoryRegistry` — ephemeral, ideal for tests and single-process use.
* :class:`JsonFileRegistry` — persists to a JSON file on every mutation.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .errors import IdentityMismatchError, ProximError
from .identity import PublicIdentity

STATUS_ACTIVE = "active"
STATUS_REVOKED = "revoked"


@dataclass
class AgentRecord:
    """A registry entry for a single agent."""

    identity: PublicIdentity
    status: str = STATUS_ACTIVE
    roles: List[str] = field(default_factory=list)
    trust_anchor: bool = False
    registered_at: float = 0.0
    revoked_at: Optional[float] = None
    revocation_reason: Optional[str] = None

    @property
    def agent_id(self) -> str:
        return self.identity.agent_id

    @property
    def is_active(self) -> bool:
        return self.status == STATUS_ACTIVE

    @property
    def is_revoked(self) -> bool:
        return self.status == STATUS_REVOKED

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "status": self.status,
            "roles": list(self.roles),
            "trust_anchor": self.trust_anchor,
            "registered_at": self.registered_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "AgentRecord":
        return cls(
            identity=PublicIdentity.from_dict(data["identity"]),
            status=data.get("status", STATUS_ACTIVE),
            roles=list(data.get("roles") or []),
            trust_anchor=bool(data.get("trust_anchor", False)),
            registered_at=float(data.get("registered_at", 0.0)),
            revoked_at=(
                None if data.get("revoked_at") is None else float(data["revoked_at"])
            ),
            revocation_reason=data.get("revocation_reason"),
        )


class InMemoryRegistry:
    """An in-process registry of agent records keyed by agent id."""

    def __init__(self) -> None:
        self._records: Dict[str, AgentRecord] = {}

    # -- mutations ------------------------------------------------------- #
    def register(
        self,
        identity: PublicIdentity,
        *,
        roles: Optional[Iterable[str]] = None,
        trust_anchor: bool = False,
        registered_at: Optional[float] = None,
    ) -> AgentRecord:
        """Add (or replace) a record for ``identity``.

        The public identity is self-validating (its constructor checks that the
        agent id matches the key), so a forged id can never be registered.
        """
        if not isinstance(identity, PublicIdentity):
            raise ProximError("register() expects a PublicIdentity")
        record = AgentRecord(
            identity=identity,
            roles=list(roles or []),
            trust_anchor=trust_anchor,
            registered_at=time.time() if registered_at is None else registered_at,
        )
        self._records[identity.agent_id] = record
        self._persist()
        return record

    def revoke(self, agent_id: str, reason: Optional[str] = None) -> AgentRecord:
        """Mark an agent as revoked. Raises ``KeyError`` if unknown."""
        record = self._records[agent_id]
        record.status = STATUS_REVOKED
        record.revoked_at = time.time()
        record.revocation_reason = reason
        self._persist()
        return record

    def remove(self, agent_id: str) -> None:
        """Delete a record entirely (rarely what you want — prefer revoke)."""
        self._records.pop(agent_id, None)
        self._persist()

    # -- queries --------------------------------------------------------- #
    def get(self, agent_id: str) -> Optional[AgentRecord]:
        return self._records.get(agent_id)

    def contains(self, agent_id: str) -> bool:
        return agent_id in self._records

    def is_revoked(self, agent_id: str) -> bool:
        record = self._records.get(agent_id)
        return bool(record and record.is_revoked)

    def is_trusted_anchor(self, agent_id: str) -> bool:
        record = self._records.get(agent_id)
        return bool(record and record.trust_anchor and record.is_active)

    def all(self) -> List[AgentRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, agent_id: object) -> bool:
        return agent_id in self._records

    # -- serialization --------------------------------------------------- #
    def to_dict(self) -> dict[str, Any]:
        return {
            "version": "proxim-registry/1",
            "records": [r.to_dict() for r in self._records.values()],
        }

    def load_dict(self, data: Mapping[str, Any]) -> None:
        self._records = {}
        for raw in data.get("records", []):
            record = AgentRecord.from_dict(raw)
            self._records[record.agent_id] = record

    # -- hook for persistent subclasses ---------------------------------- #
    def _persist(self) -> None:  # pragma: no cover - no-op in base class
        pass


class JsonFileRegistry(InMemoryRegistry):
    """An :class:`InMemoryRegistry` that mirrors itself to a JSON file.

    The file is loaded on construction (if it exists) and rewritten atomically
    after every mutation, so the on-disk copy always reflects the latest state.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        super().__init__()
        self.path = os.fspath(path)
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self.load_dict(json.load(fh))

    def _persist(self) -> None:
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)
