"""Show the three failure modes Proxim is designed to catch.

Run:  python examples/02_attacks_detected.py
"""

import proxim
from proxim import ProximAgent, Attestation, AgentIdentity, InMemoryRegistry, ReputationLedger

registry = InMemoryRegistry()
reputation = ReputationLedger()
alice = ProximAgent.create("alice", registry=registry, reputation=reputation)
bob = ProximAgent.create("bob", registry=registry, reputation=reputation)

print("1) Tampered output")
att = alice.attest(b"transfer $100")
d = bob.trust(att, b"transfer $1000000")  # payload changed in flight
print(f"   trusted={d.trusted}  reasons={d.reasons}\n")

print("2) Impersonation (attacker claims Alice's id)")
attacker = AgentIdentity.generate("attacker")
mal = Attestation.create(attacker, b"do something bad")
forged = Attestation.from_dict({**mal.to_dict(), "agent_id": alice.agent_id})
d = bob.trust(forged, b"do something bad")
print(f"   trusted={d.trusted}  reasons={d.reasons}\n")

print("3) Revoked agent (key was leaked and rotated out)")
registry.revoke(alice.agent_id, reason="key compromised")
att2 = alice.attest(b"still trying")
d = bob.trust(att2, b"still trying")
print(f"   trusted={d.trusted}  reasons={d.reasons}")
