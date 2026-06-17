"""Quickstart: one agent attests an output, another verifies and trusts it.

Run:  python examples/01_quickstart.py
"""

import proxim
from proxim import ProximAgent, InMemoryRegistry, ReputationLedger

# A shared registry + ledger = one trust domain that both agents participate in.
registry = InMemoryRegistry()
reputation = ReputationLedger()

alice = ProximAgent.create("alice", registry=registry, reputation=reputation)
bob = ProximAgent.create("bob", registry=registry, reputation=reputation)

print(f"alice = {alice.agent_id}")
print(f"bob   = {bob.agent_id}\n")

# Alice produces an output and attaches a tamper-evident attestation.
output = b'{"recommendation": "approve loan", "confidence": 0.91}'
att = alice.attest(output, payload_type="application/json", claims={"model": "opus-4.8"})
print("Alice attested an output:")
print(f"  attestation_id = {att.attestation_id}")
print(f"  payload_hash   = {att.payload_hash[:24]}...\n")

# Bob receives (output, attestation) over the wire and decides whether to trust.
decision = bob.trust(att, output)
print(f"Bob's trust decision: trusted={decision.trusted} "
      f"reputation={decision.reputation:.3f}")
if not decision.trusted:
    print("  reasons:", decision.reasons)

# Bob acted on it and it turned out well -> reputation feedback.
bob.give_feedback(att, proxim.GOOD, note="loan approval was correct")
print(f"\nAfter positive feedback, alice's reputation = "
      f"{bob.reputation_of(alice.agent_id):.3f}")
