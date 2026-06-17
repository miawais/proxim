"""A full multi-agent scenario exercising all three pillars together."""

import proxim
from proxim import ProximAgent, InMemoryRegistry, ReputationLedger


def test_two_agents_share_trust_fabric():
    # A shared registry + ledger model a single trust domain.
    registry = InMemoryRegistry()
    reputation = ReputationLedger()

    alice = ProximAgent.create("alice", registry=registry, reputation=reputation)
    bob = ProximAgent.create("bob", registry=registry, reputation=reputation)

    # Alice produces an output and attests it.
    output = b'{"plan": "ship it"}'
    att = alice.attest(output, payload_type="application/json", claims={"model": "opus"})

    # Bob receives (output, attestation) and decides whether to trust.
    decision = bob.trust(att, output)
    assert decision.trusted, decision.reasons

    # Bob acts, the result is good -> positive feedback raises Alice's reputation.
    before = bob.reputation_of(alice.agent_id)
    bob.give_feedback(att, proxim.GOOD)
    after = bob.reputation_of(alice.agent_id)
    assert after > before


def test_impersonation_is_detected():
    registry = InMemoryRegistry()
    reputation = ReputationLedger()
    alice = ProximAgent.create("alice", registry=registry, reputation=reputation)
    bob = ProximAgent.create("bob", registry=registry, reputation=reputation)

    # An attacker tries to pass off their own output as Alice's by editing the id.
    attacker = proxim.AgentIdentity.generate("attacker")
    att = proxim.Attestation.create(attacker, b"malicious")
    forged = proxim.Attestation.from_dict({**att.to_dict(), "agent_id": alice.agent_id})

    decision = bob.trust(forged, b"malicious")
    assert not decision.trusted  # id no longer matches the signing key


def test_tampered_output_breaks_trust():
    alice = ProximAgent.create("alice")
    bob = ProximAgent.create(
        "bob", registry=alice.registry, reputation=alice.reputation
    )
    att = alice.attest(b"original")
    # Bob is handed a tampered payload but the original attestation.
    decision = bob.trust(att, b"tampered")
    assert not decision.trusted


def test_reputation_gates_repeated_bad_actor():
    registry = InMemoryRegistry()
    reputation = ReputationLedger()
    flaky = ProximAgent.create("flaky", registry=registry, reputation=reputation)
    judge = ProximAgent.create("judge", registry=registry, reputation=reputation)

    # First few outputs are trusted (neutral start), but feedback is bad.
    for i in range(8):
        att = flaky.attest(f"output-{i}".encode(), issued_at=1000.0)
        judge.give_feedback(att, proxim.BAD, at=1000.0)

    # Eventually the agent's reputation drops below the policy threshold.
    final = flaky.attest(b"final", issued_at=1000.0)
    decision = judge.trust(final, b"final", now=1000.0)
    assert not decision.trusted
    assert any("reputation" in r for r in decision.reasons)


def test_provenance_chain():
    registry = InMemoryRegistry()
    reputation = ReputationLedger()
    researcher = ProximAgent.create("researcher", registry=registry, reputation=reputation)
    writer = ProximAgent.create("writer", registry=registry, reputation=reputation)

    research = researcher.attest(b"raw findings")
    # Writer derives its output from the researcher's, recording provenance.
    article = writer.attest(b"polished article", parents=[research.attestation_id])

    assert article.parents == [research.attestation_id]
    # Both links of the chain verify independently.
    assert writer.verify(article, b"polished article").cryptographically_valid
    assert researcher.verify(research, b"raw findings").cryptographically_valid
