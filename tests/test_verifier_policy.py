import pytest

from proxim import (
    AgentIdentity,
    Attestation,
    InMemoryRegistry,
    ReputationLedger,
    TrustPolicy,
    Verifier,
)
from proxim.errors import UntrustedError


@pytest.fixture
def setup():
    registry = InMemoryRegistry()
    reputation = ReputationLedger()
    producer = AgentIdentity.generate("producer")
    registry.register(producer.public())
    verifier = Verifier(registry=registry, reputation=reputation)
    return registry, reputation, producer, verifier


def test_verify_gathers_facts(setup):
    registry, reputation, producer, verifier = setup
    att = Attestation.create(producer, b"out")
    result = verifier.verify(att, b"out")
    assert result.signature_valid
    assert result.identity_consistent
    assert result.payload_matches
    assert result.registered
    assert not result.revoked


def test_decide_trusts_registered_neutral_agent(setup):
    registry, reputation, producer, verifier = setup
    att = Attestation.create(producer, b"out")
    decision = verifier.decide(att, b"out")
    # neutral reputation 0.5 meets default min_reputation 0.5
    assert decision.trusted, decision.reasons


def test_unregistered_agent_rejected(setup):
    registry, reputation, producer, verifier = setup
    stranger = AgentIdentity.generate("stranger")
    att = Attestation.create(stranger, b"out")
    decision = verifier.decide(att, b"out")
    assert not decision.trusted
    assert any("not registered" in r for r in decision.reasons)


def test_revoked_agent_rejected(setup):
    registry, reputation, producer, verifier = setup
    registry.revoke(producer.agent_id, reason="leak")
    att = Attestation.create(producer, b"out")
    decision = verifier.decide(att, b"out")
    assert not decision.trusted
    assert any("revoked" in r for r in decision.reasons)


def test_low_reputation_rejected(setup):
    registry, reputation, producer, verifier = setup
    for _ in range(10):
        reputation.record_failure(producer.agent_id, at=1000.0)
    att = Attestation.create(producer, b"out", issued_at=1000.0)
    decision = verifier.decide(att, b"out", now=1000.0)
    assert not decision.trusted
    assert any("reputation" in r for r in decision.reasons)


def test_payload_mismatch_rejected(setup):
    registry, reputation, producer, verifier = setup
    att = Attestation.create(producer, b"real output")
    decision = verifier.decide(att, b"different output")
    assert not decision.trusted
    assert any("payload" in r for r in decision.reasons)


def test_expired_rejected(setup):
    registry, reputation, producer, verifier = setup
    att = Attestation.create(producer, b"out", ttl_seconds=10, issued_at=1000.0)
    decision = verifier.decide(att, b"out", now=2000.0)
    assert not decision.trusted
    assert any("expired" in r for r in decision.reasons)


def test_trust_anchor_bypasses_reputation(setup):
    registry, reputation, producer, verifier = setup
    anchor = AgentIdentity.generate("anchor")
    registry.register(anchor.public(), trust_anchor=True)
    for _ in range(10):
        reputation.record_failure(anchor.agent_id, at=1000.0)  # terrible rep
    att = Attestation.create(anchor, b"out", issued_at=1000.0)
    decision = verifier.decide(att, b"out", now=1000.0)
    assert decision.trusted, decision.reasons


def test_required_roles(setup):
    registry, reputation, producer, verifier = setup
    policy = TrustPolicy(required_roles=["planner"])
    att = Attestation.create(producer, b"out")
    decision = verifier.decide(att, b"out", policy=policy)
    assert not decision.trusted
    assert any("roles" in r for r in decision.reasons)

    # now grant the role
    registry.register(producer.public(), roles=["planner"])
    decision2 = verifier.decide(att, b"out", policy=policy)
    assert decision2.trusted, decision2.reasons


def test_accept_raises_when_untrusted(setup):
    registry, reputation, producer, verifier = setup
    stranger = AgentIdentity.generate()
    att = Attestation.create(stranger, b"out")
    with pytest.raises(UntrustedError):
        verifier.accept(att, b"out")


def test_max_age_seconds(setup):
    registry, reputation, producer, verifier = setup
    policy = TrustPolicy(max_age_seconds=60)
    att = Attestation.create(producer, b"out", issued_at=1000.0)
    decision = verifier.decide(att, b"out", policy=policy, now=2000.0)
    assert not decision.trusted
    assert any("too old" in r for r in decision.reasons)
