import pytest

from proxim import AgentIdentity, Attestation
from proxim.errors import (
    ExpiredAttestationError,
    PayloadMismatchError,
    SignatureError,
)


@pytest.fixture
def ident():
    return AgentIdentity.generate("producer")


def test_create_and_verify_signature(ident):
    att = Attestation.create(ident, b"the output")
    assert att.verify_signature() is True
    assert att.agent_id == ident.agent_id
    assert att.attestation_id.startswith("att_")


def test_payload_binding(ident):
    att = Attestation.create(ident, b"hello")
    assert att.matches_payload(b"hello") is True
    assert att.matches_payload(b"hell0") is False
    with pytest.raises(PayloadMismatchError):
        att.require_payload(b"nope")


def test_tampered_payload_hash_breaks_signature(ident):
    att = Attestation.create(ident, b"hello")
    data = att.to_dict()
    data["payload_hash"] = "0" * 64
    forged = Attestation.from_dict(data)
    assert forged.verify_signature() is False
    with pytest.raises(SignatureError):
        forged.require_valid_signature()


def test_tampered_claims_break_signature(ident):
    att = Attestation.create(ident, b"x", claims={"model": "opus"})
    data = att.to_dict()
    data["claims"] = {"model": "evil"}
    forged = Attestation.from_dict(data)
    assert forged.verify_signature() is False


def test_swapped_signature_fails(ident):
    other = AgentIdentity.generate()
    att = Attestation.create(ident, b"x")
    other_att = Attestation.create(other, b"x")
    data = att.to_dict()
    data["signature"] = other_att.to_dict()["signature"]
    forged = Attestation.from_dict(data)
    assert forged.verify_signature() is False


def test_expiry(ident):
    att = Attestation.create(ident, b"x", ttl_seconds=100, issued_at=1000.0)
    assert att.is_expired(now=1050.0) is False
    assert att.is_expired(now=1200.0) is True
    att.require_not_expired(now=1050.0)
    with pytest.raises(ExpiredAttestationError):
        att.require_not_expired(now=1200.0)


def test_no_expiry_never_expires(ident):
    att = Attestation.create(ident, b"x")
    assert att.is_expired(now=10**12) is False


def test_json_roundtrip(ident):
    att = Attestation.create(
        ident, b"data", payload_type="text/plain", claims={"k": 1}, parents=["att_a"]
    )
    restored = Attestation.from_json(att.to_json())
    assert restored.attestation_id == att.attestation_id
    assert restored.verify_signature() is True
    assert restored.parents == ["att_a"]
    assert restored.claims == {"k": 1}


def test_str_must_be_encoded(ident):
    with pytest.raises(Exception):
        Attestation.create(ident, "not bytes")  # type: ignore[arg-type]


def test_parents_chain_provenance(ident):
    root = Attestation.create(ident, b"root output")
    child = Attestation.create(ident, b"derived", parents=[root.attestation_id])
    assert child.parents == [root.attestation_id]
    assert child.verify_signature()
