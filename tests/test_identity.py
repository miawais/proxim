import pytest

from proxim import AgentIdentity, PublicIdentity, crypto
from proxim.errors import IdentityMismatchError


def test_generate_and_public():
    ident = AgentIdentity.generate("alice", metadata={"team": "research"})
    pub = ident.public()
    assert isinstance(pub, PublicIdentity)
    assert pub.agent_id == ident.agent_id
    assert pub.name == "alice"
    assert pub.metadata["team"] == "research"


def test_sign_and_verify_through_public_identity():
    ident = AgentIdentity.generate()
    sig = ident.sign(b"payload")
    assert ident.public().verify(b"payload", sig) is True
    assert ident.public().verify(b"other", sig) is False


def test_public_identity_rejects_forged_agent_id():
    _, pub = crypto.generate_keypair()
    with pytest.raises(IdentityMismatchError):
        PublicIdentity(agent_id="px_not_the_real_id", public_key=pub)


def test_public_identity_dict_roundtrip():
    pub = AgentIdentity.generate("bob").public()
    restored = PublicIdentity.from_dict(pub.to_dict())
    assert restored.agent_id == pub.agent_id
    assert restored.public_key == pub.public_key
    assert restored.name == "bob"


def test_secret_dict_roundtrip_preserves_key():
    ident = AgentIdentity.generate("carol")
    restored = AgentIdentity.from_secret_dict(ident.to_secret_dict())
    assert restored.agent_id == ident.agent_id
    # same private key => identical signatures are verifiable cross-wise
    sig = restored.sign(b"x")
    assert ident.public().verify(b"x", sig)


def test_save_and_load_identity(tmp_path):
    ident = AgentIdentity.generate("dave")
    path = tmp_path / "dave.json"
    ident.save(path)
    loaded = AgentIdentity.load(path)
    assert loaded.agent_id == ident.agent_id
    assert loaded.name == "dave"


def test_secret_dict_detects_tampered_agent_id():
    ident = AgentIdentity.generate()
    data = ident.to_secret_dict()
    data["agent_id"] = "px_tampered"
    with pytest.raises(IdentityMismatchError):
        AgentIdentity.from_secret_dict(data)
