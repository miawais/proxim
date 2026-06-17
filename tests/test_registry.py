from proxim import AgentIdentity, InMemoryRegistry, JsonFileRegistry
from proxim.registry import STATUS_REVOKED


def test_register_and_get():
    reg = InMemoryRegistry()
    ident = AgentIdentity.generate("a")
    record = reg.register(ident.public(), roles=["planner"], trust_anchor=True)
    assert reg.contains(ident.agent_id)
    assert record.roles == ["planner"]
    assert reg.is_trusted_anchor(ident.agent_id)
    assert reg.get(ident.agent_id).identity.name == "a"


def test_revoke():
    reg = InMemoryRegistry()
    ident = AgentIdentity.generate()
    reg.register(ident.public())
    assert not reg.is_revoked(ident.agent_id)
    rec = reg.revoke(ident.agent_id, reason="key leaked")
    assert rec.status == STATUS_REVOKED
    assert reg.is_revoked(ident.agent_id)
    assert rec.revocation_reason == "key leaked"
    # revoked anchor is no longer a trusted anchor
    assert not reg.is_trusted_anchor(ident.agent_id)


def test_unknown_agent():
    reg = InMemoryRegistry()
    assert reg.get("px_missing") is None
    assert not reg.is_revoked("px_missing")


def test_json_file_registry_persists(tmp_path):
    path = tmp_path / "registry.json"
    reg = JsonFileRegistry(path)
    ident = AgentIdentity.generate("persisted")
    reg.register(ident.public(), roles=["x"])
    reg.revoke(ident.agent_id, reason="rotate")

    reloaded = JsonFileRegistry(path)
    rec = reloaded.get(ident.agent_id)
    assert rec is not None
    assert rec.is_revoked
    assert rec.roles == ["x"]
    assert rec.identity.public_key == ident.public_key
