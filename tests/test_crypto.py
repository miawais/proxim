import pytest

from proxim import crypto
from proxim.errors import CryptoError


def test_keypair_roundtrip_sign_verify():
    priv, pub = crypto.generate_keypair()
    assert len(priv) == crypto.PRIVATE_KEY_LEN
    assert len(pub) == crypto.PUBLIC_KEY_LEN

    msg = b"attest this"
    sig = crypto.sign(priv, msg)
    assert len(sig) == crypto.SIGNATURE_LEN
    assert crypto.verify(pub, msg, sig) is True


def test_verify_rejects_tampered_message():
    priv, pub = crypto.generate_keypair()
    sig = crypto.sign(priv, b"hello")
    assert crypto.verify(pub, b"hell0", sig) is False


def test_public_from_private_is_deterministic():
    priv, pub = crypto.generate_keypair()
    assert crypto.public_from_private(priv) == pub


def test_agent_id_is_stable_and_prefixed():
    _, pub = crypto.generate_keypair()
    aid = crypto.agent_id_from_public_key(pub)
    assert aid.startswith(crypto.AGENT_ID_PREFIX)
    assert crypto.agent_id_from_public_key(pub) == aid  # deterministic
    # 'px_' + 32 base32 chars
    assert len(aid) == len(crypto.AGENT_ID_PREFIX) + 32


def test_different_keys_get_different_ids():
    _, pub1 = crypto.generate_keypair()
    _, pub2 = crypto.generate_keypair()
    assert crypto.agent_id_from_public_key(pub1) != crypto.agent_id_from_public_key(pub2)


def test_b64u_roundtrip():
    data = bytes(range(50))
    assert crypto.b64u_decode(crypto.b64u_encode(data)) == data


def test_verify_rejects_bad_lengths():
    with pytest.raises(CryptoError):
        crypto.verify(b"short", b"m", b"x" * 64)
    with pytest.raises(CryptoError):
        crypto.sign(b"short", b"m")


def test_require_valid_signature_raises():
    from proxim.errors import SignatureError

    priv, pub = crypto.generate_keypair()
    sig = crypto.sign(priv, b"a")
    with pytest.raises(SignatureError):
        crypto.require_valid_signature(pub, b"b", sig)
