"""Cryptographic primitives used throughout Proxim.

Proxim uses **Ed25519** for signatures: small keys (32 bytes), small signatures
(64 bytes), fast verification, and no parameter choices to get wrong. This
module wraps the ``cryptography`` library and adds the encoding helpers
(base64url, base32 fingerprints) that the rest of the package relies on.

Keeping every crypto detail in one place means the higher-level modules
(identity, attestation, verifier) never touch raw key material directly.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import CryptoError, SignatureError

# Length, in bytes, of raw Ed25519 keys and signatures.
PRIVATE_KEY_LEN = 32
PUBLIC_KEY_LEN = 32
SIGNATURE_LEN = 64

# Number of bytes of the SHA-256 public-key digest used in an agent id.
# 20 bytes = 160 bits, which base32-encodes to exactly 32 chars with no padding.
_FINGERPRINT_BYTES = 20
AGENT_ID_PREFIX = "px_"


# --------------------------------------------------------------------------- #
# Base64url helpers (URL-safe, unpadded — friendly inside JSON and URLs).
# --------------------------------------------------------------------------- #
def b64u_encode(data: bytes) -> str:
    """Encode bytes as unpadded URL-safe base64."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Decode unpadded URL-safe base64 back to bytes."""
    pad = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + pad)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise CryptoError(f"invalid base64url value: {text!r}") from exc


# --------------------------------------------------------------------------- #
# Hashing.
# --------------------------------------------------------------------------- #
def sha256(data: bytes) -> bytes:
    """Return the raw SHA-256 digest of ``data``."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- #
# Key generation / serialization.
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair as ``(private_raw, public_raw)`` bytes."""
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes_raw()
    public_raw = private.public_key().public_bytes_raw()
    return private_raw, public_raw


def public_from_private(private_raw: bytes) -> bytes:
    """Derive the raw public key from a raw private key."""
    _check_len(private_raw, PRIVATE_KEY_LEN, "private key")
    private = Ed25519PrivateKey.from_private_bytes(private_raw)
    return private.public_key().public_bytes_raw()


# --------------------------------------------------------------------------- #
# Sign / verify.
# --------------------------------------------------------------------------- #
def sign(private_raw: bytes, message: bytes) -> bytes:
    """Sign ``message`` with the raw private key, returning a 64-byte signature."""
    _check_len(private_raw, PRIVATE_KEY_LEN, "private key")
    private = Ed25519PrivateKey.from_private_bytes(private_raw)
    return private.sign(message)


def verify(public_raw: bytes, message: bytes, signature: bytes) -> bool:
    """Return ``True`` iff ``signature`` is valid for ``message`` under the key.

    Never raises on an invalid signature — returns ``False`` instead — so it is
    safe to use in boolean trust checks. It *does* raise :class:`CryptoError`
    for structurally invalid key/signature lengths, which indicate a bug or
    corrupted record rather than a forgery attempt.
    """
    _check_len(public_raw, PUBLIC_KEY_LEN, "public key")
    if len(signature) != SIGNATURE_LEN:
        raise CryptoError(
            f"signature must be {SIGNATURE_LEN} bytes, got {len(signature)}"
        )
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def require_valid_signature(public_raw: bytes, message: bytes, signature: bytes) -> None:
    """Like :func:`verify` but raise :class:`SignatureError` on failure."""
    if not verify(public_raw, message, signature):
        raise SignatureError("signature verification failed")


# --------------------------------------------------------------------------- #
# Agent-id fingerprints.
# --------------------------------------------------------------------------- #
def agent_id_from_public_key(public_raw: bytes) -> str:
    """Derive a self-certifying agent id from a raw public key.

    The id is ``px_`` followed by the lowercase base32 of the first 160 bits of
    ``SHA-256(public_key)``. Because the id is a function of the key, an agent
    cannot claim an id it does not hold the private key for — identity is
    cryptographic, not merely assigned.
    """
    _check_len(public_raw, PUBLIC_KEY_LEN, "public key")
    digest = sha256(public_raw)[:_FINGERPRINT_BYTES]
    body = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
    return AGENT_ID_PREFIX + body


def _check_len(value: bytes, expected: int, label: str) -> None:
    if not isinstance(value, (bytes, bytearray)):
        raise CryptoError(f"{label} must be bytes, got {type(value).__name__}")
    if len(value) != expected:
        raise CryptoError(f"{label} must be {expected} bytes, got {len(value)}")
