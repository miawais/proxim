# Proxim Protocol Specification (v1)

This document defines the wire formats and verification rules of Proxim. The
reference implementation lives in [`src/proxim`](src/proxim).

## 1. Cryptography

* **Signatures:** Ed25519 (RFC 8032). Public/private keys are 32 bytes raw;
  signatures are 64 bytes.
* **Hashing:** SHA-256.
* **Binary encoding in JSON:** unpadded URL-safe Base64 (`base64url`).
* **Canonical bytes:** for any object that is hashed or signed, the byte string
  is `JSON` with keys sorted lexicographically, the most compact separators
  (`,` and `:`), UTF-8 encoding, and `NaN`/`Infinity` forbidden.

## 2. Agent identity

An agent's id is derived from its public key, making it self-certifying:

```
agent_id = "px_" + lowercase(base32(SHA-256(public_key)[:20]))
```

20 bytes (160 bits) base32-encode to exactly 32 characters with no padding, so
every id is `px_` followed by 32 lowercase base32 characters.

### Identity file (`proxim-identity/1`)

Contains the **private key** — protect it like an SSH key (written `0600`).

```json
{
  "version": "proxim-identity/1",
  "agent_id": "px_…",
  "private_key": "<base64url 32 bytes>",
  "name": "alice",
  "metadata": {},
  "created_at": 1750000000.0
}
```

### Public identity

The shareable half. Its `agent_id` MUST equal the fingerprint of `public_key`;
implementations MUST reject a mismatch.

```json
{ "agent_id": "px_…", "public_key": "<base64url>", "name": "alice",
  "metadata": {}, "created_at": 1750000000.0 }
```

## 3. Attestation (`proxim-attestation/1`)

A signed statement that an agent produced an output with a given hash.

```json
{
  "version": "proxim-attestation/1",
  "agent_id": "px_…",
  "public_key": "<base64url>",
  "payload_hash": "<hex SHA-256 of the output bytes>",
  "payload_type": "application/json",
  "claims": { "model": "opus-4.8" },
  "parents": ["att_…"],
  "issued_at": 1750000000.0,
  "expires_at": 1750003600.0,
  "nonce": "<base64url 16 bytes>",
  "signature": "<base64url 64 bytes>",
  "attestation_id": "att_<base64url SHA-256 of signing bytes>"
}
```

### Signing body

The **signing body** is the object above **excluding** `signature` and
`attestation_id`. Then:

```
signing_bytes  = canonical_bytes(signing_body)
attestation_id = "att_" + base64url(SHA-256(signing_bytes))
signature      = Ed25519_sign(private_key, signing_bytes)
```

The output bytes themselves are never stored — only their hash. `parents` lists
the `attestation_id`s an output was derived from, forming an auditable
provenance chain.

### Verification (standalone, no registry)

An attestation is **cryptographically valid** iff **all** hold:

1. `agent_id == "px_" + base32(SHA-256(public_key)[:20])` (id matches key).
2. `attestation_id == "att_" + base64url(SHA-256(signing_bytes))` (id matches body).
3. `Ed25519_verify(public_key, signing_bytes, signature)` succeeds.

Additionally, when the consumer holds the output bytes:

4. `SHA-256(output) == payload_hash` (payload binding).

And for freshness:

5. `expires_at` is absent or in the future.

## 4. Registry (`proxim-registry/1`)

The trust directory. Each record wraps a public identity with status.

```json
{
  "version": "proxim-registry/1",
  "records": [
    { "identity": { … }, "status": "active" | "revoked",
      "roles": ["planner"], "trust_anchor": false,
      "registered_at": 0.0, "revoked_at": null, "revocation_reason": null }
  ]
}
```

`status: "revoked"` MUST block trust unless a policy explicitly allows it.
`trust_anchor: true` marks a first-party, known-good agent.

## 5. Reputation (`proxim-reputation/1`)

An append-only log of outcome events plus scoring parameters.

```json
{
  "version": "proxim-reputation/1",
  "params": { "half_life_days": 30.0, "prior_mean": 0.5, "prior_strength": 2.0 },
  "events": [
    { "agent_id": "px_…", "outcome": 1.0, "weight": 1.0, "at": 1750000000.0,
      "attestation_id": "att_…", "note": null }
  ]
}
```

### Score

For agent `a` evaluated at time `now`, each event `i` for that agent contributes

```
decay_i     = 0.5 ** ((now - at_i) / (half_life_days * 86400))
effective_i = weight_i * decay_i
```

and the score is the prior-smoothed, decay-weighted mean of outcomes:

```
score = (prior_mean * prior_strength + Σ effective_i * outcome_i)
        / (prior_strength + Σ effective_i)
```

With no evidence the score equals `prior_mean` (0.5). All outcomes are clamped
to `[0, 1]`.

## 6. Trust decision

A policy combines the verification facts into a boolean. The default policy
trusts an attestation iff it is cryptographically valid, payload-bound (if the
payload is presented), unexpired, the agent is registered and not revoked, any
required roles are present, and reputation ≥ `min_reputation` (default 0.5). A
registered `trust_anchor` bypasses the role/reputation checks once integrity,
freshness, and revocation pass.
