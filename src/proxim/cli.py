"""A small command-line interface: ``proxim ...`` (or ``python -m proxim``).

Subcommands:

* ``keygen``  — create a new identity and write it to a file.
* ``id``      — print the agent id of an identity file.
* ``attest``  — sign a payload (file or stdin) and print the attestation JSON.
* ``verify``  — check an attestation's signature (and optionally a payload).

This is a thin convenience wrapper over the library; everything it does is also
available programmatically.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from .attestation import Attestation
from .identity import AgentIdentity
from .verifier import Verifier
from .version import __version__


def _read_payload(path: Optional[str]) -> bytes:
    if path is None or path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as fh:
        return fh.read()


def _cmd_keygen(args: argparse.Namespace) -> int:
    identity = AgentIdentity.generate(args.name)
    identity.save(args.out)
    print(f"created {identity.agent_id}")
    print(f"  name: {identity.name}")
    print(f"  saved to: {args.out}")
    return 0


def _cmd_id(args: argparse.Namespace) -> int:
    identity = AgentIdentity.load(args.identity)
    print(identity.agent_id)
    return 0


def _cmd_attest(args: argparse.Namespace) -> int:
    identity = AgentIdentity.load(args.identity)
    payload = _read_payload(args.payload)
    claims = json.loads(args.claims) if args.claims else None
    att = Attestation.create(
        identity,
        payload,
        payload_type=args.type,
        claims=claims,
        ttl_seconds=args.ttl,
    )
    out = att.to_json(indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"wrote attestation {att.attestation_id} to {args.out}", file=sys.stderr)
    else:
        print(out)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    with open(args.attestation, "r", encoding="utf-8") as fh:
        att = Attestation.from_json(fh.read())
    payload = _read_payload(args.payload) if args.payload else None

    verifier = Verifier()
    result = verifier.verify(att, payload)

    ok = result.cryptographically_valid and (
        not result.payload_checked or result.payload_matches
    )
    status = "VALID" if ok else "INVALID"
    print(f"{status}  {att.attestation_id}")
    print(f"  agent_id:          {att.agent_id}")
    print(f"  signature_valid:   {result.signature_valid}")
    print(f"  identity_match:    {result.identity_consistent}")
    if result.payload_checked:
        print(f"  payload_matches:   {result.payload_matches}")
    print(f"  expired:           {result.expired}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxim", description=__doc__)
    parser.add_argument("--version", action="version", version=f"proxim {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="create a new identity file")
    p_keygen.add_argument("--name", help="human-readable agent name")
    p_keygen.add_argument("--out", "-o", required=True, help="path to write identity")
    p_keygen.set_defaults(func=_cmd_keygen)

    p_id = sub.add_parser("id", help="print the agent id of an identity file")
    p_id.add_argument("identity", help="path to an identity file")
    p_id.set_defaults(func=_cmd_id)

    p_attest = sub.add_parser("attest", help="sign a payload into an attestation")
    p_attest.add_argument("identity", help="path to the signing identity file")
    p_attest.add_argument("--payload", "-p", help="payload file ('-' or omit = stdin)")
    p_attest.add_argument("--type", "-t", help="payload type label")
    p_attest.add_argument("--claims", help="claims as a JSON object string")
    p_attest.add_argument("--ttl", type=float, help="time-to-live in seconds")
    p_attest.add_argument("--out", "-o", help="write attestation JSON to this file")
    p_attest.set_defaults(func=_cmd_attest)

    p_verify = sub.add_parser("verify", help="verify an attestation file")
    p_verify.add_argument("attestation", help="path to an attestation JSON file")
    p_verify.add_argument("--payload", "-p", help="payload file to bind-check")
    p_verify.set_defaults(func=_cmd_verify)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
