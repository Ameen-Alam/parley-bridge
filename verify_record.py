#!/usr/bin/env python3
"""Check a Parley signed record offline (story 8.2).

The Parley relay signs every refusal record, every approval of a permission and every
acceptance of the tester notice, as a JWS compact serialisation (RFC 7515) with EdDSA
over Ed25519 (RFC 8037). This script checks such a record against the relay's published
key set, the JSON the relay serves at ``/.well-known/parley-keys`` (an operator export
carries a copy as ``parley-keys.json``), and prints ``valid`` or ``invalid`` with the
payload's fields.

    python verify_record.py parley-keys.json JWS_TEXT_OR_FILE
    python verify_record.py parley-keys.json -                       # the JWS on stdin
    python verify_record.py parley-keys.json --records records.json  # every record
    python verify_record.py parley-keys.json --records records.json --index 0

Exit 0 when every record checked is valid, 1 when one is not, 2 when the input cannot be
read. It runs offline: it imports the standard library and PyNaCl only, opens no
network connection and contacts no host. It reads the files named on its command line
and nothing else.

A record is valid when its header says ``alg`` EdDSA with no ``crit``, every part is
canonical unpadded base64url, its ``kid`` (when present) is a key of the set, and the
Ed25519 signature over ``header.payload`` verifies with that key. Compare the key set
with the one the relay serves before you trust a verdict: a record proves something
only against a key you got from the relay yourself.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

ALGORITHM = "EdDSA"
KEY_BYTES = 32
SIGNATURE_BYTES = 64
EXPORT_FORMAT = "parley-signed-records-1"
_B64URL = re.compile(r"[A-Za-z0-9_-]*")

VALID = 0
INVALID = 1
UNREADABLE = 2


class InputError(Exception):
    """A file or a value the script cannot read; the message names the rule."""


@dataclass(frozen=True)
class Verdict:
    """One record's result: valid or not, why not, and the payload when it is JSON."""

    valid: bool
    reason: str
    payload: dict[str, Any] | None


def b64url_decode(text: str) -> bytes:
    """Unpadded base64url, accepting only the canonical spelling (as the relay writes)."""
    if not isinstance(text, str) or _B64URL.fullmatch(text) is None:
        raise ValueError("not unpadded base64url")
    padded = text + "=" * (-len(text) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except binascii.Error as error:
        raise ValueError("not unpadded base64url") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != text:
        raise ValueError("not canonical base64url")
    return decoded


def load_keys(data: Any) -> dict[str, VerifyKey]:
    """The Ed25519 keys of a JWK set, by ``kid`` and by ``x`` (the relay sets both to the
    base64url of the 32 raw bytes)."""
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise InputError("the key set must be a JSON object with a keys list")
    keys: dict[str, VerifyKey] = {}
    for jwk in data["keys"]:
        if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        x = jwk.get("x")
        if not isinstance(x, str):
            continue
        try:
            raw = b64url_decode(x)
        except ValueError:
            continue
        if len(raw) != KEY_BYTES:
            continue
        key = VerifyKey(raw)
        keys[x] = key
        kid = jwk.get("kid")
        if isinstance(kid, str):
            keys[kid] = key
    if not keys:
        raise InputError("the key set holds no Ed25519 key")
    return keys


def _payload_of(part: str) -> dict[str, Any] | None:
    try:
        value = json.loads(b64url_decode(part).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def check(jws: str, keys: dict[str, VerifyKey]) -> Verdict:
    """Check one JWS against the keys; never raises on a bad record."""
    parts = jws.strip().split(".") if isinstance(jws, str) else []
    if len(parts) != 3:
        return Verdict(False, "not a JWS compact serialisation (three parts)", None)
    header_part, payload_part, signature_part = parts
    payload = _payload_of(payload_part)
    try:
        header_bytes = b64url_decode(header_part)
        b64url_decode(payload_part)
        signature = b64url_decode(signature_part)
    except ValueError:
        return Verdict(False, "a part is not canonical base64url", payload)
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return Verdict(False, "the header is not JSON", payload)
    if not isinstance(header, dict) or header.get("alg") != ALGORITHM:
        return Verdict(False, "the header's alg is not EdDSA", payload)
    if "crit" in header:
        return Verdict(False, "the header has crit parameters", payload)
    if len(signature) != SIGNATURE_BYTES:
        return Verdict(False, "the signature is not 64 bytes", payload)
    kid = header.get("kid")
    if kid is not None and not isinstance(kid, str):
        return Verdict(False, "the header's kid is not text", payload)
    if kid is not None and kid not in keys:
        return Verdict(False, "signed by a key that is not in the key set", payload)
    candidates = (
        [keys[kid]] if kid is not None else list({id(k): k for k in keys.values()}.values())
    )
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    for key in candidates:
        try:
            key.verify(signing_input, signature)
        except BadSignatureError:
            continue
        if payload is None:
            return Verdict(False, "the signature verifies but the payload is not JSON", None)
        return Verdict(True, "", payload)
    return Verdict(False, "the signature does not verify", payload)


def describe(verdict: Verdict) -> str:
    """``valid`` or ``invalid: why``, then the payload's fields, one per line."""
    lines = ["valid" if verdict.valid else f"invalid: {verdict.reason}"]
    if verdict.payload is not None:
        lines.append("payload:")
        lines.extend(
            f"  {name}: {json.dumps(value, sort_keys=True)}"
            for name, value in sorted(verdict.payload.items())
        )
    return "\n".join(lines)


def _read_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise InputError(f"{path} is not a readable JSON file") from error


def _read_jws(value: str) -> str:
    """The JWS itself, a file holding it, or ``-`` for standard input."""
    if value == "-":
        return sys.stdin.read().strip()
    if value.count(".") == 2 and _B64URL.fullmatch(value.replace(".", "")):
        return value
    try:
        return Path(value).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise InputError("the JWS is neither JWS text nor a readable file") from error


def _records(path: str) -> list[dict[str, Any]]:
    data = _read_json(path)
    if not isinstance(data, dict) or data.get("format") != EXPORT_FORMAT:
        raise InputError(f"{path} is not a Parley export ({EXPORT_FORMAT})")
    records = data.get("records")
    if not isinstance(records, list) or not all(
        isinstance(record, dict) and isinstance(record.get("jws"), str) for record in records
    ):
        raise InputError(f"{path} has no list of records with a jws each")
    return records


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_record.py",
        description="Check a Parley signed record against the relay's key set, offline.",
    )
    parser.add_argument("keys", metavar="KEYS.json", help="the key set (parley-keys.json)")
    parser.add_argument("jws", nargs="?", metavar="JWS", help="JWS text, a file, or -")
    parser.add_argument("--records", metavar="RECORDS.json", help="an export's records.json")
    parser.add_argument("--index", type=int, help="with --records: check only this record")
    args = parser.parse_args(argv)
    if (args.jws is None) == (args.records is None):
        parser.error("give one JWS or --records, not both and not neither")
    if args.index is not None and args.records is None:
        parser.error("--index goes with --records")
    try:
        keys = load_keys(_read_json(args.keys))
        if args.records is None:
            verdict = check(_read_jws(args.jws), keys)
            sys.stdout.write(describe(verdict) + "\n")
            return VALID if verdict.valid else INVALID
        records = _records(args.records)
        if args.index is not None:
            if not 0 <= args.index < len(records):
                raise InputError(f"--index must be from 0 to {len(records) - 1}")
            record = records[args.index]
            verdict = check(record["jws"], keys)
            sys.stdout.write(
                f"record {args.index} ({record.get('kind')}, {record.get('time')})\n"
                + describe(verdict)
                + "\n"
            )
            return VALID if verdict.valid else INVALID
    except InputError as error:
        sys.stderr.write(f"verify_record.py: {error}\n")
        return UNREADABLE
    bad = 0
    for index, record in enumerate(records):
        verdict = check(record["jws"], keys)
        bad += 0 if verdict.valid else 1
        result = "valid" if verdict.valid else f"invalid: {verdict.reason}"
        sys.stdout.write(f"record {index} ({record.get('kind')}, {record.get('time')}): {result}\n")
    sys.stdout.write(f"{len(records) - bad} valid, {bad} invalid\n")
    return VALID if bad == 0 else INVALID


if __name__ == "__main__":
    sys.exit(main())
