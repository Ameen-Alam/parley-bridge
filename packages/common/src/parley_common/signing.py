"""Ed25519 signing with JWS compact serialisation (RFC 7515, RFC 8037).

The relay signs approvals and refusal records so that an owner, or a
customer's security officer, can verify them with the published key and any
JWS library (stories 2.4, 4.12, 8.2). The format is deliberately small:

- ``sign(payload, private_key)`` returns ``base64url(header).base64url(payload)
  .base64url(signature)`` with header ``{"alg": "EdDSA", "kid": <public key>}``,
  where ``kid`` is the signer's public key as base64url of its raw 32 bytes.
- ``verify(jws, public_key)`` returns the payload bytes or raises one of three
  distinct errors: :class:`MalformedJwsError` when the text is not a JWS we
  understand, :class:`WrongKeyError` when the header names a different key,
  :class:`BadSignatureError` when the signature does not match (a tampered
  payload or header, or a signature from a different key without a ``kid``).

Public keys serialise as base64url raw bytes and as a JWK
(``{"kty": "OKP", "crv": "Ed25519", "x": ...}``). No JOSE library is used, so
the record format stays open and verifiable offline. Nothing here logs or
prints, and no key or payload appears in an exception message.

Base64url is canonical in both directions (T-0016): :func:`b64url_decode`
accepts only the alphabet ``A-Za-z0-9-_`` without padding and only encodings
that re-encode to the same text, so one JWS has exactly one spelling and a
strict JWS library accepts what :func:`verify` accepts.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any

from nacl import exceptions as nacl_exceptions
from nacl import signing as nacl_signing

ALGORITHM = "EdDSA"
KEY_BYTES = 32
SIGNATURE_BYTES = 64
_B64URL_ALPHABET_RE = re.compile(r"[A-Za-z0-9_-]*")


class SigningError(Exception):
    """Base class for every error raised by this module."""


class VerificationError(SigningError):
    """The JWS did not verify. Subclasses say why."""


class MalformedJwsError(VerificationError):
    """The text is not a JWS compact serialisation with an EdDSA header."""


class WrongKeyError(VerificationError):
    """The header's ``kid`` names a key other than the one given to verify."""


class BadSignatureError(VerificationError):
    """The signature does not match the header and payload under the given key."""


class InvalidKeyError(SigningError):
    """The bytes, text or JWK do not describe an Ed25519 key."""


def b64url_encode(data: bytes) -> str:
    """Base64url without padding, as JWS requires."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Inverse of :func:`b64url_encode`, accepting only the canonical spelling.

    Enforced: ``text`` is a ``str`` made only of ``A-Z``, ``a-z``, ``0-9``,
    ``-`` and ``_`` (no ``+``, ``/``, ``=`` or whitespace); its length is not
    1 modulo 4; and the trailing bits of the last character are zero, so
    re-encoding the decoded bytes reproduces ``text`` exactly. Anything else
    raises :class:`ValueError`.
    """
    if not isinstance(text, str) or _B64URL_ALPHABET_RE.fullmatch(text) is None:
        raise ValueError("not unpadded base64url")
    padded = text + "=" * (-len(text) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except binascii.Error as error:
        raise ValueError("not unpadded base64url") from error
    if b64url_encode(decoded) != text:
        raise ValueError("not canonical base64url")
    return decoded


@dataclass(frozen=True, slots=True)
class PublicKey:
    """An Ed25519 public key, 32 raw bytes."""

    raw: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.raw, bytes) or len(self.raw) != KEY_BYTES:
            raise InvalidKeyError("an Ed25519 public key is 32 bytes")

    def __repr__(self) -> str:
        return f"PublicKey({self.to_base64url()})"

    def to_base64url(self) -> str:
        return b64url_encode(self.raw)

    @classmethod
    def from_base64url(cls, text: str) -> PublicKey:
        try:
            raw = b64url_decode(text)
        except ValueError as error:
            raise InvalidKeyError("public key is not base64url") from error
        return cls(raw)

    def to_jwk(self) -> dict[str, str]:
        return {"kty": "OKP", "crv": "Ed25519", "x": self.to_base64url()}

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any]) -> PublicKey:
        if not isinstance(jwk, dict):
            raise InvalidKeyError("JWK must be an object")
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            raise InvalidKeyError("JWK must have kty OKP and crv Ed25519")
        x = jwk.get("x")
        if not isinstance(x, str):
            raise InvalidKeyError("JWK x must be a string")
        return cls.from_base64url(x)

    def _verify_key(self) -> Any:
        return nacl_signing.VerifyKey(self.raw)


@dataclass(frozen=True, slots=True)
class PrivateKey:
    """An Ed25519 private key, held as its 32-byte seed. Its repr hides the seed."""

    seed: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.seed, bytes) or len(self.seed) != KEY_BYTES:
            raise InvalidKeyError("an Ed25519 private key seed is 32 bytes")

    def __repr__(self) -> str:
        return f"PrivateKey(public={self.public_key().to_base64url()})"

    def public_key(self) -> PublicKey:
        return PublicKey(bytes(self._signing_key().verify_key))

    def to_base64url(self) -> str:
        return b64url_encode(self.seed)

    @classmethod
    def from_base64url(cls, text: str) -> PrivateKey:
        try:
            seed = b64url_decode(text)
        except ValueError as error:
            raise InvalidKeyError("private key is not base64url") from error
        return cls(seed)

    def _signing_key(self) -> Any:
        return nacl_signing.SigningKey(self.seed)


@dataclass(frozen=True, slots=True)
class KeyPair:
    private: PrivateKey
    public: PublicKey


def generate_keypair() -> KeyPair:
    """Make a fresh Ed25519 key pair from the operating system's randomness."""
    signing_key = nacl_signing.SigningKey.generate()
    private = PrivateKey(bytes(signing_key))
    return KeyPair(private=private, public=private.public_key())


def sign(payload: bytes, key: PrivateKey) -> str:
    """Sign ``payload`` and return the JWS compact serialisation."""
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    header = {"alg": ALGORITHM, "kid": key.public_key().to_base64url()}
    header_text = json.dumps(header, separators=(",", ":"), sort_keys=True)
    signing_input = f"{b64url_encode(header_text.encode('ascii'))}.{b64url_encode(payload)}"
    signature = bytes(key._signing_key().sign(signing_input.encode("ascii")).signature)
    return f"{signing_input}.{b64url_encode(signature)}"


def verify(jws: str, public_key: PublicKey) -> bytes:
    """Check ``jws`` against ``public_key`` and return its payload bytes.

    Raises :class:`MalformedJwsError`, :class:`WrongKeyError` or
    :class:`BadSignatureError`. A ``kid`` in the header is compared with the
    given key before the signature is checked; a JWS without ``kid`` is
    verified on the signature alone.
    """
    header, signing_input, payload, signature = _split(jws)
    kid = header.get("kid")
    if kid is not None and kid != public_key.to_base64url():
        raise WrongKeyError("JWS was signed by a different key")
    try:
        public_key._verify_key().verify(signing_input, signature)
    except nacl_exceptions.BadSignatureError as error:
        raise BadSignatureError("JWS signature does not verify") from error
    return payload


def _split(jws: str) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    if not isinstance(jws, str):
        raise MalformedJwsError("JWS must be a string")
    parts = jws.split(".")
    if len(parts) != 3:
        raise MalformedJwsError("JWS compact serialisation has three parts")
    header_part, payload_part, signature_part = parts
    try:
        header_bytes = b64url_decode(header_part)
        payload = b64url_decode(payload_part)
        signature = b64url_decode(signature_part)
    except ValueError as error:
        raise MalformedJwsError("JWS parts are not base64url") from error
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise MalformedJwsError("JWS header is not JSON") from error
    if not isinstance(header, dict):
        raise MalformedJwsError("JWS header must be an object")
    if header.get("alg") != ALGORITHM:
        raise MalformedJwsError("JWS alg must be EdDSA")
    if "crit" in header:
        raise MalformedJwsError("JWS crit header parameters are not supported")
    kid = header.get("kid")
    if kid is not None and not isinstance(kid, str):
        raise MalformedJwsError("JWS kid must be a string")
    if len(signature) != SIGNATURE_BYTES:
        raise MalformedJwsError("Ed25519 signature is 64 bytes")
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    return header, signing_input, payload, signature
