"""T-0001 criteria 3 and 4: JWS compact EdDSA signing that an outside party can verify."""

import json

import pytest
from nacl import signing as nacl_signing

from parley_common import signing

# RFC 8037, appendix A: the Ed25519 test key and the JWS of appendix A.4.
RFC8037_D = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
RFC8037_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
RFC8037_JWS = (
    "eyJhbGciOiJFZERTQSJ9"
    ".RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc"
    ".hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
)
RFC8037_PAYLOAD = b"Example of Ed25519 signing"

SIXTY_FOUR_ZEROS = signing.b64url_encode(b"\x00" * 64)


def header(text: bytes) -> str:
    return signing.b64url_encode(text)


def test_generate_keypair_gives_matching_32_byte_keys() -> None:
    pair = signing.generate_keypair()
    assert len(pair.private.seed) == 32
    assert len(pair.public.raw) == 32
    assert pair.private.public_key() == pair.public
    assert signing.generate_keypair().public != pair.public


def test_sign_then_verify_round_trip() -> None:
    pair = signing.generate_keypair()
    jws = signing.sign(b'{"reason": "over_limit"}', pair.private)
    assert jws.count(".") == 2
    assert signing.verify(jws, pair.public) == b'{"reason": "over_limit"}'


def test_header_is_eddsa_with_the_public_key_as_kid() -> None:
    pair = signing.generate_keypair()
    jws = signing.sign(b"x", pair.private)
    parsed = json.loads(signing.b64url_decode(jws.split(".")[0]))
    assert parsed == {"alg": "EdDSA", "kid": pair.public.to_base64url()}


def test_rfc8037_vector_verifies_with_the_published_key() -> None:
    """Criterion 3: a JWS made by an independent implementation (the RFC) verifies here."""
    public = signing.PublicKey.from_jwk({"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X})
    assert signing.verify(RFC8037_JWS, public) == RFC8037_PAYLOAD


def test_our_signature_matches_the_rfc8037_vector() -> None:
    """Criterion 3: our key handling reproduces the RFC's signature byte for byte."""
    private = signing.PrivateKey.from_base64url(RFC8037_D)
    assert private.public_key().to_base64url() == RFC8037_X
    # The RFC header has no kid, so sign its exact signing input with the same
    # key material sign() uses and compare with the RFC's signature.
    signing_input, expected = RFC8037_JWS.rsplit(".", 1)
    raw = nacl_signing.SigningKey(private.seed).sign(signing_input.encode("ascii")).signature
    assert signing.b64url_encode(raw) == expected


def test_our_jws_verifies_with_pynacl_directly() -> None:
    """Criterion 3: a second implementation (raw pynacl over the signing input) agrees."""
    pair = signing.generate_keypair()
    jws = signing.sign(b"record", pair.private)
    signing_input, signature = jws.rsplit(".", 1)
    nacl_signing.VerifyKey(pair.public.raw).verify(
        signing_input.encode("ascii"), signing.b64url_decode(signature)
    )


def test_public_key_serialises_as_base64url_and_jwk() -> None:
    pair = signing.generate_keypair()
    text = pair.public.to_base64url()
    assert len(text) == 43
    assert "=" not in text
    assert signing.PublicKey.from_base64url(text) == pair.public
    jwk = pair.public.to_jwk()
    assert jwk == {"kty": "OKP", "crv": "Ed25519", "x": text}
    assert signing.PublicKey.from_jwk(json.loads(json.dumps(jwk))) == pair.public


@pytest.mark.parametrize(
    "jwk",
    [
        {"kty": "RSA", "crv": "Ed25519", "x": RFC8037_X},
        {"kty": "OKP", "crv": "X25519", "x": RFC8037_X},
        {"kty": "OKP", "crv": "Ed25519", "x": "short"},
        {"kty": "OKP", "crv": "Ed25519"},
        {"kty": "OKP", "crv": "Ed25519", "x": RFC8037_X + "=="},
    ],
)
def test_bad_jwk_is_refused(jwk: dict[str, str]) -> None:
    with pytest.raises(signing.InvalidKeyError):
        signing.PublicKey.from_jwk(jwk)


def test_wrong_length_keys_are_refused() -> None:
    with pytest.raises(signing.InvalidKeyError):
        signing.PublicKey(b"\x00" * 31)
    with pytest.raises(signing.InvalidKeyError):
        signing.PrivateKey(b"\x00" * 33)


def test_tampered_payload_fails_with_bad_signature() -> None:
    """Criterion 4: tampering."""
    pair = signing.generate_keypair()
    jws = signing.sign(b"amount=10", pair.private)
    head, _, signature = jws.split(".")
    tampered = ".".join([head, signing.b64url_encode(b"amount=99"), signature])
    with pytest.raises(signing.BadSignatureError):
        signing.verify(tampered, pair.public)


def test_tampered_header_fails_with_bad_signature() -> None:
    pair = signing.generate_keypair()
    jws = signing.sign(b"x", pair.private)
    _, payload, signature = jws.split(".")
    with pytest.raises(signing.BadSignatureError):
        signing.verify(".".join([header(b'{"alg":"EdDSA"}'), payload, signature]), pair.public)


def test_wrong_key_fails_with_wrong_key() -> None:
    """Criterion 4: wrong key, detected from the header's kid."""
    signer = signing.generate_keypair()
    other = signing.generate_keypair()
    jws = signing.sign(b"x", signer.private)
    with pytest.raises(signing.WrongKeyError):
        signing.verify(jws, other.public)


def test_wrong_key_without_kid_fails_with_bad_signature() -> None:
    other = signing.generate_keypair()
    with pytest.raises(signing.BadSignatureError):
        signing.verify(RFC8037_JWS, other.public)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "abc",
        "a.b",
        "a.b.c.d",
        "not base64!.RXhhbXBsZQ.c2ln",
        header(b"not json") + ".RXhhbXBsZQ." + SIXTY_FOUR_ZEROS,
        header(b"[]") + ".RXhhbXBsZQ." + SIXTY_FOUR_ZEROS,
        header(b'{"alg":"HS256"}') + ".RXhhbXBsZQ." + SIXTY_FOUR_ZEROS,
        header(b'{"alg":"none"}') + ".RXhhbXBsZQ.",
        header(b'{"alg":"EdDSA","crit":["x"]}') + ".RXhhbXBsZQ." + SIXTY_FOUR_ZEROS,
        header(b'{"alg":"EdDSA"}') + ".RXhhbXBsZQ." + signing.b64url_encode(b"\x00"),
        header(b'{"alg":"EdDSA","kid":5}') + ".RXhhbXBsZQ." + SIXTY_FOUR_ZEROS,
        # T-0016: non-canonical base64url. Standard-alphabet characters in a part.
        header(b'{"alg":"EdDSA"}') + ".RXhh+XBsZQ." + SIXTY_FOUR_ZEROS,
        header(b'{"alg":"EdDSA"}') + ".RXhh/XBsZQ." + SIXTY_FOUR_ZEROS,
        # Non-zero trailing bits: "RXhhbXBsZR" decodes to the same bytes as "RXhhbXBsZQ".
        header(b'{"alg":"EdDSA"}') + ".RXhhbXBsZR." + SIXTY_FOUR_ZEROS,
        header(b'{"alg":"EdDSA"}') + ".RXhhbXBsZQ." + SIXTY_FOUR_ZEROS[:-1] + "B",
        # Padding and an impossible length (1 modulo 4).
        header(b'{"alg":"EdDSA"}') + ".RXhhbXBsZQ==." + SIXTY_FOUR_ZEROS,
        header(b'{"alg":"EdDSA"}') + ".RXhhbXBsZ." + SIXTY_FOUR_ZEROS,
        header(b'{"alg":"EdDSA"}') + ".RXhhb XBsZQ." + SIXTY_FOUR_ZEROS,
    ],
)
def test_malformed_jws_fails_with_malformed(text: str) -> None:
    """Criterion 4 of T-0001 and criteria 1 and 2 of T-0016: malformed input,
    including alg none, foreign algorithms and non-canonical base64url."""
    pair = signing.generate_keypair()
    with pytest.raises(signing.MalformedJwsError):
        signing.verify(text, pair.public)


def test_b64url_decode_accepts_only_the_canonical_spelling() -> None:
    """T-0016 criterion 1: one byte string has one base64url spelling."""
    assert signing.b64url_decode("RXhhbXBsZQ") == b"Example"
    assert signing.b64url_decode("") == b""
    assert signing.b64url_decode(signing.b64url_encode(bytes(range(256)))) == bytes(range(256))
    for text in ["RXhhbXBsZR", "RXhh+XBsZQ", "RXhh/XBsZQ", "RXhhbXBsZQ=", "RXhhbXBsZ", " "]:
        with pytest.raises(ValueError):
            signing.b64url_decode(text)


def test_the_three_failures_are_distinct_but_all_verification_errors() -> None:
    kinds = {signing.MalformedJwsError, signing.WrongKeyError, signing.BadSignatureError}
    assert len(kinds) == 3
    for kind in kinds:
        assert issubclass(kind, signing.VerificationError)
        for other in kinds - {kind}:
            assert not issubclass(kind, other)


def test_reprs_hide_private_material_and_errors_hide_payloads() -> None:
    pair = signing.generate_keypair()
    assert pair.private.to_base64url() not in repr(pair.private)
    assert pair.private.to_base64url() not in repr(pair)
    secret = b"the secret payload text"
    jws = signing.sign(secret, pair.private)
    other = signing.generate_keypair()
    with pytest.raises(signing.WrongKeyError) as wrong:
        signing.verify(jws, other.public)
    assert secret.decode() not in str(wrong.value)
    head, _, signature = jws.split(".")
    with pytest.raises(signing.BadSignatureError) as bad:
        signing.verify(".".join([head, signing.b64url_encode(b"changed"), signature]), pair.public)
    assert secret.decode() not in str(bad.value)
