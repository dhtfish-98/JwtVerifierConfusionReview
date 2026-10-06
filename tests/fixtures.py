"""Synthetic keys and tokens for this repository's owned local tests only."""

from __future__ import annotations

import base64
import json
import time

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ISSUER = "https://issuer.test.invalid"
AUDIENCE = "urn:owned-resource:test"
OTHER_ISSUER = "https://other-issuer.test.invalid"


def keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPrivateKey, bytes, bytes]:
    first = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        first,
        second,
        first.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        second.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
    )


def claims(**changes: object) -> dict[str, object]:
    now = int(time.time())
    result: dict[str, object] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "owned-user-a",
        "iat": now - 1,
        "nbf": now - 1,
        "exp": now + 180,
        "jti": "synthetic-jti-001",
        "token_use": "access",
    }
    result.update(changes)
    return result


def signed(private_key: rsa.RSAPrivateKey, payload: dict[str, object] | None = None, **header: object) -> str:
    actual_header = {"kid": "shared", "typ": "at+jwt"}
    actual_header.update(header)
    return jwt.encode(payload or claims(), private_key, algorithm="RS256", headers=actual_header)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def raw_signed(private_key: rsa.RSAPrivateKey, header: str, payload: str) -> str:
    signing_input = (b64(header.encode()) + "." + b64(payload.encode())).encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode("ascii") + "." + b64(signature)


def raw_unsigned(payload: dict[str, object]) -> str:
    h = b64(json.dumps({"alg": "none", "kid": "shared", "typ": "at+jwt"}, separators=(",", ":")).encode())
    p = b64(json.dumps(payload, separators=(",", ":")).encode())
    return h + "." + p + "."

