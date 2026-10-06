"""Strict RS256 access-token verification using a caller-configured trust anchor.

The caller constructs a Verifier for one resource server and one issuer.  The
token may choose only a key ID within that already trusted issuer configuration.
No token-provided URL, key, or algorithm can change the verification policy.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key


_SEGMENT = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)
_KID = re.compile(r"[A-Za-z0-9._-]{1,64}\Z", re.ASCII)
_HEADER_KEYS = frozenset({"alg", "kid", "typ"})
_CLAIM_KEYS = frozenset({"iss", "aud", "sub", "exp", "iat", "nbf", "jti", "token_use"})
_MAX_TOKEN_BYTES = 8192
_MAX_HEADER_BYTES = 2048
_MAX_CLAIMS_BYTES = 4096
_MAX_RSA_KEY_BITS = 8192


class RejectedToken(ValueError):
    """Token rejected under the selected local profile, with a stable code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class VerificationPolicy:
    """Trusted resource-server policy, supplied independently of any token."""

    issuer: str
    audience: str
    public_keys_by_kid: Mapping[str, bytes]
    max_lifetime_seconds: int = 600

    def __post_init__(self) -> None:
        if not isinstance(self.issuer, str) or not self.issuer or len(self.issuer) > 256:
            raise ValueError("issuer must be a nonempty bounded string")
        if not isinstance(self.audience, str) or not self.audience or len(self.audience) > 256:
            raise ValueError("audience must be a nonempty bounded string")
        if type(self.max_lifetime_seconds) is not int or not 1 <= self.max_lifetime_seconds <= 3600:
            raise ValueError("max_lifetime_seconds must be 1..3600")
        if not isinstance(self.public_keys_by_kid, Mapping) or not 1 <= len(self.public_keys_by_kid) <= 16:
            raise ValueError("1..16 trusted public keys are required")
        # Copy the mapping and convert every key at construction time.  A later
        # mutation of the caller's dictionary cannot change the trust set.
        keys: dict[str, bytes] = {}
        for kid, pem in self.public_keys_by_kid.items():
            if not isinstance(kid, str) or not _KID.fullmatch(kid):
                raise ValueError("invalid trusted key ID")
            if not isinstance(pem, bytes) or len(pem) > 8192:
                raise ValueError("trusted public key must be bounded PEM bytes")
            try:
                key = load_pem_public_key(pem)
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid trusted public key") from exc
            if not isinstance(key, rsa.RSAPublicKey) or not 2048 <= key.key_size <= _MAX_RSA_KEY_BITS:
                raise ValueError("RS256 requires an RSA public key of 2048..8192 bits")
            if key.public_numbers().e != 65537:
                raise ValueError("trusted RSA exponent must be 65537")
            keys[kid] = key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        object.__setattr__(self, "public_keys_by_kid", MappingProxyType(keys))


@dataclass(frozen=True)
class VerifiedAccessToken:
    subject: str
    issuer: str
    audience: str
    token_id: str
    expires_at: int


def _decode_segment(encoded: str, limit: int) -> bytes:
    if not encoded or len(encoded) > (limit * 4 // 3 + 8) or not _SEGMENT.fullmatch(encoded):
        raise RejectedToken("invalid_segment")
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (binascii.Error, ValueError) as exc:
        raise RejectedToken("invalid_segment") from exc
    if len(decoded) > limit or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != encoded:
        raise RejectedToken("noncanonical_segment")
    return decoded


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RejectedToken("duplicate_json_member")
        result[key] = value
    return result


def _reject_nonfinite(_: str) -> object:
    raise RejectedToken("nonfinite_json_number")


def _parse_object(raw: bytes, code: str) -> dict[str, object]:
    try:
        data = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_nonfinite,
        )
    except RejectedToken:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RejectedToken(code) from exc
    if not isinstance(data, dict):
        raise RejectedToken(code)
    # This profile is intentionally flat.  It has no nested header/claim objects
    # and does not accept lone UTF-16 surrogate escapes in any text field.
    for key, value in data.items():
        if not isinstance(key, str) or any(0xD800 <= ord(c) <= 0xDFFF for c in key):
            raise RejectedToken(code)
        if type(value) not in (str, int) or (
            isinstance(value, str) and any(0xD800 <= ord(c) <= 0xDFFF for c in value)
        ):
            raise RejectedToken(code)
    return data


class Verifier:
    """Verify one bounded RS256 access-token profile for one trusted resource."""

    def __init__(self, policy: VerificationPolicy) -> None:
        if not isinstance(policy, VerificationPolicy):
            raise TypeError("a VerificationPolicy is required")
        self._policy = policy
        self._keys = MappingProxyType(
            {kid: load_pem_public_key(pem) for kid, pem in policy.public_keys_by_kid.items()}
        )

    def verify(self, token: str) -> VerifiedAccessToken:
        if not isinstance(token, str) or len(token) > _MAX_TOKEN_BYTES or not token.isascii():
            raise RejectedToken("invalid_token")
        parts = token.split(".")
        if len(parts) != 3:
            raise RejectedToken("invalid_token")
        header = _parse_object(_decode_segment(parts[0], _MAX_HEADER_BYTES), "invalid_header")
        claims = _parse_object(_decode_segment(parts[1], _MAX_CLAIMS_BYTES), "invalid_claims")
        if set(header) != _HEADER_KEYS:
            raise RejectedToken("unsupported_header")
        if header["alg"] != "RS256":
            raise RejectedToken("wrong_algorithm")
        if header["typ"] != "at+jwt":
            raise RejectedToken("wrong_type")
        kid = header["kid"]
        if not isinstance(kid, str) or not _KID.fullmatch(kid):
            raise RejectedToken("invalid_key_id")
        key = self._keys.get(kid)
        if key is None:
            raise RejectedToken("unknown_key")
        # An RS256 signature is exactly as wide as the selected trusted RSA
        # modulus. A fixed 512-byte budget would reject an accepted 6144-bit key.
        expected_signature_bytes = (key.key_size + 7) // 8
        if len(_decode_segment(parts[2], expected_signature_bytes)) != expected_signature_bytes:
            raise RejectedToken("invalid_segment")

        if set(claims) != _CLAIM_KEYS:
            raise RejectedToken("unsupported_claims")
        for name in ("iss", "aud", "sub", "jti", "token_use"):
            if type(claims[name]) is not str or not claims[name] or len(claims[name]) > 256:
                raise RejectedToken("invalid_claims")
        for name in ("exp", "iat", "nbf"):
            if type(claims[name]) is not int or claims[name] < 0:
                raise RejectedToken("invalid_claims")
        if claims["iss"] != self._policy.issuer or claims["aud"] != self._policy.audience:
            raise RejectedToken("wrong_context")
        if claims["token_use"] != "access":
            raise RejectedToken("wrong_use")
        if not claims["iat"] <= claims["nbf"] < claims["exp"]:
            raise RejectedToken("invalid_lifetime")
        if claims["exp"] - claims["iat"] > self._policy.max_lifetime_seconds:
            raise RejectedToken("invalid_lifetime")

        try:
            decoded = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                issuer=self._policy.issuer,
                audience=self._policy.audience,
                options={"require": ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"]},
                leeway=0,
            )
        except jwt.PyJWTError as exc:
            raise RejectedToken("signature_or_time_invalid") from exc
        if decoded != claims:
            raise RejectedToken("claim_parser_disagreement")
        return VerifiedAccessToken(
            subject=claims["sub"],
            issuer=claims["iss"],
            audience=claims["aud"],
            token_id=claims["jti"],
            expires_at=claims["exp"],
        )
