"""Real RS256 signatures, strict JSON parsing, and trusted-context tests."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa

from fixtures import AUDIENCE, ISSUER, OTHER_ISSUER, b64, claims, keys, raw_signed, raw_unsigned, signed
from weak_baseline import weak_claim_only_accept
from jwt_verifier_confusion_review import RejectedToken, VerificationPolicy, Verifier


class VerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.first, cls.second, cls.public_first, cls.public_second = keys()
        cls.verifier = Verifier(
            VerificationPolicy(ISSUER, AUDIENCE, {"shared": cls.public_first})
        )

    def reject(self, token: str, code: str) -> None:
        with self.assertRaises(RejectedToken) as context:
            self.verifier.verify(token)
        self.assertEqual(context.exception.code, code)

    def test_real_valid_signature_and_context(self) -> None:
        result = self.verifier.verify(signed(self.first))
        self.assertEqual((result.subject, result.issuer, result.audience), ("owned-user-a", ISSUER, AUDIENCE))

    def test_wrong_trusted_signer_same_kid(self) -> None:
        self.reject(signed(self.second), "signature_or_time_invalid")

    def test_wrong_issuer_even_when_signed_by_trusted_key(self) -> None:
        self.reject(signed(self.first, claims(iss=OTHER_ISSUER)), "wrong_context")

    def test_wrong_audience(self) -> None:
        self.reject(signed(self.first, claims(aud="urn:other-resource")), "wrong_context")

    def test_id_token_type_not_access_type(self) -> None:
        self.reject(signed(self.first, typ="JWT"), "wrong_type")

    def test_wrong_use_claim(self) -> None:
        self.reject(signed(self.first, claims(token_use="refresh")), "wrong_use")

    def test_attacker_key_source_headers_rejected(self) -> None:
        self.reject(signed(self.first, jku="https://attacker.test.invalid/jwks"), "unsupported_header")
        self.reject(signed(self.first, jwk={"kty": "RSA"}), "invalid_header")
        self.reject(signed(self.first, x5u="https://attacker.test.invalid/cert"), "unsupported_header")

    def test_unknown_kid(self) -> None:
        self.reject(signed(self.first, kid="other"), "unknown_key")

    def test_hs256_confusion_token(self) -> None:
        header = b64(b'{"alg":"HS256","kid":"shared","typ":"at+jwt"}')
        payload = b64(json.dumps(claims(), separators=(",", ":")).encode())
        signing_input = (header + "." + payload).encode("ascii")
        mac = b64(hmac.new(self.public_first, signing_input, hashlib.sha256).digest())
        self.reject(signing_input.decode() + "." + mac, "wrong_algorithm")

    def test_unsigned_weak_baseline_is_not_verifier(self) -> None:
        token = raw_unsigned(claims())
        self.assertTrue(weak_claim_only_accept(token, ISSUER, AUDIENCE))
        self.reject(token, "wrong_algorithm")

    def test_duplicate_jose_member_even_with_real_signature(self) -> None:
        header = '{"alg":"RS256","kid":"shared","typ":"at+jwt","alg":"none"}'
        payload = json.dumps(claims(), separators=(",", ":"))
        self.reject(raw_signed(self.first, header, payload), "duplicate_json_member")

    def test_duplicate_claim_member_even_with_real_signature(self) -> None:
        header = '{"alg":"RS256","kid":"shared","typ":"at+jwt"}'
        payload = json.dumps(claims(), separators=(",", ":"))[:-1] + ',"aud":"urn:other-resource"}'
        self.reject(raw_signed(self.first, header, payload), "duplicate_json_member")

    def test_unicode_escape_duplicate_key(self) -> None:
        header = '{"alg":"RS256","\\u0061lg":"none","kid":"shared","typ":"at+jwt"}'
        self.reject(raw_signed(self.first, header, json.dumps(claims())), "duplicate_json_member")

    def test_nonfinite_and_boolean_time_rejected(self) -> None:
        header = '{"alg":"RS256","kid":"shared","typ":"at+jwt"}'
        payload = json.dumps(claims()).replace('"exp": ', '"exp": NaN, "old_exp": ')
        self.reject(raw_signed(self.first, header, payload), "nonfinite_json_number")
        self.reject(signed(self.first, claims(exp=True)), "invalid_claims")

    def test_expired_and_not_yet_valid(self) -> None:
        past = int(time.time()) - 100
        self.reject(signed(self.first, claims(iat=past - 10, nbf=past - 10, exp=past)), "signature_or_time_invalid")
        future = int(time.time()) + 100
        self.reject(signed(self.first, claims(iat=future - 1, nbf=future, exp=future + 50)), "signature_or_time_invalid")

    def test_long_lifetime(self) -> None:
        self.reject(signed(self.first, claims(exp=int(time.time()) + 1200)), "invalid_lifetime")

    def test_audience_array_and_extra_claim_not_in_selected_profile(self) -> None:
        self.reject(signed(self.first, claims(aud=[AUDIENCE])), "invalid_claims")
        self.reject(signed(self.first, claims(scope="read")), "unsupported_claims")

    def test_noncanonical_base64url_rejected(self) -> None:
        token = signed(self.first)
        head, payload, sig = token.split(".")
        self.reject(head + "=" + "." + payload + "." + sig, "invalid_segment")

    def test_policy_copies_trust_set(self) -> None:
        source = {"shared": self.public_first}
        policy = VerificationPolicy(ISSUER, AUDIENCE, source)
        source["shared"] = self.public_second
        verifier = Verifier(policy)
        self.assertEqual(verifier.verify(signed(self.first)).issuer, ISSUER)
        with self.assertRaises(TypeError):
            policy.public_keys_by_kid["shared"] = self.public_second

    def test_weak_rsa_trust_anchor_rejected(self) -> None:
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        public = small.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaises(ValueError):
            VerificationPolicy(ISSUER, AUDIENCE, {"small": public})

    def test_6144_bit_trusted_key_and_signature_budget_agree(self) -> None:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        large = rsa.generate_private_key(public_exponent=65537, key_size=6144)
        public = large.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        verifier = Verifier(VerificationPolicy(ISSUER, AUDIENCE, {"large": public}))
        self.assertEqual(verifier.verify(signed(large, kid="large")).subject, "owned-user-a")

    def test_malformed_and_oversized_tokens(self) -> None:
        self.reject("nonsense", "invalid_token")
        self.reject("x" * 8193, "invalid_token")


if __name__ == "__main__":
    unittest.main()
