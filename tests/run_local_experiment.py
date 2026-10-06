"""Loopback-only resource-server check with synthetic identities and keys."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fixtures import AUDIENCE, ISSUER, OTHER_ISSUER, b64, claims, keys, raw_signed, raw_unsigned, signed
from weak_baseline import weak_claim_only_accept
from jwt_verifier_confusion_review import RejectedToken, VerificationPolicy, Verifier


def run(output: Path) -> dict[str, object]:
    private_a, private_b, public_a, _ = keys()
    verifier = Verifier(VerificationPolicy(ISSUER, AUDIENCE, {"shared": public_a}))
    decisions: list[dict[str, object]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/owned":
                self.send_error(404)
                return
            auth = self.headers.get("Authorization", "")
            try:
                if not auth.startswith("Bearer "):
                    raise RejectedToken("missing_bearer")
                verified = verifier.verify(auth[7:])
            except RejectedToken as exc:
                decisions.append({"accepted": False, "reason": exc.code})
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b"unauthorized")
                return
            decisions.append({"accepted": True, "subject_label": verified.subject})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"owned-resource")

        def log_message(self, format: str, *args: object) -> None:
            pass

    token_parts = signed(private_a).split(".")
    hs_header = b64(b'{"alg":"HS256","kid":"shared","typ":"at+jwt"}')
    hs_input = (hs_header + "." + token_parts[1]).encode("ascii")
    hs_token = hs_input.decode() + "." + b64(hmac.new(public_a, hs_input, hashlib.sha256).digest())
    duplicate_payload = json.dumps(claims(), separators=(",", ":"))[:-1] + ',"aud":"urn:other-resource"}'
    cases = [
        ("valid_owned_access", signed(private_a), 200),
        ("same_kid_wrong_signer", signed(private_b), 401),
        ("wrong_issuer", signed(private_a, claims(iss=OTHER_ISSUER)), 401),
        ("wrong_audience", signed(private_a, claims(aud="urn:other-resource")), 401),
        ("wrong_token_type", signed(private_a, typ="JWT"), 401),
        ("wrong_token_use", signed(private_a, claims(token_use="refresh")), 401),
        ("unsigned_claims", raw_unsigned(claims()), 401),
        ("hs256_public_key_mac", hs_token, 401),
        ("attacker_jku", signed(private_a, jku="https://attacker.test.invalid/jwks"), 401),
        ("duplicate_signed_claim", raw_signed(private_a, '{"alg":"RS256","kid":"shared","typ":"at+jwt"}', duplicate_payload), 401),
    ]

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        results: list[dict[str, object]] = []
        for name, token, expected in cases:
            request = urllib.request.Request(base + "/owned", headers={"Authorization": "Bearer " + token})
            try:
                with urllib.request.urlopen(request, timeout=3) as response:
                    status = response.status
                    response.read()
            except urllib.error.HTTPError as exc:
                status = exc.code
                exc.read()
            results.append({"case": name, "expected_http": expected, "actual_http": status, "pass": status == expected})
        server.shutdown()
        thread.join(timeout=3)

    unsigned_weak = weak_claim_only_accept(cases[6][1], ISSUER, AUDIENCE)
    result = {
        "schema": "jwt-verifier-confusion-local-lab-v1",
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "bind_address": "127.0.0.1",
        "synthetic_public_key_sha256": hashlib.sha256(public_a).hexdigest(),
        "weak_test_helper_accepts_unsigned_claims": unsigned_weak,
        "guarded_http_rejects_unsigned_claims": results[6]["actual_http"] == 401,
        "cases": results,
        "decisions": decisions,
        "status": "PASS" if all(item["pass"] for item in results) and unsigned_weak and results[6]["actual_http"] == 401 else "FAIL",
        "limits": "Synthetic one-process loopback service; no upstream vulnerability, external target, real identity, or CVP approval is established.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output)
    print(json.dumps({"status": result["status"], "cases": len(result["cases"]), "receipt": str(args.output)}, ensure_ascii=False))
    raise SystemExit(0 if result["status"] == "PASS" else 1)
