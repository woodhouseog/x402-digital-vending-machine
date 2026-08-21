import json
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from requests import Response

from scripts.x402_client_sdk import (
    RECIPIENT_WALLET,
    SCHEMA_GATE_AMOUNT_ATOMIC,
    SCHEMA_GATE_ENDPOINT,
    SCHEMA_GATE_NORMALIZER,
    SCHEMA_GATE_RECEIPT_TYPE,
    SOLANA_NETWORK,
    USDC_MINT,
    ProtocolError,
    SDKError,
    X402ClientSDK,
    _canonical_json,
    _schema_gate_binding,
    _sha256_text,
    build_acceptance_commitment,
)


CRITERIA = {
    "canonical_json": True,
    "required_fields": ["/sku", "/quantity"],
    "forbidden_patterns": ["<script"],
    "max_output_bytes": 4096,
    "normalizer_version": SCHEMA_GATE_NORMALIZER,
}


def response(payload, status=200, url="https://example.test"):
    value = Response()
    value.status_code = status
    value.url = url
    value.headers["Content-Type"] = "application/json"
    value._content = json.dumps(payload, separators=(",", ":")).encode()
    return value


class KeySession:
    def __init__(self, key_document):
        self.key_document = key_document

    def get(self, endpoint, headers=None, timeout=None):
        return response(self.key_document, url=endpoint)


class RecoverySession:
    def __init__(self, order_id, token):
        self.order_id = order_id
        self.token = token
        self.called = None

    def get(self, endpoint, headers=None, timeout=None):
        self.called = (endpoint, headers, timeout)
        return response(
            {
                "order_id": self.order_id,
                "status": "awaiting_payment",
                "recovery": {"url": endpoint, "token": self.token},
            },
            url=endpoint,
        )


class SchemaGateSDKTests(unittest.TestCase):
    def test_strict_policy_commitment_matches_documented_example(self):
        self.assertEqual(
            build_acceptance_commitment(CRITERIA),
            "sha256:f3f8f6ac94fdc2d4eac59f404f26c1eb6cadb63a2625cd6642a0a7a2240b1c63",
        )
        with self.assertRaises(SDKError):
            build_acceptance_commitment({"quantity_limit": 10})
        self.assertEqual(_canonical_json({"number": 1.0}), '{"number":1}')

    def test_schema_gate_requires_eight_character_idempotency_key(self):
        client = X402ClientSDK(session=KeySession({}))
        with self.assertRaisesRegex(SDKError, "8-128"):
            client.schema_gate(
                order_id="order-1",
                idempotency_key="short",
                input={"sku": "A-7"},
                target_schema={"type": "object"},
                acceptance_criteria=CRITERIA,
            )

    def test_schema_gate_rejects_any_price_other_than_exact_10000(self):
        client = X402ClientSDK(session=KeySession({}))
        challenge = {
            "x402Version": 2,
            "resource": {"url": SCHEMA_GATE_ENDPOINT},
            "accepts": [
                {
                    "scheme": "exact",
                    "network": SOLANA_NETWORK,
                    "amount": "9999",
                    "asset": USDC_MINT,
                    "payTo": RECIPIENT_WALLET,
                    "extra": {
                        "feePayer": "fee-payer",
                        "memo": "memo",
                        "challengeId": "challenge",
                    },
                }
            ],
        }
        with self.assertRaisesRegex(ProtocolError, "10000"):
            client._validate_payment_required(
                challenge,
                expected_endpoint=SCHEMA_GATE_ENDPOINT,
                expected_amount=SCHEMA_GATE_AMOUNT_ATOMIC,
            )

    def test_explicit_recovery_uses_bearer_token_and_cannot_pay(self):
        order_id = "order-1042"
        token = "sg_test-token"
        session = RecoverySession(order_id, token)
        client = X402ClientSDK(session=session)
        recovered = client.recover_order(
            order_id=order_id,
            recovery_token=token,
            idempotency_key="order-1042-v1",
            input={"sku": "A-7", "quantity": 2},
            target_schema={"type": "object"},
            acceptance_criteria=CRITERIA,
        )
        self.assertEqual(recovered["status"], "awaiting_payment")
        self.assertEqual(session.called[1]["Authorization"], f"Bearer {token}")

    def test_es256_receipt_is_verified_and_bound_to_result(self):
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        x = X402ClientSDK._base64url_encode(numbers.x.to_bytes(32, "big"))
        y = X402ClientSDK._base64url_encode(numbers.y.to_bytes(32, "big"))
        kid = "test-schema-gate-key"
        key_document = {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "alg": "ES256",
                    "use": "sig",
                    "kid": kid,
                    "x": x,
                    "y": y,
                }
            ],
            "receipt_type": SCHEMA_GATE_RECEIPT_TYPE,
            "canonicalization": SCHEMA_GATE_NORMALIZER,
        }
        client = X402ClientSDK(session=KeySession(key_document))
        commitment = build_acceptance_commitment(CRITERIA)
        binding = _schema_gate_binding(
            order_id="order-1042",
            idempotency_key="order-1042-v1",
            input_value={"sku": "A-7", "quantity": 2},
            target_schema={"type": "object"},
            acceptance_commitment=commitment,
            expires_at=None,
        )
        output = {"quantity": 2, "sku": "A-7"}
        checks = [{"check": "canonical_json", "passed": True}]
        payment = {
            "success": True,
            "transaction": "test-settlement",
            "network": SOLANA_NETWORK,
        }
        recovery = {
            "url": "https://www.x402digitalvendingmachine.store/v1/orders/order-1042",
            "token": "sg_test-token",
        }
        payload = {
            "receipt_version": 1,
            "service": "x402-schema-gate",
            "service_version": SCHEMA_GATE_NORMALIZER,
            "outcome": "paid_evaluation_delivered",
            "verdict": "ACCEPT",
            "order_id": binding["order_id"],
            "idempotency_hash": binding["idempotency_hash"],
            "request_hash": binding["request_hash"],
            "acceptance_commitment": binding["acceptance_commitment"],
            "input_hash": binding["input_hash"],
            "schema_hash": binding["schema_hash"],
            "output_hash": _sha256_text(_canonical_json(output)),
            "checks": checks,
            "payment": {
                "authorization_hash": "authorization-hash",
                "settlement_transaction": "test-settlement",
                "payer": "test-payer",
                "network": SOLANA_NETWORK,
                "asset": USDC_MINT,
                "pay_to": RECIPIENT_WALLET,
                "amount_atomic": SCHEMA_GATE_AMOUNT_ATOMIC,
                "settlement_response_hash": _sha256_text(_canonical_json(payment)),
            },
            "timestamps": {
                "verified_at": 1,
                "checked_at": 1,
                "settled_at": 1,
                "delivered_at": 1,
            },
            "recovery": recovery,
        }
        protected = {"alg": "ES256", "kid": kid, "typ": SCHEMA_GATE_RECEIPT_TYPE}
        signing_input = (
            X402ClientSDK._base64url_encode(_canonical_json(protected).encode())
            + "."
            + X402ClientSDK._base64url_encode(_canonical_json(payload).encode())
        ).encode("ascii")
        der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = X402ClientSDK._base64url_encode(
            r.to_bytes(32, "big") + s.to_bytes(32, "big")
        )
        result = {
            "order_id": "order-1042",
            "status": "delivered",
            "verdict": "ACCEPT",
            "output": output,
            "canonical_json": _canonical_json(output),
            "checks": checks,
            "payment": payment,
            "recovery": recovery,
            "receipt": {
                "protected": protected,
                "payload": payload,
                "signature": signature,
            },
        }
        parsed = client._parse_schema_gate_result(response(result), binding=binding)
        self.assertTrue(parsed["receipt_verified"])

        result["output"] = {"sku": "tampered", "quantity": 2}
        with self.assertRaisesRegex(ProtocolError, "output_hash"):
            client._parse_schema_gate_result(response(result), binding=binding)


if __name__ == "__main__":
    unittest.main()
