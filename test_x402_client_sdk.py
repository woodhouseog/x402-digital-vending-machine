import base64
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from requests import Response

from scripts.x402_client_sdk import (
    RECIPIENT_WALLET,
    EXECUTION_GATE_ENDPOINT,
    EXECUTION_GATE_RECEIPT_TYPE,
    EXECUTION_RECEIPT_KEY_ENDPOINT,
    SCHEMA_GATE_AMOUNT_ATOMIC,
    SCHEMA_GATE_ENDPOINT,
    SCHEMA_GATE_NORMALIZER,
    SCHEMA_GATE_RECOVERY_TOKEN_HEADER,
    SCHEMA_GATE_RECOVERY_URL_HEADER,
    SCHEMA_GATE_RECEIPT_TYPE,
    SOLANA_NETWORK,
    USDC_MINT,
    ProtocolError,
    SDKError,
    X402ClientSDK,
    _canonical_json,
    _execution_gate_binding,
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


class PendingExecutionRecoverySession:
    def __init__(self, order_id, token):
        self.order_id = order_id
        self.token = token
        self.get_calls = []
        self.post_calls = []

    def get(self, endpoint, headers=None, timeout=None):
        self.get_calls.append((endpoint, headers, timeout))
        return response(
            {
                "order_id": self.order_id,
                "status": "EXECUTION_UNKNOWN",
                "payment_settled": True,
                "outcome_unknown": True,
            },
            status=202,
            url=endpoint,
        )

    def post(self, endpoint, json=None, headers=None, timeout=None):
        self.post_calls.append((endpoint, json, headers, timeout))
        raise AssertionError("recovery must never POST or initiate payment")


class AmbiguousExecutionSession:
    def __init__(self, challenge):
        self.challenge = challenge
        self.post_calls = []

    def post(self, endpoint, json=None, headers=None, timeout=None):
        self.post_calls.append((endpoint, json, headers, timeout))
        if len(self.post_calls) == 1:
            challenged = response(self.challenge, status=402, url=endpoint)
            challenged.headers["PAYMENT-REQUIRED"] = base64.b64encode(
                _canonical_json(self.challenge).encode()
            ).decode()
            return challenged
        raise requests.ConnectionError("ambiguous paid transport failure")


class AmbiguousSchemaSession:
    def __init__(self, challenge, recovery_headers):
        self.challenge = challenge
        self.recovery_headers = recovery_headers
        self.post_calls = []

    def post(self, endpoint, json=None, headers=None, timeout=None):
        self.post_calls.append((endpoint, json, dict(headers or {}), timeout))
        if len(self.post_calls) == 1:
            challenged = response(self.challenge, status=402, url=endpoint)
            challenged.headers["PAYMENT-REQUIRED"] = base64.b64encode(
                _canonical_json(self.challenge).encode()
            ).decode()
            challenged.headers.update(self.recovery_headers)
            return challenged
        raise requests.ConnectionError("ambiguous paid transport failure")


class FakeExecutionHTTPClient:
    def __init__(self, challenge):
        self.challenge = challenge

    def handle_402_response(self, _headers, _content, _url):
        envelope = {
            "x402Version": 2,
            "resource": self.challenge["resource"],
            "accepted": self.challenge["accepts"][0],
            "payload": {
                "transaction": base64.b64encode(b"signed-transaction").decode()
            },
        }
        return {
            "PAYMENT-SIGNATURE": base64.b64encode(
                _canonical_json(envelope).encode()
            ).decode()
        }, object()


class CapturingSchemaHTTPClient:
    def __init__(self):
        self.payment_required = None
        self.payment_envelope = None

    def handle_402_response(self, headers, _content, _url):
        encoded = next(
            value
            for key, value in headers.items()
            if key.lower() == "payment-required"
        )
        self.payment_required = json.loads(base64.b64decode(encoded))
        self.payment_envelope = {
            "x402Version": 2,
            "resource": self.payment_required["resource"],
            "accepted": self.payment_required["accepts"][0],
            "payload": {
                "transaction": base64.b64encode(b"signed-transaction").decode()
            },
            "extensions": self.payment_required.get("extensions"),
        }
        return {
            "PAYMENT-SIGNATURE": base64.b64encode(
                _canonical_json(self.payment_envelope).encode()
            ).decode()
        }, object()


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

    def test_schema_gate_prefers_headers_and_never_echoes_recovery_bearer(self):
        order_id = "order-1042"
        commitment = build_acceptance_commitment(CRITERIA)
        binding = _schema_gate_binding(
            order_id=order_id,
            idempotency_key="order-1042-v1",
            input_value={"sku": "A-7", "quantity": 2},
            target_schema={"type": "object"},
            acceptance_commitment=commitment,
            expires_at=None,
        )
        expected_info = {
            "orderId": order_id,
            "requestHash": binding["request_hash"],
            "acceptanceCommitment": commitment,
            "recovery": {
                "url": f"https://www.x402digitalvendingmachine.store/v1/orders/{order_id}",
                "token": "sg_info-token",
            },
        }
        challenge = {
            "x402Version": 2,
            "resource": {"url": SCHEMA_GATE_ENDPOINT},
            "accepts": [{
                "scheme": "exact",
                "network": SOLANA_NETWORK,
                "amount": str(SCHEMA_GATE_AMOUNT_ATOMIC),
                "asset": USDC_MINT,
                "payTo": RECIPIENT_WALLET,
                "extra": {
                    "feePayer": "not-the-buyer",
                    "memo": "memo",
                    "challengeId": "challenge",
                    "schemaGateExtensionVersion": "2",
                },
            }],
            "extensions": {"schemaGate": {
                "info": expected_info,
                "schema": {"type": "object"},
                "orderId": "legacy-wrong-order",
                "requestHash": "legacy-wrong-hash",
                "acceptanceCommitment": "legacy-wrong-commitment",
                "recovery": {
                    "url": f"https://www.x402digitalvendingmachine.store/v1/orders/{order_id}",
                    "token": "sg_legacy-token",
                },
            }},
        }
        recovery = {
            SCHEMA_GATE_RECOVERY_URL_HEADER:
                f"https://www.x402digitalvendingmachine.store/v1/orders/{order_id}",
            SCHEMA_GATE_RECOVERY_TOKEN_HEADER: "sg_header-token",
        }
        session = AmbiguousSchemaSession(challenge, recovery)
        fake_http = CapturingSchemaHTTPClient()
        client = X402ClientSDK(session=session)
        with (
            patch("scripts.x402_client_sdk.x402ClientSync", return_value=object()),
            patch("scripts.x402_client_sdk.register_exact_svm_client"),
            patch("scripts.x402_client_sdk.KeypairSigner", return_value=object()),
            patch(
                "scripts.x402_client_sdk.x402HTTPClientSync",
                return_value=fake_http,
            ),
        ):
            with self.assertRaises(SDKError) as raised:
                client.schema_gate(
                    order_id=order_id,
                    idempotency_key="order-1042-v1",
                    input={"sku": "A-7", "quantity": 2},
                    target_schema={"type": "object"},
                    acceptance_criteria=CRITERIA,
                    wallet_key=bytes(range(32)),
                )

        self.assertEqual(raised.exception.recovery["token"], "sg_header-token")
        sanitized = fake_http.payment_required["extensions"]["schemaGate"]
        self.assertNotIn("recovery", sanitized)
        self.assertNotIn("recovery", sanitized["info"])
        paid_headers = session.post_calls[1][2]
        payment_envelope = json.loads(
            base64.b64decode(paid_headers["PAYMENT-SIGNATURE"])
        )
        self.assertNotIn("sg_header-token", _canonical_json(payment_envelope))
        self.assertNotIn("sg_info-token", _canonical_json(payment_envelope))
        self.assertNotIn("sg_legacy-token", _canonical_json(payment_envelope))

    def test_schema_gate_recovery_falls_back_to_info_then_legacy(self):
        order_id = "order-1042"
        url = f"https://www.x402digitalvendingmachine.store/v1/orders/{order_id}"
        client = X402ClientSDK(session=KeySession({}))
        challenge = {
            "extensions": {"schemaGate": {
                "info": {"recovery": {"url": url, "token": "sg_info-token"}},
                "recovery": {"url": url, "token": "sg_legacy-token"},
            }}
        }
        self.assertEqual(
            client._extract_schema_gate_recovery({}, challenge, order_id=order_id)[
                "token"
            ],
            "sg_info-token",
        )
        del challenge["extensions"]["schemaGate"]["info"]["recovery"]
        self.assertEqual(
            client._extract_schema_gate_recovery({}, challenge, order_id=order_id)[
                "token"
            ],
            "sg_legacy-token",
        )
        with self.assertRaisesRegex(ProtocolError, "supplied together"):
            client._extract_schema_gate_recovery(
                {SCHEMA_GATE_RECOVERY_URL_HEADER: url},
                challenge,
                order_id=order_id,
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


class ExecutionGateSDKTests(unittest.TestCase):
    def execution_values(self):
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        token = "v1." + ("a" * 43)
        values = {
            "order_id": "execution-1042",
            "idempotency_key": "execution-1042-v1",
            "integration_id": "canary",
            "integration_version": "v1",
            "action_id": "commit",
            "input": {"sku": "A-7", "quantity": 2},
            "target_schema": {"type": "object"},
            "acceptance_criteria": CRITERIA,
            "expires_at": expires_at,
            "audience": "urn:x402:receiver:canary",
            "environment": "pilot",
            "configuration_hash": f"sha256:{'1' * 64}",
            "policy_hash": f"sha256:{'2' * 64}",
            "qualification_report_hash": f"sha256:{'3' * 64}",
            "amount_atomic": 17500,
            "recovery_token": token,
        }
        values["binding"] = _execution_gate_binding(**values)
        return values

    def test_execution_receipt_strictly_binds_prepare_commit_effect_and_settlement(self):
        values = self.execution_values()
        binding = values["binding"]
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        kid = "execution-receipt-test-key"
        key_document = {
            "keys": [{
                "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
                "kid": kid,
                "x": X402ClientSDK._base64url_encode(numbers.x.to_bytes(32, "big")),
                "y": X402ClientSDK._base64url_encode(numbers.y.to_bytes(32, "big")),
            }],
            "receipt_type": EXECUTION_GATE_RECEIPT_TYPE,
            "service": "x402-execution-gate",
        }
        result = {
            "status": "EXECUTED",
            "nonce": "dispatch-nonce-1",
            "aud": values["audience"],
            "integration_id": values["integration_id"],
            "integration_version": values["integration_version"],
            "action_id": values["action_id"],
            "configuration_hash": values["configuration_hash"],
            "policy_hash": values["policy_hash"],
            "payload_hash": binding["payload_hash"],
            "order_id": values["order_id"],
            "settlement_id": "settlement-signature-1",
            "effect_id": f"sha256:{'4' * 64}",
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt_payload = {
            "receipt_version": 1,
            "service": "x402-execution-gate",
            "environment": values["environment"],
            "audience": values["audience"],
            "integration_id": values["integration_id"],
            "integration_version": values["integration_version"],
            "action_id": values["action_id"],
            "order_id": values["order_id"],
            "idempotency_hash": binding["idempotency_hash"],
            "request_hash": binding["request_hash"],
            "configuration_hash": values["configuration_hash"],
            "policy_hash": values["policy_hash"],
            "qualification_report_hash": values["qualification_report_hash"],
            "payload_hash": binding["payload_hash"],
            "dispatch_nonce": result["nonce"],
            "payment_id": "payment-proof-id-1",
            "network": SOLANA_NETWORK,
            "asset": USDC_MINT,
            "recipient": RECIPIENT_WALLET,
            "amount_atomic": values["amount_atomic"],
            "payer": "payer-wallet-1",
            "settlement_id": result["settlement_id"],
            "prepare_jti": "prepare-jti-1",
            "prepare_permit_hash": f"sha256:{'5' * 64}",
            "prepare_ack_hash": f"sha256:{'6' * 64}",
            "commit_jti": "commit-jti-1",
            "commit_permit_hash": f"sha256:{'7' * 64}",
            "commit_ack_hash": f"sha256:{'8' * 64}",
            "effect_id": result["effect_id"],
            "effect_ack_hash": f"sha256:{'8' * 64}",
            "result_hash": f"sha256:{_sha256_text(_canonical_json(result))}",
            "recovery_url": f"https://www.x402digitalvendingmachine.store/v1/executions/{values['order_id']}",
            "recovery_token_hash": _sha256_text(values["recovery_token"]),
            "executed_at": result["executed_at"],
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }
        protected = {"alg": "ES256", "kid": kid, "typ": EXECUTION_GATE_RECEIPT_TYPE}
        signing_input = (
            X402ClientSDK._base64url_encode(_canonical_json(protected).encode())
            + "."
            + X402ClientSDK._base64url_encode(_canonical_json(receipt_payload).encode())
        ).encode("ascii")
        der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        signature = X402ClientSDK._base64url_encode(
            r.to_bytes(32, "big") + s.to_bytes(32, "big")
        )
        final = {
            "order_id": values["order_id"],
            "status": "delivered",
            "payment_settled": True,
            "result": result,
            "receipt": {"protected": protected, "payload": receipt_payload, "signature": signature},
            "delivery": {"recovered": False},
        }
        settlement = {
            "success": True,
            "transaction": result["settlement_id"],
            "network": SOLANA_NETWORK,
        }
        final_response = response(final, url=EXECUTION_GATE_ENDPOINT)
        final_response.headers["PAYMENT-RESPONSE"] = base64.b64encode(
            _canonical_json(settlement).encode()
        ).decode()
        client = X402ClientSDK(session=KeySession(key_document))
        parsed = client._parse_execution_result(
            final_response,
            binding=binding,
            recovery_token=values["recovery_token"],
        )
        self.assertTrue(parsed["receipt_verified"])
        self.assertTrue(parsed["prepare_verified"])
        self.assertTrue(parsed["commit_verified"])
        self.assertTrue(parsed["execution_verified"])

        final["result"] = {**result, "effect_id": f"sha256:{'9' * 64}"}
        tampered = response(final, url=EXECUTION_GATE_ENDPOINT)
        tampered.headers["PAYMENT-RESPONSE"] = final_response.headers["PAYMENT-RESPONSE"]
        with self.assertRaisesRegex(ProtocolError, "effect_id|result_hash"):
            client._parse_execution_result(
                tampered,
                binding=binding,
                recovery_token=values["recovery_token"],
            )

    def test_execution_gate_never_blindly_retries_an_ambiguous_paid_request(self):
        values = self.execution_values()
        binding = values["binding"]
        challenge = {
            "x402Version": 2,
            "resource": {"url": EXECUTION_GATE_ENDPOINT},
            "accepts": [{
                "scheme": "exact", "network": SOLANA_NETWORK,
                "amount": str(values["amount_atomic"]), "asset": USDC_MINT,
                "payTo": RECIPIENT_WALLET, "maxTimeoutSeconds": 300,
                "extra": {"feePayer": "not-the-buyer", "memo": "memo", "challengeId": "challenge"},
            }],
            "extensions": {"executionGate": {
                "order_id": values["order_id"],
                "integration_id": values["integration_id"],
                "integration_version": values["integration_version"],
                "action_id": values["action_id"],
                "environment": values["environment"],
                "audience": values["audience"],
                "request_hash": binding["request_hash"],
                "configuration_hash": values["configuration_hash"],
                "policy_hash": values["policy_hash"],
                "qualification_report_hash": values["qualification_report_hash"],
                "expires_at": values["expires_at"],
                "permit_ttl_seconds": 180,
                "recovery": {
                    "url": f"https://www.x402digitalvendingmachine.store/v1/executions/{values['order_id']}",
                    "token": values["recovery_token"],
                },
            }},
        }
        session = AmbiguousExecutionSession(challenge)
        client = X402ClientSDK(session=session)
        wallet = bytes(range(32))
        fake_http = FakeExecutionHTTPClient(challenge)
        with (
            patch("scripts.x402_client_sdk.x402ClientSync", return_value=object()),
            patch("scripts.x402_client_sdk.register_exact_svm_client"),
            patch("scripts.x402_client_sdk.KeypairSigner", return_value=object()),
            patch("scripts.x402_client_sdk.x402HTTPClientSync", return_value=fake_http),
        ):
            with self.assertRaises(SDKError) as raised:
                client.execution_gate(
                    order_id=values["order_id"],
                    idempotency_key=values["idempotency_key"],
                    integration_id=values["integration_id"],
                    integration_version=values["integration_version"],
                    action_id=values["action_id"],
                    input=values["input"],
                    target_schema=values["target_schema"],
                    acceptance_criteria=values["acceptance_criteria"],
                    expires_at=values["expires_at"],
                    max_amount_atomic=values["amount_atomic"],
                    wallet_key=wallet,
                )
        self.assertEqual(len(session.post_calls), 2)
        self.assertEqual(raised.exception.recovery["token"], values["recovery_token"])

    def test_recover_execution_is_get_only_and_never_creates_payment(self):
        values = self.execution_values()
        session = PendingExecutionRecoverySession(values["order_id"], values["recovery_token"])
        client = X402ClientSDK(session=session)
        recovered = client.recover_execution(
            order_id=values["order_id"],
            recovery_token=values["recovery_token"],
            idempotency_key=values["idempotency_key"],
            integration_id=values["integration_id"],
            integration_version=values["integration_version"],
            action_id=values["action_id"],
            input=values["input"],
            target_schema=values["target_schema"],
            acceptance_criteria=values["acceptance_criteria"],
            expires_at=values["expires_at"],
        )
        self.assertEqual(recovered["status"], "EXECUTION_UNKNOWN")
        self.assertEqual(len(session.get_calls), 1)
        self.assertEqual(session.post_calls, [])
        self.assertEqual(session.get_calls[0][1]["Authorization"], f"Bearer {values['recovery_token']}")


if __name__ == "__main__":
    unittest.main()
def _base_first_payment_required() -> dict:
    endpoint = "https://www.x402digitalvendingmachine.store/v1/schema-gate"
    challenge_id = "challenge-base-first"
    return {
        "x402Version": 2,
        "error": "Payment required",
        "resource": {
            "url": endpoint,
            "description": "Schema Gate",
            "mimeType": "application/json",
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "amount": "10000",
                "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                "payTo": "0xCbE8df651925485046bFd42b736186433904F8a6",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "name": "USD Coin",
                    "version": "2",
                    "assetTransferMethod": "eip3009",
                    "challengeId": challenge_id,
                },
            },
            {
                "scheme": "exact",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "amount": "10000",
                "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "payTo": "E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD",
                "maxTimeoutSeconds": 300,
                "extra": {
                    "decimals": 6,
                    "feePayer": "E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD",
                    "memo": f"x402:{challenge_id}",
                    "challengeId": challenge_id,
                },
            },
        ],
    }


def test_evm_wallet_key_is_appended_to_public_methods():
    import inspect

    from scripts.x402_client_sdk import X402ClientSDK

    for method in (
        X402ClientSDK.clean_text,
        X402ClientSDK.schema_gate,
        X402ClientSDK.execution_gate,
    ):
        assert list(inspect.signature(method).parameters)[-1] == "evm_wallet_key"


def test_base_first_dual_accept_preserves_solana_for_existing_callers():
    from scripts.x402_client_sdk import X402ClientSDK

    challenge = _base_first_payment_required()
    metadata = X402ClientSDK()._validate_payment_required(
        challenge,
        expected_endpoint=challenge["resource"]["url"],
        expected_amount=10_000,
    )

    assert metadata.rail == "svm"
    assert metadata.accepted["network"].startswith("solana:")


def test_evm_wallet_prefers_base_and_validates_eip3009_payload():
    import base64
    import json

    from scripts.x402_client_sdk import X402ClientSDK

    challenge = _base_first_payment_required()
    endpoint = challenge["resource"]["url"]
    payer = "0x1111111111111111111111111111111111111111"
    sdk = X402ClientSDK()
    metadata = sdk._validate_payment_required(
        challenge,
        expected_endpoint=endpoint,
        expected_amount=10_000,
        prefer_base=True,
    )
    envelope = {
        "x402Version": 2,
        "resource": challenge["resource"],
        "accepted": metadata.accepted,
        "payload": {
            "signature": "0x" + ("ab" * 65),
            "authorization": {
                "from": payer,
                "to": metadata.accepted["payTo"],
                "value": metadata.accepted["amount"],
                "validAfter": "0",
                "validBefore": "9999999999",
                "nonce": "0x" + ("cd" * 32),
            },
        },
    }
    payment_header = base64.b64encode(
        json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")

    assert metadata.rail == "evm"
    assert metadata.accepted["network"] == "eip155:8453"
    sdk._validate_payment_payload(
        {"PAYMENT-SIGNATURE": payment_header},
        metadata,
        expected_endpoint=endpoint,
        expected_payer=payer,
    )


def test_official_x402_client_signs_selected_base_eip3009_offer():
    import base64
    import json

    from scripts.x402_client_sdk import X402ClientSDK

    challenge = _base_first_payment_required()
    endpoint = challenge["resource"]["url"]
    sdk = X402ClientSDK()
    metadata = sdk._validate_payment_required(
        challenge,
        expected_endpoint=endpoint,
        expected_amount=10_000,
        prefer_base=True,
    )
    http_client, payer = sdk._payment_client(
        metadata,
        wallet_key=None,
        keypair_path=None,
        evm_wallet_key="0x" + ("01" * 32),
    )
    encoded_required = base64.b64encode(
        json.dumps(challenge, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")

    payment_headers, payment_payload = http_client.handle_402_response(
        {"PAYMENT-REQUIRED": encoded_required},
        b"",
        endpoint,
    )

    assert payment_payload is not None
    sdk._validate_payment_payload(
        payment_headers,
        metadata,
        expected_endpoint=endpoint,
        expected_payer=payer,
    )


def test_base_accept_rejects_noncanonical_eip3009_terms():
    import copy

    import pytest

    from scripts.x402_client_sdk import ProtocolError, X402ClientSDK

    challenge = _base_first_payment_required()
    challenge["accepts"] = [challenge["accepts"][0]]
    endpoint = challenge["resource"]["url"]
    mutations = (
        ("network", "eip155:1"),
        ("asset", "0x1111111111111111111111111111111111111111"),
        ("payTo", "0x2222222222222222222222222222222222222222"),
        ("name", "Not USD Coin"),
        ("version", "1"),
        ("assetTransferMethod", "permit2"),
    )

    for field, value in mutations:
        malformed = copy.deepcopy(challenge)
        target = malformed["accepts"][0]
        if field in {"name", "version", "assetTransferMethod"}:
            target["extra"][field] = value
        else:
            target[field] = value
        with pytest.raises(ProtocolError):
            X402ClientSDK()._validate_payment_required(
                malformed,
                expected_endpoint=endpoint,
                expected_amount=10_000,
                prefer_base=True,
            )
