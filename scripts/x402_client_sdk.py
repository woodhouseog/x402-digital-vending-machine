#!/usr/bin/env python3
"""Canonical x402 v2 exact-SVM client for Schema Gate and legacy cleanup.

The buyer signs only the transfer-authority portion of the transaction. The
facilitator supplies the fee-payer signature, broadcasts, and settles it. This
client never broadcasts a payment itself.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional
from urllib.parse import quote

import requests
import rfc8785
from base58 import b58decode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from requests import Response, Session
from solders.keypair import Keypair
from x402 import x402ClientSync
from x402.http import x402HTTPClientSync
from x402.mechanisms.svm import KeypairSigner
from x402.mechanisms.svm.exact.register import register_exact_svm_client


SERVICE_ENDPOINT = "https://www.x402digitalvendingmachine.store/v1/clean"
SCHEMA_GATE_ENDPOINT = (
    "https://www.x402digitalvendingmachine.store/v1/schema-gate"
)
RECEIPT_KEY_ENDPOINT = (
    "https://www.x402digitalvendingmachine.store/.well-known/receipt-key.json"
)
MAINNET_RPC = "https://api.mainnet-beta.solana.com"
SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
RECIPIENT_WALLET = "E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD"
PAYMENT_AMOUNT_ATOMIC = 2_000
SCHEMA_GATE_AMOUNT_ATOMIC = 10_000
SCHEMA_GATE_NORMALIZER = "schema-gate-c14n-v1"
SCHEMA_GATE_MAX_OUTPUT_BYTES = 100_000
SCHEMA_GATE_RECEIPT_TYPE = "x402-schema-gate-receipt"
SCHEMA_GATE_OPERATION = "schema-gate-v1"
USDC_DECIMALS = 6
PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"


class SDKError(RuntimeError):
    """Base error raised by the public SDK."""

    def __init__(
        self,
        message: str,
        *,
        recovery: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.recovery = dict(recovery) if recovery else None


class ProtocolError(SDKError):
    """The service returned terms outside the pinned production contract."""


class PaymentError(SDKError):
    """The canonical x402 payment could not be created or settled."""


@dataclass(frozen=True)
class ChallengeMetadata:
    resource: dict[str, Any]
    accepted: dict[str, Any]
    fee_payer: str
    memo: str
    challenge_id: str
    amount_atomic: int
    schema_gate: dict[str, Any] | None = None


def _canonical_json(value: Any) -> str:
    try:
        return rfc8785.dumps(value).decode("utf-8")
    except (TypeError, ValueError, rfc8785.CanonicalizationError) as exc:
        raise SDKError("Value must contain only finite JSON data.") from exc


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_acceptance_criteria(
    acceptance_criteria: Any,
) -> dict[str, Any]:
    if not isinstance(acceptance_criteria, Mapping):
        raise SDKError("acceptance_criteria must be a JSON object.")
    exact_keys = {
        "canonical_json",
        "required_fields",
        "forbidden_patterns",
        "max_output_bytes",
        "normalizer_version",
    }
    if set(acceptance_criteria) != exact_keys:
        raise SDKError(
            "acceptance_criteria must contain exactly canonical_json, "
            "required_fields, forbidden_patterns, max_output_bytes, and "
            "normalizer_version."
        )
    if acceptance_criteria.get("canonical_json") is not True:
        raise SDKError("acceptance_criteria.canonical_json must be true.")

    required_fields = acceptance_criteria.get("required_fields")
    if (
        not isinstance(required_fields, list)
        or len(required_fields) > 64
        or any(
            not isinstance(pointer, str)
            or len(pointer) > 256
            or (pointer != "" and not pointer.startswith("/"))
            for pointer in required_fields
        )
    ):
        raise SDKError(
            "acceptance_criteria.required_fields must contain at most 64 "
            "bounded RFC 6901 JSON Pointers."
        )

    forbidden_patterns = acceptance_criteria.get("forbidden_patterns")
    if (
        not isinstance(forbidden_patterns, list)
        or len(forbidden_patterns) > 32
        or any(
            not isinstance(pattern, str)
            or not pattern
            or len(pattern) > 128
            for pattern in forbidden_patterns
        )
    ):
        raise SDKError(
            "acceptance_criteria.forbidden_patterns must contain at most 32 "
            "non-empty literal strings of at most 128 characters."
        )

    max_output_bytes = acceptance_criteria.get("max_output_bytes")
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or not 2 <= max_output_bytes <= SCHEMA_GATE_MAX_OUTPUT_BYTES
    ):
        raise SDKError(
            "acceptance_criteria.max_output_bytes must be an integer between "
            f"2 and {SCHEMA_GATE_MAX_OUTPUT_BYTES}."
        )
    if acceptance_criteria.get("normalizer_version") != SCHEMA_GATE_NORMALIZER:
        raise SDKError(
            "acceptance_criteria.normalizer_version must be "
            f"{SCHEMA_GATE_NORMALIZER}."
        )
    return {
        "canonical_json": True,
        "required_fields": list(required_fields),
        "forbidden_patterns": list(forbidden_patterns),
        "max_output_bytes": max_output_bytes,
        "normalizer_version": SCHEMA_GATE_NORMALIZER,
    }


def canonicalize_acceptance_criteria(acceptance_criteria: Any) -> str:
    """Return the deterministic JSON representation committed to the request."""
    return _canonical_json(_normalize_acceptance_criteria(acceptance_criteria))


def build_acceptance_commitment(acceptance_criteria: Any) -> str:
    """Build the SHA-256 commitment sent with every Schema Gate request."""
    canonical = canonicalize_acceptance_criteria(acceptance_criteria)
    digest = _sha256_text(canonical)
    return f"sha256:{digest}"


def _normalized_input(value: Any) -> Any:
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
            _canonical_json(decoded)
            return decoded
        except (json.JSONDecodeError, SDKError):
            return value
    _canonical_json(value)
    return value


def _expires_epoch(value: str | int | None, *, enforce_window: bool) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise SDKError("expires_at must be an RFC 3339 timestamp or epoch integer.")
    if isinstance(value, int):
        epoch = value
    elif isinstance(value, str) and value.strip():
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise SDKError("expires_at must be a valid RFC 3339 timestamp.") from exc
        if parsed.tzinfo is None:
            raise SDKError("expires_at must include an explicit timezone.")
        epoch = int(parsed.timestamp())
    else:
        raise SDKError("expires_at must be an RFC 3339 timestamp or epoch integer.")
    if enforce_window:
        now = int(datetime.now(timezone.utc).timestamp())
        if epoch <= now + 30 or epoch > now + 86_400:
            raise SDKError("expires_at must be 30 seconds to 24 hours in the future.")
    return epoch


def _schema_gate_binding(
    *,
    order_id: str,
    idempotency_key: str,
    input_value: Any,
    target_schema: Mapping[str, Any],
    acceptance_commitment: str,
    expires_at: str | int | None,
) -> dict[str, str | int | None]:
    normalized_input = _normalized_input(input_value)
    input_hash = _sha256_text(_canonical_json(normalized_input))
    schema_hash = _sha256_text(_canonical_json(dict(target_schema)))
    idempotency_hash = _sha256_text(idempotency_key)
    expires_epoch = _expires_epoch(expires_at, enforce_window=False)
    request_hash = _sha256_text(
        _canonical_json(
            {
                "operation": SCHEMA_GATE_OPERATION,
                "order_id": order_id,
                "idempotency_hash": idempotency_hash,
                "input_hash": input_hash,
                "schema_hash": schema_hash,
                "acceptance_commitment": acceptance_commitment,
                "expires_at": expires_epoch,
            }
        )
    )
    return {
        "order_id": order_id,
        "idempotency_hash": idempotency_hash,
        "input_hash": input_hash,
        "schema_hash": schema_hash,
        "request_hash": request_hash,
        "acceptance_commitment": acceptance_commitment,
        "expires_at": expires_epoch,
    }


class X402ClientSDK:
    """Client for the pinned Schema Gate and legacy cleanup endpoints."""

    def __init__(
        self,
        endpoint: str = SERVICE_ENDPOINT,
        rpc_url: str = MAINNET_RPC,
        timeout_seconds: float = 30,
        session: Session | None = None,
    ) -> None:
        if endpoint.rstrip("/") != SERVICE_ENDPOINT:
            raise SDKError(
                "This production client is pinned to "
                f"{SERVICE_ENDPOINT}; refusing endpoint {endpoint!r}."
            )
        self.endpoint = SERVICE_ENDPOINT
        self.rpc_url = rpc_url
        self.timeout_seconds = timeout_seconds
        self.session = session or requests.Session()
        self.last_recovery: dict[str, Any] | None = None
        self._receipt_key: dict[str, Any] | None = None

    def clean_text(
        self,
        text: str,
        keypair_path: Optional[str] = None,
        wallet_key: Optional[Any] = None,
        verify_signature: bool = True,
        keypair_timeout_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Buy one cleanup and return structured JSON plus settlement receipt.

        The final two arguments remain accepted for source compatibility. The
        canonical facilitator flow is synchronous, so the legacy client-side
        broadcast controls no longer change payment behavior.
        """
        del verify_signature, keypair_timeout_seconds

        if not isinstance(text, str) or not text.strip():
            raise SDKError("Text input must be a non-empty string.")
        if keypair_path and wallet_key is not None:
            raise SDKError("Provide either wallet_key or keypair_path, not both.")
        if not keypair_path and wallet_key is None:
            raise SDKError(
                "Purchase requires wallet_key or a local Solana keypair_path."
            )

        probe = self._post_clean(text)
        if probe.status_code == 200:
            return self._parse_json_object(probe, "service response")
        if probe.status_code != 402:
            self._raise_http_error(probe, "Expected an x402 payment challenge")

        encoded_required = probe.headers.get(PAYMENT_REQUIRED_HEADER)
        if not encoded_required:
            raise ProtocolError(
                f"HTTP 402 response omitted {PAYMENT_REQUIRED_HEADER}."
            )
        payment_required = self._decode_base64_json(
            encoded_required, PAYMENT_REQUIRED_HEADER
        )
        metadata = self._validate_payment_required(payment_required)

        payer = (
            self._coerce_keypair(wallet_key)
            if wallet_key is not None
            else self._load_keypair(keypair_path or "")
        )
        if str(payer.pubkey()) == metadata.fee_payer:
            raise ProtocolError(
                "Buyer authority cannot also be the facilitator fee payer."
            )

        core_client = x402ClientSync()
        register_exact_svm_client(
            core_client,
            KeypairSigner(payer),
            networks=SOLANA_NETWORK,
            rpc_url=self.rpc_url,
        )
        http_client = x402HTTPClientSync(core_client)

        response_headers = dict(probe.headers)
        response_headers[PAYMENT_REQUIRED_HEADER] = encoded_required
        try:
            payment_headers, payment_payload = http_client.handle_402_response(
                response_headers,
                probe.content,
                probe.url,
            )
        except Exception as exc:
            raise PaymentError(
                f"Could not create canonical exact-SVM payment payload: {exc}"
            ) from exc
        if payment_payload is None:
            raise ProtocolError("x402 client did not create a payment payload.")
        self._validate_payment_payload(payment_headers, metadata)

        # Exactly one paid resubmission. Never automatically replay a monetary
        # request after an ambiguous connection failure.
        paid_response = self._post_clean(text, extra_headers=payment_headers)
        try:
            processed = http_client.process_payment_result(
                payment_payload,
                lambda name: paid_response.headers.get(name),
                paid_response.status_code,
            )
        except Exception as exc:
            raise ProtocolError(
                f"Invalid PAYMENT-RESPONSE settlement header: {exc}"
            ) from exc

        settle_response = processed.settle_response
        if paid_response.status_code != 200:
            if settle_response is not None:
                settlement_error = settle_response.model_dump(
                    mode="json", by_alias=True
                )
                raise PaymentError(
                    "Facilitator rejected settlement: "
                    f"{settlement_error.get('errorReason') or settlement_error}"
                )
            self._raise_http_error(
                paid_response, "x402 settlement or service delivery failed"
            )
        if settle_response is None:
            raise ProtocolError("Paid response omitted PAYMENT-RESPONSE.")

        settlement = settle_response.model_dump(mode="json", by_alias=True)
        if settlement.get("success") is not True:
            reason = settlement.get("errorReason") or settlement.get("error")
            raise PaymentError(
                f"Facilitator did not confirm settlement: {reason or settlement}"
            )

        result = self._parse_json_object(paid_response, "paid service response")
        result.setdefault("payment_response", settlement)
        return result

    def schema_gate(
        self,
        *,
        order_id: str,
        idempotency_key: str,
        input: Any,
        target_schema: Mapping[str, Any],
        acceptance_criteria: Any,
        wallet_key: Optional[Any] = None,
        keypair_path: Optional[str] = None,
        expires_at: str | int | None = None,
        max_amount_atomic: int = SCHEMA_GATE_AMOUNT_ATOMIC,
    ) -> dict[str, Any]:
        """Purchase one signed Schema Gate evaluation or recover its receipt.

        The initial request is always unsigned. Wallet material is loaded only
        after the service returns a valid HTTP 402 challenge. An exact retry of
        an already completed idempotency key can therefore return its recovery
        response without creating another payment.
        """
        if (
            not isinstance(order_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", order_id)
            is None
        ):
            raise SDKError("order_id must be 1-128 URL-safe characters.")
        if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 128:
            raise SDKError("idempotency_key must be 8-128 characters.")
        if not isinstance(target_schema, Mapping) or not target_schema:
            raise SDKError("target_schema must be a non-empty JSON object.")
        if keypair_path and wallet_key is not None:
            raise SDKError("Provide either wallet_key or keypair_path, not both.")
        if (
            isinstance(max_amount_atomic, bool)
            or not isinstance(max_amount_atomic, int)
            or max_amount_atomic != SCHEMA_GATE_AMOUNT_ATOMIC
        ):
            raise SDKError(
                "Schema Gate authorizes exactly 10000 atomic USDC; "
                "max_amount_atomic cannot change that price."
            )
        _expires_epoch(expires_at, enforce_window=True)

        normalized_criteria = _normalize_acceptance_criteria(acceptance_criteria)
        commitment = build_acceptance_commitment(normalized_criteria)
        body: dict[str, Any] = {
            "order_id": order_id,
            "idempotency_key": idempotency_key,
            "input": input,
            "target_schema": dict(target_schema),
            "acceptance_criteria": normalized_criteria,
            "acceptance_commitment": commitment,
        }
        if expires_at is not None:
            body["expires_at"] = expires_at.strip() if isinstance(expires_at, str) else expires_at
        _canonical_json(body)
        binding = _schema_gate_binding(
            order_id=order_id,
            idempotency_key=idempotency_key,
            input_value=input,
            target_schema=target_schema,
            acceptance_commitment=commitment,
            expires_at=expires_at,
        )

        probe = self._post_json(SCHEMA_GATE_ENDPOINT, body)
        if probe.status_code == 200:
            return self._parse_schema_gate_result(
                probe,
                binding=binding,
            )
        if probe.status_code != 402:
            self._raise_http_error(
                probe, "Schema Gate preflight did not return a payment challenge"
            )

        encoded_required = probe.headers.get(PAYMENT_REQUIRED_HEADER)
        if not encoded_required:
            raise ProtocolError(
                f"HTTP 402 response omitted {PAYMENT_REQUIRED_HEADER}."
            )
        payment_required = self._decode_base64_json(
            encoded_required, PAYMENT_REQUIRED_HEADER
        )
        metadata = self._validate_payment_required(
            payment_required,
            expected_endpoint=SCHEMA_GATE_ENDPOINT,
            expected_amount=SCHEMA_GATE_AMOUNT_ATOMIC,
        )
        schema_gate_terms = metadata.schema_gate
        if not schema_gate_terms:
            raise ProtocolError("Schema Gate challenge omitted extensions.schemaGate.")
        expected_challenge_fields = {
            "orderId": order_id,
            "requestHash": binding["request_hash"],
            "acceptanceCommitment": commitment,
        }
        for field, expected in expected_challenge_fields.items():
            if schema_gate_terms.get(field) != expected:
                raise ProtocolError(
                    f"Schema Gate challenge changed extensions.schemaGate.{field}."
                )
        recovery = schema_gate_terms.get("recovery")
        if (
            not isinstance(recovery, dict)
            or recovery.get("url")
            != f"https://www.x402digitalvendingmachine.store/v1/orders/{quote(order_id, safe='')}"
            or not isinstance(recovery.get("token"), str)
            or not recovery["token"].startswith("sg_")
        ):
            raise ProtocolError("Schema Gate challenge omitted valid recovery terms.")
        self.last_recovery = dict(recovery)

        if not keypair_path and wallet_key is None:
            raise SDKError(
                "A new Schema Gate evaluation requires wallet_key or "
                "a local Solana keypair_path.",
                recovery=self.last_recovery,
            )
        payer = (
            self._coerce_keypair(wallet_key)
            if wallet_key is not None
            else self._load_keypair(keypair_path or "")
        )
        if str(payer.pubkey()) == metadata.fee_payer:
            raise ProtocolError(
                "Buyer authority cannot also be the facilitator fee payer."
            )

        core_client = x402ClientSync()
        register_exact_svm_client(
            core_client,
            KeypairSigner(payer),
            networks=SOLANA_NETWORK,
            rpc_url=self.rpc_url,
        )
        http_client = x402HTTPClientSync(core_client)
        response_headers = dict(probe.headers)
        response_headers[PAYMENT_REQUIRED_HEADER] = encoded_required
        try:
            payment_headers, payment_payload = http_client.handle_402_response(
                response_headers,
                probe.content,
                probe.url,
            )
        except Exception as exc:
            raise PaymentError(
                f"Could not create canonical exact-SVM payment payload: {exc}",
                recovery=self.last_recovery,
            ) from exc
        if payment_payload is None:
            raise ProtocolError(
                "x402 client did not create a payment payload.",
                recovery=self.last_recovery,
            )
        self._validate_payment_payload(
            payment_headers,
            metadata,
            expected_endpoint=SCHEMA_GATE_ENDPOINT,
        )

        # A monetary request is sent exactly once. Ambiguous transport failures
        # are recovered by repeating the unsigned idempotent call, not by
        # automatically creating another payment.
        try:
            paid_response = self._post_json(
                SCHEMA_GATE_ENDPOINT, body, extra_headers=payment_headers
            )
        except SDKError as exc:
            if exc.recovery is None:
                exc.recovery = self.last_recovery
            raise
        try:
            processed = http_client.process_payment_result(
                payment_payload,
                lambda name: paid_response.headers.get(name),
                paid_response.status_code,
            )
        except Exception as exc:
            raise ProtocolError(
                f"Invalid PAYMENT-RESPONSE settlement header: {exc}",
                recovery=self.last_recovery,
            ) from exc

        settle_response = processed.settle_response
        if paid_response.status_code != 200:
            if settle_response is not None:
                settlement_error = settle_response.model_dump(
                    mode="json", by_alias=True
                )
                raise PaymentError(
                    "Facilitator rejected settlement: "
                    f"{settlement_error.get('errorReason') or settlement_error}",
                    recovery=self.last_recovery,
                )
            self._raise_http_error(
                paid_response, "Schema Gate settlement or evaluation failed"
            )
        if settle_response is None:
            raise ProtocolError(
                "Paid response omitted PAYMENT-RESPONSE.",
                recovery=self.last_recovery,
            )
        settlement = settle_response.model_dump(mode="json", by_alias=True)
        if settlement.get("success") is not True:
            reason = settlement.get("errorReason") or settlement.get("error")
            raise PaymentError(
                f"Facilitator did not confirm settlement: {reason or settlement}",
                recovery=self.last_recovery,
            )

        result = self._parse_schema_gate_result(
            paid_response,
            binding=binding,
        )
        result.setdefault("payment_response", settlement)
        result.setdefault("amount_atomic", metadata.amount_atomic)
        return result

    def gate_json(self, **kwargs: Any) -> dict[str, Any]:
        """Alias for :meth:`schema_gate`."""
        return self.schema_gate(**kwargs)

    def recover_order(
        self,
        *,
        order_id: str,
        recovery_token: str,
        idempotency_key: str,
        input: Any,
        target_schema: Mapping[str, Any],
        acceptance_criteria: Any,
        expires_at: str | int | None = None,
    ) -> dict[str, Any]:
        """Recover a prior order by token without creating a new payment.

        Original request material is required so the signed receipt can be
        bound to the exact order rather than merely signature-checked.
        """
        if (
            not isinstance(order_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", order_id)
            is None
        ):
            raise SDKError("order_id must be 1-128 URL-safe characters.")
        if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 128:
            raise SDKError("idempotency_key must be 8-128 characters.")
        if not isinstance(recovery_token, str) or not recovery_token.startswith("sg_"):
            raise SDKError("recovery_token must be the server-issued sg_ token.")
        if not isinstance(target_schema, Mapping) or not target_schema:
            raise SDKError("target_schema must be a non-empty JSON object.")
        criteria = _normalize_acceptance_criteria(acceptance_criteria)
        commitment = build_acceptance_commitment(criteria)
        binding = _schema_gate_binding(
            order_id=order_id,
            idempotency_key=idempotency_key,
            input_value=input,
            target_schema=target_schema,
            acceptance_commitment=commitment,
            expires_at=expires_at,
        )
        url = (
            "https://www.x402digitalvendingmachine.store/v1/orders/"
            f"{quote(order_id, safe='')}"
        )
        response = self._get_json(
            url,
            extra_headers={
                "Authorization": f"Bearer {recovery_token}",
                "X-Recovery-Token": recovery_token,
            },
        )
        recovery = {"url": url, "token": recovery_token}
        self.last_recovery = recovery
        if response.status_code == 200:
            status_result = self._parse_json_object(
                response, "Schema Gate recovery response"
            )
            if status_result.get("status") == "delivered":
                return self._parse_schema_gate_result(response, binding=binding)
            returned_recovery = status_result.get("recovery")
            if not isinstance(returned_recovery, dict):
                raise ProtocolError("Schema Gate recovery response omitted recovery.")
            status_result.setdefault("recovery", recovery)
            return status_result
        if response.status_code == 202:
            result = self._parse_json_object(response, "Schema Gate recovery response")
            result.setdefault("recovery", recovery)
            return result
        self._raise_http_error(response, "Schema Gate recovery failed")

    def _post_clean(
        self,
        text: str,
        extra_headers: Mapping[str, str] | None = None,
    ) -> Response:
        return self._post_json(
            self.endpoint,
            {"text": text},
            extra_headers=extra_headers,
        )

    def _post_json(
        self,
        endpoint: str,
        body: Mapping[str, Any],
        extra_headers: Mapping[str, str] | None = None,
    ) -> Response:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "x402-cleanup-client/2",
        }
        if extra_headers:
            headers.update(dict(extra_headers))
        try:
            return self.session.post(
                endpoint,
                json=dict(body),
                headers=headers,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise SDKError(f"Request to {endpoint} failed: {exc}") from exc

    def _get_json(
        self,
        endpoint: str,
        extra_headers: Mapping[str, str] | None = None,
    ) -> Response:
        headers = {
            "Accept": "application/json",
            "User-Agent": "x402-cleanup-client/3",
        }
        if extra_headers:
            headers.update(dict(extra_headers))
        try:
            return self.session.get(
                endpoint,
                headers=headers,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise SDKError(f"Request to {endpoint} failed: {exc}") from exc

    def _validate_payment_required(
        self,
        payment_required: dict[str, Any],
        *,
        expected_endpoint: str | None = None,
        expected_amount: int | None = PAYMENT_AMOUNT_ATOMIC,
        max_amount: int | None = None,
    ) -> ChallengeMetadata:
        if payment_required.get("x402Version") != 2:
            raise ProtocolError("Payment challenge must use x402Version 2.")

        pinned_endpoint = expected_endpoint or self.endpoint
        resource = payment_required.get("resource")
        if not isinstance(resource, dict) or resource.get("url") != pinned_endpoint:
            raise ProtocolError(
                f"Payment resource must be exactly {pinned_endpoint}."
            )

        accepts = payment_required.get("accepts")
        if not isinstance(accepts, list):
            raise ProtocolError("Payment challenge omitted accepts[].")
        accepted = next(
            (
                item
                for item in accepts
                if isinstance(item, dict)
                and item.get("scheme") == "exact"
                and item.get("network") == SOLANA_NETWORK
                and item.get("asset") == USDC_MINT
                and item.get("payTo") == RECIPIENT_WALLET
            ),
            None,
        )
        if accepted is None:
            raise ProtocolError(
                "No option matches exact SVM, Solana mainnet, official USDC, "
                "and the pinned recipient."
            )
        amount = accepted.get("amount")
        try:
            amount_atomic = int(str(amount))
        except (TypeError, ValueError) as exc:
            raise ProtocolError("Payment amount must be an integer string.") from exc
        if isinstance(amount, bool) or amount_atomic <= 0:
            raise ProtocolError("Payment amount must be positive.")
        if expected_amount is not None and amount_atomic != expected_amount:
            raise ProtocolError(
                f"Payment amount must be {expected_amount} atomic USDC."
            )
        if max_amount is not None and amount_atomic > max_amount:
            raise ProtocolError(
                f"Payment amount {amount_atomic} exceeds the authorized cap "
                f"of {max_amount} atomic USDC."
            )

        extra = accepted.get("extra")
        if not isinstance(extra, dict):
            raise ProtocolError("Accepted payment option omitted extra metadata.")
        decimals = extra.get("decimals", USDC_DECIMALS)
        if isinstance(decimals, bool) or str(decimals) != str(USDC_DECIMALS):
            raise ProtocolError(
                f"USDC decimals must be {USDC_DECIMALS} when supplied."
            )

        fee_payer = extra.get("feePayer")
        memo = extra.get("memo")
        challenge_id = extra.get("challengeId") or extra.get("challenge_id")
        if not isinstance(fee_payer, str) or not fee_payer.strip():
            raise ProtocolError("Accepted terms omitted extra.feePayer.")
        if not isinstance(memo, str) or not memo.strip():
            raise ProtocolError("Accepted terms omitted extra.memo.")
        if len(memo.encode("utf-8")) > 256:
            raise ProtocolError("Payment memo exceeds 256 bytes.")
        if not isinstance(challenge_id, str) or not challenge_id.strip():
            raise ProtocolError("Accepted terms omitted the challenge identifier.")

        extensions = payment_required.get("extensions")
        schema_gate: dict[str, Any] | None = None
        if isinstance(extensions, dict):
            candidate = extensions.get("schemaGate")
            if isinstance(candidate, dict):
                schema_gate = candidate

        return ChallengeMetadata(
            resource=resource,
            accepted=accepted,
            fee_payer=fee_payer.strip(),
            memo=memo,
            challenge_id=challenge_id.strip(),
            amount_atomic=amount_atomic,
            schema_gate=schema_gate,
        )

    def _validate_payment_payload(
        self,
        headers: Mapping[str, str],
        metadata: ChallengeMetadata,
        *,
        expected_endpoint: str | None = None,
    ) -> None:
        encoded = self._mapping_header(headers, PAYMENT_SIGNATURE_HEADER)
        if not encoded:
            raise ProtocolError("x402 client did not produce PAYMENT-SIGNATURE.")
        envelope = self._decode_base64_json(encoded, PAYMENT_SIGNATURE_HEADER)
        if envelope.get("x402Version") != 2:
            raise ProtocolError("Generated payment payload is not x402 v2.")

        pinned_endpoint = expected_endpoint or self.endpoint
        resource = envelope.get("resource")
        if not isinstance(resource, dict) or resource.get("url") != pinned_endpoint:
            raise ProtocolError("Generated payment payload changed the resource.")
        generated_terms = envelope.get("accepted")
        if not isinstance(generated_terms, dict):
            raise ProtocolError("Generated payment payload omitted accepted terms.")
        for field in ("scheme", "network", "amount", "asset", "payTo"):
            if generated_terms.get(field) != metadata.accepted.get(field):
                raise ProtocolError(
                    f"Generated payment payload changed accepted.{field}."
                )
        generated_extra = generated_terms.get("extra")
        expected_extra = metadata.accepted.get("extra")
        if not isinstance(generated_extra, dict) or not isinstance(
            expected_extra, dict
        ):
            raise ProtocolError("Generated payload omitted accepted.extra.")
        if _canonical_json(generated_extra) != _canonical_json(expected_extra):
            raise ProtocolError("Generated payment payload changed accepted.extra.")

        payload = envelope.get("payload")
        transaction = payload.get("transaction") if isinstance(payload, dict) else None
        if not isinstance(transaction, str) or not transaction:
            raise ProtocolError(
                "Generated payload omitted its signed partial SVM transaction."
            )
        try:
            base64.b64decode(transaction, validate=True)
        except Exception as exc:
            raise ProtocolError(
                "Generated SVM transaction is not valid base64."
            ) from exc

    def _parse_schema_gate_result(
        self,
        response: Response,
        *,
        binding: Mapping[str, str | int | None],
    ) -> dict[str, Any]:
        result = self._parse_json_object(response, "Schema Gate response")
        returned_order = result.get("order_id")
        if returned_order is not None and returned_order != binding["order_id"]:
            raise ProtocolError("Schema Gate response changed order_id.")
        returned_commitment = result.get("acceptance_commitment")
        if (
            returned_commitment is not None
            and returned_commitment != binding["acceptance_commitment"]
        ):
            raise ProtocolError(
                "Schema Gate response changed acceptance_commitment."
            )

        verdict = result.get("verdict")
        if verdict not in {"ACCEPT", "REJECT"}:
            raise ProtocolError("Schema Gate verdict must be ACCEPT or REJECT.")
        if verdict == "ACCEPT" and "output" not in result:
            raise ProtocolError("An ACCEPT verdict must include output.")
        if verdict == "REJECT" and result.get("output") is not None:
            raise ProtocolError("A REJECT verdict cannot include output.")

        checks = result.get("checks")
        if not isinstance(checks, list):
            raise ProtocolError("Schema Gate checks must be an array.")
        receipt = result.get("receipt")
        if not isinstance(receipt, dict):
            raise ProtocolError("Schema Gate response omitted its signed receipt.")
        recovery = result.get("recovery")
        if (
            not isinstance(recovery, dict)
            or not isinstance(recovery.get("url"), str)
            or not isinstance(recovery.get("token"), str)
            or not recovery["token"].startswith("sg_")
        ):
            raise ProtocolError("Schema Gate response omitted valid recovery terms.")
        expected_recovery_url = (
            "https://www.x402digitalvendingmachine.store/v1/orders/"
            f"{quote(str(binding['order_id']), safe='')}"
        )
        if recovery["url"] != expected_recovery_url:
            raise ProtocolError("Schema Gate response changed the recovery URL.")
        self.last_recovery = dict(recovery)

        self._verify_receipt(result=result, binding=binding)

        result.setdefault("order_id", binding["order_id"])
        result.setdefault("acceptance_commitment", binding["acceptance_commitment"])
        result["receipt_verified"] = True
        return result

    def _verify_receipt(
        self,
        *,
        result: Mapping[str, Any],
        binding: Mapping[str, str | int | None],
    ) -> None:
        receipt = result.get("receipt")
        if not isinstance(receipt, dict):
            raise ProtocolError("Schema Gate receipt must be an object.")
        protected = receipt.get("protected")
        payload = receipt.get("payload")
        encoded_signature = receipt.get("signature")
        if not isinstance(protected, dict) or set(protected) != {"alg", "kid", "typ"}:
            raise ProtocolError("Receipt protected header is malformed.")
        if protected.get("alg") != "ES256":
            raise ProtocolError("Receipt algorithm must be ES256.")
        kid = protected.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ProtocolError("Receipt protected header omitted kid.")
        if protected.get("typ") != SCHEMA_GATE_RECEIPT_TYPE:
            raise ProtocolError("Receipt protected header has the wrong type.")
        if not isinstance(payload, dict) or not isinstance(encoded_signature, str):
            raise ProtocolError("Receipt payload or signature is malformed.")

        jwk = self._load_receipt_jwk(kid)
        try:
            x_bytes = self._base64url_decode(str(jwk["x"]))
            y_bytes = self._base64url_decode(str(jwk["y"]))
            signature = self._base64url_decode(encoded_signature)
            if len(x_bytes) != 32 or len(y_bytes) != 32 or len(signature) != 64:
                raise ValueError("invalid ES256 coordinate or signature length")
            public_key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_bytes, "big"),
                int.from_bytes(y_bytes, "big"),
                ec.SECP256R1(),
            ).public_key()
            der_signature = encode_dss_signature(
                int.from_bytes(signature[:32], "big"),
                int.from_bytes(signature[32:], "big"),
            )
            signing_input = (
                self._base64url_encode(_canonical_json(protected).encode("utf-8"))
                + "."
                + self._base64url_encode(_canonical_json(payload).encode("utf-8"))
            ).encode("ascii")
            public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise ProtocolError("Receipt ES256 signature is invalid.") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("Receipt key or signature encoding is invalid.") from exc

        expected_fields: dict[str, Any] = {
            "receipt_version": 1,
            "service": "x402-schema-gate",
            "service_version": SCHEMA_GATE_NORMALIZER,
            "outcome": "paid_evaluation_delivered",
            "verdict": result.get("verdict"),
            "order_id": binding["order_id"],
            "idempotency_hash": binding["idempotency_hash"],
            "request_hash": binding["request_hash"],
            "acceptance_commitment": binding["acceptance_commitment"],
            "input_hash": binding["input_hash"],
            "schema_hash": binding["schema_hash"],
        }
        for field, expected in expected_fields.items():
            if payload.get(field) != expected:
                raise ProtocolError(f"Receipt payload changed {field}.")

        verdict = result.get("verdict")
        expected_output_hash = (
            _sha256_text(_canonical_json(result.get("output")))
            if verdict == "ACCEPT"
            else None
        )
        if payload.get("output_hash") != expected_output_hash:
            raise ProtocolError("Receipt output_hash does not bind the returned output.")
        canonical_output = result.get("canonical_json")
        if verdict == "ACCEPT" and canonical_output is not None:
            if canonical_output != _canonical_json(result.get("output")):
                raise ProtocolError("Response canonical_json does not match output.")
        if _canonical_json(payload.get("checks")) != _canonical_json(result.get("checks")):
            raise ProtocolError("Receipt checks do not bind the returned checks.")
        if _canonical_json(payload.get("recovery")) != _canonical_json(result.get("recovery")):
            raise ProtocolError("Receipt recovery terms do not bind the response.")

        receipt_payment = payload.get("payment")
        response_payment = result.get("payment")
        if not isinstance(receipt_payment, dict) or not isinstance(response_payment, dict):
            raise ProtocolError("Receipt or response omitted payment evidence.")
        pinned_payment = {
            "network": SOLANA_NETWORK,
            "asset": USDC_MINT,
            "pay_to": RECIPIENT_WALLET,
            "amount_atomic": SCHEMA_GATE_AMOUNT_ATOMIC,
        }
        for field, expected in pinned_payment.items():
            actual = receipt_payment.get(field)
            if field == "amount_atomic":
                try:
                    actual = int(str(actual))
                except (TypeError, ValueError) as exc:
                    raise ProtocolError("Receipt amount_atomic is invalid.") from exc
            if actual != expected:
                raise ProtocolError(f"Receipt payment changed {field}.")
        for field in ("authorization_hash", "settlement_transaction", "payer"):
            if not isinstance(receipt_payment.get(field), str) or not receipt_payment[field]:
                raise ProtocolError(f"Receipt payment omitted {field}.")
        settlement_hash = _sha256_text(_canonical_json(response_payment))
        if receipt_payment.get("settlement_response_hash") != settlement_hash:
            raise ProtocolError(
                "Receipt settlement_response_hash does not bind payment evidence."
            )

    def _load_receipt_jwk(self, kid: str) -> dict[str, Any]:
        if self._receipt_key is not None:
            if self._receipt_key.get("kid") != kid:
                raise ProtocolError("Receipt kid does not match the cached public key.")
            return self._receipt_key
        response = self._get_json(RECEIPT_KEY_ENDPOINT)
        if response.status_code != 200:
            self._raise_http_error(response, "Receipt public key lookup failed")
        document = self._parse_json_object(response, "receipt public key document")
        if document.get("receipt_type") != SCHEMA_GATE_RECEIPT_TYPE:
            raise ProtocolError("Receipt key document has the wrong receipt_type.")
        if document.get("canonicalization") != SCHEMA_GATE_NORMALIZER:
            raise ProtocolError("Receipt key document has the wrong canonicalization.")
        keys = document.get("keys")
        if not isinstance(keys, list):
            raise ProtocolError("Receipt key document omitted keys[].")
        jwk = next(
            (
                item
                for item in keys
                if isinstance(item, dict) and item.get("kid") == kid
            ),
            None,
        )
        if not isinstance(jwk, dict):
            raise ProtocolError("Receipt kid is not published by the service.")
        required = {
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": kid,
        }
        for field, expected in required.items():
            if jwk.get(field) != expected:
                raise ProtocolError(f"Receipt JWK has invalid {field}.")
        if not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str):
            raise ProtocolError("Receipt JWK omitted P-256 coordinates.")
        self._receipt_key = dict(jwk)
        return self._receipt_key

    @staticmethod
    def _base64url_decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))

    @staticmethod
    def _base64url_encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _mapping_header(
        headers: Mapping[str, str], name: str
    ) -> str | None:
        lowered = name.lower()
        for key, value in headers.items():
            if key.lower() == lowered:
                return value
        return None

    @staticmethod
    def _decode_base64_json(value: str, name: str) -> dict[str, Any]:
        try:
            padded = value + ("=" * (-len(value) % 4))
            parsed = json.loads(base64.b64decode(padded).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolError(f"{name} is not valid base64 JSON.") from exc
        if not isinstance(parsed, dict):
            raise ProtocolError(f"{name} must decode to a JSON object.")
        return parsed

    @staticmethod
    def _parse_json_object(response: Response, label: str) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise ProtocolError(f"{label} is not JSON.") from exc
        if not isinstance(payload, dict):
            raise ProtocolError(f"{label} must be a JSON object.")
        return payload

    @staticmethod
    def _raise_http_error(response: Response, context: str) -> None:
        try:
            details: Any = response.json()
        except ValueError:
            details = response.text[:500]
        raise SDKError(
            f"{context}. HTTP {response.status_code} from {response.url}. "
            f"Body: {details}"
        )

    @staticmethod
    def _load_keypair(keypair_path: str) -> Keypair:
        path = Path(keypair_path).expanduser()
        if not path.is_file():
            raise SDKError(f"Could not locate keypair path: {path}")
        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            raise SDKError(f"Keypair file is empty: {path}")
        try:
            parsed: Any = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw
        return X402ClientSDK._coerce_keypair(parsed)

    @staticmethod
    def _coerce_keypair(wallet_key: Any) -> Keypair:
        if isinstance(wallet_key, Keypair):
            return wallet_key
        if isinstance(wallet_key, dict):
            wallet_key = (
                wallet_key.get("secretKey")
                or wallet_key.get("secret_key")
                or wallet_key.get("private_key")
                or wallet_key.get("secret")
            )
        if isinstance(wallet_key, str):
            candidate = Path(wallet_key).expanduser()
            if candidate.is_file():
                return X402ClientSDK._load_keypair(str(candidate))
            try:
                parsed = json.loads(wallet_key)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, (list, dict)):
                return X402ClientSDK._coerce_keypair(parsed)
            try:
                secret_bytes = b58decode(wallet_key)
            except Exception as exc:
                raise SDKError("Wallet key is not valid base58.") from exc
        elif isinstance(wallet_key, (list, tuple, bytes, bytearray)):
            secret_bytes = bytes(wallet_key)
        else:
            raise SDKError("Unsupported wallet_key format.")

        if len(secret_bytes) == 32:
            return Keypair.from_seed(secret_bytes)
        if len(secret_bytes) == 64:
            return Keypair.from_bytes(secret_bytes)
        raise SDKError(
            f"Unsupported secret key length ({len(secret_bytes)}); expected 32 or 64."
        )


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Canonical x402 v2 exact-SVM text cleanup client"
    )
    parser.add_argument("--text", required=True, help="Raw text to clean")
    parser.add_argument(
        "--text-to-clean",
        dest="text_to_clean",
        help="Backward-compatible alias for --text",
    )
    parser.add_argument("--endpoint", default=SERVICE_ENDPOINT)
    parser.add_argument("--rpc-url", default=MAINNET_RPC)
    parser.add_argument("--keypair", "--keypair-path", dest="keypair")
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Compatibility flag; facilitator settlement remains synchronous",
    )
    parser.add_argument("--timeout", type=float, default=30)
    return parser


def main() -> None:
    args = build_cli().parse_args()
    text = args.text_to_clean or args.text
    client = X402ClientSDK(
        endpoint=args.endpoint,
        rpc_url=args.rpc_url,
        timeout_seconds=args.timeout,
    )
    try:
        result = client.clean_text(
            text=text,
            keypair_path=args.keypair,
            verify_signature=not args.no_wait,
            keypair_timeout_seconds=int(args.timeout),
        )
    except SDKError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
