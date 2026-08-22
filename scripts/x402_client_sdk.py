#!/usr/bin/env python3
"""Canonical x402 v2 client for Base, Solana, Schema Gate, and cleanup.

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
from eth_account import Account
from requests import Response, Session
from solders.keypair import Keypair
from x402 import x402ClientSync
from x402.http import x402HTTPClientSync
from x402.mechanisms.evm import EthAccountSigner
from x402.mechanisms.evm.exact.register import register_exact_evm_client
from x402.mechanisms.svm import KeypairSigner
from x402.mechanisms.svm.exact.register import register_exact_svm_client


SERVICE_ENDPOINT = "https://www.x402digitalvendingmachine.store/v1/clean"
SCHEMA_GATE_ENDPOINT = (
    "https://www.x402digitalvendingmachine.store/v1/schema-gate"
)
EXECUTION_GATE_ENDPOINT = (
    "https://www.x402digitalvendingmachine.store/v1/execution-gate"
)
RECEIPT_KEY_ENDPOINT = (
    "https://www.x402digitalvendingmachine.store/.well-known/receipt-key.json"
)
EXECUTION_RECEIPT_KEY_ENDPOINT = (
    "https://www.x402digitalvendingmachine.store/"
    ".well-known/execution-gate-receipt-jwks.json"
)
MAINNET_RPC = "https://api.mainnet-beta.solana.com"
BASE_NETWORK = "eip155:8453"
BASE_USDC_ASSET = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BASE_RECIPIENT_WALLET = "0xCbE8df651925485046bFd42b736186433904F8a6"
SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
RECIPIENT_WALLET = "E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD"
PAYMENT_AMOUNT_ATOMIC = 2_000
SCHEMA_GATE_AMOUNT_ATOMIC = 10_000
SCHEMA_GATE_NORMALIZER = "schema-gate-c14n-v1"
SCHEMA_GATE_MAX_OUTPUT_BYTES = 100_000
SCHEMA_GATE_RECEIPT_TYPE = "x402-schema-gate-receipt"
SCHEMA_GATE_OPERATION = "schema-gate-v1"
EXECUTION_GATE_RECEIPT_TYPE = "x402-execution-gate-receipt+jwt"
EXECUTION_GATE_OPERATION = "execution-gate-v1"
USDC_DECIMALS = 6
PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"
SCHEMA_GATE_RECOVERY_URL_HEADER = "X-Schema-Gate-Recovery-URL"
SCHEMA_GATE_RECOVERY_TOKEN_HEADER = "X-Schema-Gate-Recovery-Token"


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
    rail: str
    fee_payer: str | None
    memo: str | None
    challenge_id: str
    amount_atomic: int
    schema_gate: dict[str, Any] | None = None
    execution_gate: dict[str, Any] | None = None


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


def _execution_expires_epoch(
    value: str | int | None,
    *,
    enforce_window: bool,
) -> int:
    if not isinstance(value, str) or not value.strip():
        raise SDKError("Execution Gate expires_at must be an RFC 3339 string.")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise SDKError("Execution Gate expires_at must be valid RFC 3339.") from exc
    if parsed.tzinfo is None:
        raise SDKError("Execution Gate expires_at must include a timezone.")
    epoch = int(parsed.timestamp())
    if enforce_window:
        now = int(datetime.now(timezone.utc).timestamp())
        if epoch <= now + 30 or epoch > now + 600:
            raise SDKError(
                "Execution Gate expires_at must be 30 seconds to 10 minutes "
                "in the future."
            )
    return epoch


def _execution_identifier(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is None
    ):
        raise SDKError(f"{field} must be 1-128 URL-safe characters.")
    return value


def _execution_recovery_token(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 256 or "." not in value:
        raise SDKError("recovery_token must be a server-issued versioned token.")
    version, signature = value.rsplit(".", 1)
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", version) is None
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", signature) is None
    ):
        raise SDKError("recovery_token must be a server-issued versioned token.")
    return value


def _execution_gate_binding(
    *,
    order_id: str,
    idempotency_key: str,
    integration_id: str,
    integration_version: str,
    action_id: str,
    input: Any,
    target_schema: Mapping[str, Any],
    acceptance_criteria: Any,
    expires_at: str | int | None,
    audience: str,
    environment: str,
    configuration_hash: str,
    policy_hash: str,
    qualification_report_hash: str,
    amount_atomic: int,
    recovery_token: str | None,
) -> dict[str, Any]:
    """Build the exact buyer/request/price binding for Execution Gate."""
    normalized_criteria = _normalize_acceptance_criteria(acceptance_criteria)
    acceptance_commitment = build_acceptance_commitment(normalized_criteria)
    input_hash = _sha256_text(_canonical_json(input))
    schema_hash = _sha256_text(_canonical_json(dict(target_schema)))
    idempotency_hash = _sha256_text(idempotency_key)
    expires_epoch = _execution_expires_epoch(expires_at, enforce_window=False)
    payload_hash = "sha256:" + _sha256_text(
        _canonical_json(
            {
                "input": input,
                "target_schema": dict(target_schema),
                "acceptance_criteria": normalized_criteria,
                "acceptance_commitment": acceptance_commitment,
            }
        )
    )
    request_hash = _sha256_text(
        _canonical_json(
            {
                "operation": EXECUTION_GATE_OPERATION,
                "order_id": order_id,
                "idempotency_hash": idempotency_hash,
                "integration_id": integration_id,
                "integration_version": integration_version,
                "action_id": action_id,
                "audience": audience,
                "configuration_hash": configuration_hash,
                "policy_hash": policy_hash,
                "input_hash": input_hash,
                "schema_hash": schema_hash,
                "acceptance_commitment": acceptance_commitment,
                "network": SOLANA_NETWORK,
                "asset": USDC_MINT,
                "recipient": RECIPIENT_WALLET,
                "amount_atomic": amount_atomic,
                "expires_at": expires_epoch,
            }
        )
    )
    return {
        "order_id": order_id,
        "idempotency_hash": idempotency_hash,
        "integration_id": integration_id,
        "integration_version": integration_version,
        "action_id": action_id,
        "environment": environment,
        "audience": audience,
        "configuration_hash": configuration_hash,
        "policy_hash": policy_hash,
        "qualification_report_hash": qualification_report_hash,
        "input_hash": input_hash,
        "schema_hash": schema_hash,
        "acceptance_commitment": acceptance_commitment,
        "payload_hash": payload_hash,
        "request_hash": request_hash,
        "network": SOLANA_NETWORK,
        "asset": USDC_MINT,
        "recipient": RECIPIENT_WALLET,
        "amount_atomic": amount_atomic,
        "expires_at": expires_epoch,
        "recovery_url": (
            "https://www.x402digitalvendingmachine.store/v1/executions/"
            f"{quote(order_id, safe='')}"
        ),
        "recovery_token_hash": (
            _sha256_text(recovery_token) if recovery_token is not None else None
        ),
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
        self._execution_receipt_keys: dict[str, dict[str, Any]] = {}

    def clean_text(
        self,
        text: str,
        keypair_path: Optional[str] = None,
        wallet_key: Optional[Any] = None,
        verify_signature: bool = True,
        keypair_timeout_seconds: Optional[int] = None,
        evm_wallet_key: Optional[Any] = None,
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
        if not keypair_path and wallet_key is None and evm_wallet_key is None:
            raise SDKError(
                "Purchase requires evm_wallet_key, wallet_key, or a local "
                "Solana keypair_path."
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
        metadata = self._validate_payment_required(
            payment_required,
            prefer_base=evm_wallet_key is not None,
        )
        http_client, expected_payer = self._payment_client(
            metadata,
            wallet_key=wallet_key,
            keypair_path=keypair_path,
            evm_wallet_key=evm_wallet_key,
        )

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
                f"Could not create canonical exact-{metadata.rail.upper()} "
                f"payment payload: {exc}"
            ) from exc
        if payment_payload is None:
            raise ProtocolError("x402 client did not create a payment payload.")
        self._validate_payment_payload(
            payment_headers,
            metadata,
            expected_payer=expected_payer,
        )

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
        evm_wallet_key: Optional[Any] = None,
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
            prefer_base=evm_wallet_key is not None,
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
        recovery = self._extract_schema_gate_recovery(
            probe.headers,
            payment_required,
            order_id=order_id,
        )
        self.last_recovery = recovery

        if not keypair_path and wallet_key is None and evm_wallet_key is None:
            raise SDKError(
                "A new Schema Gate evaluation requires evm_wallet_key, "
                "wallet_key, or a local Solana keypair_path.",
                recovery=self.last_recovery,
            )
        http_client, expected_payer = self._payment_client(
            metadata,
            wallet_key=wallet_key,
            keypair_path=keypair_path,
            evm_wallet_key=evm_wallet_key,
        )
        recovery_header_names = {
            SCHEMA_GATE_RECOVERY_URL_HEADER.lower(),
            SCHEMA_GATE_RECOVERY_TOKEN_HEADER.lower(),
        }
        response_headers = {
            key: value
            for key, value in probe.headers.items()
            if key.lower() not in recovery_header_names
        }
        signable_required = self._without_schema_gate_recovery(payment_required)
        response_headers[PAYMENT_REQUIRED_HEADER] = base64.b64encode(
            _canonical_json(signable_required).encode("utf-8")
        ).decode("ascii")
        try:
            payment_headers, payment_payload = http_client.handle_402_response(
                response_headers,
                probe.content,
                probe.url,
            )
        except Exception as exc:
            raise PaymentError(
                f"Could not create canonical exact-{metadata.rail.upper()} "
                f"payment payload: {exc}",
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
            expected_payer=expected_payer,
        )
        self._validate_recovery_not_echoed(
            payment_headers,
            recovery_token=recovery["token"],
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

    def execution_gate(
        self,
        *,
        order_id: str,
        idempotency_key: str,
        integration_id: str,
        integration_version: str,
        action_id: str,
        input: Any,
        target_schema: Mapping[str, Any],
        acceptance_criteria: Any,
        expires_at: str | int | None,
        max_amount_atomic: int,
        wallet_key: Optional[Any] = None,
        keypair_path: Optional[str] = None,
        evm_wallet_key: Optional[Any] = None,
    ) -> dict[str, Any]:
        """Purchase one private-pilot execution with one paid attempt at most."""
        self._validate_execution_request(
            order_id=order_id,
            idempotency_key=idempotency_key,
            integration_id=integration_id,
            integration_version=integration_version,
            action_id=action_id,
            target_schema=target_schema,
            expires_at=expires_at,
            enforce_expiry_window=True,
        )
        if keypair_path and wallet_key is not None:
            raise SDKError("Provide either wallet_key or keypair_path, not both.")
        if (
            isinstance(max_amount_atomic, bool)
            or not isinstance(max_amount_atomic, int)
            or max_amount_atomic <= 0
        ):
            raise SDKError("max_amount_atomic must be an explicit positive integer.")

        criteria = _normalize_acceptance_criteria(acceptance_criteria)
        commitment = build_acceptance_commitment(criteria)
        body = {
            "order_id": order_id,
            "idempotency_key": idempotency_key,
            "integration_id": integration_id,
            "integration_version": integration_version,
            "action_id": action_id,
            "input": input,
            "target_schema": dict(target_schema),
            "acceptance_criteria": criteria,
            "acceptance_commitment": commitment,
            "expires_at": str(expires_at).strip(),
        }
        _canonical_json(body)

        probe = self._post_json(EXECUTION_GATE_ENDPOINT, body)
        if probe.status_code == 200:
            binding = self._execution_binding_from_result(
                probe,
                request=body,
                recovery_token=None,
            )
            if binding["amount_atomic"] > max_amount_atomic:
                raise ProtocolError("Recovered execution price exceeds max_amount_atomic.")
            return self._parse_execution_result(
                probe,
                binding=binding,
                recovery_token=None,
            )
        if probe.status_code != 402:
            self._raise_http_error(
                probe, "Execution Gate preflight did not return a payment challenge"
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
            expected_endpoint=EXECUTION_GATE_ENDPOINT,
            expected_amount=None,
            max_amount=max_amount_atomic,
            require_amount_string=True,
            prefer_base=evm_wallet_key is not None,
        )
        binding, recovery = self._validate_execution_challenge(
            metadata=metadata,
            request=body,
        )
        self.last_recovery = recovery

        try:
            if (
                not keypair_path
                and wallet_key is None
                and evm_wallet_key is None
            ):
                raise SDKError(
                    "A new execution requires evm_wallet_key, wallet_key, or "
                    "a local Solana keypair_path."
                )
            http_client, expected_payer = self._payment_client(
                metadata,
                wallet_key=wallet_key,
                keypair_path=keypair_path,
                evm_wallet_key=evm_wallet_key,
            )
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
                    f"Could not create canonical exact-{metadata.rail.upper()} "
                    f"payment payload: {exc}"
                ) from exc
            if payment_payload is None:
                raise ProtocolError("x402 client did not create a payment payload.")
            self._validate_payment_payload(
                payment_headers,
                metadata,
                expected_endpoint=EXECUTION_GATE_ENDPOINT,
                strict_resource=True,
                strict_terms=True,
                expected_payer=expected_payer,
            )

            # Exactly one paid POST. Ambiguous failure is recovered by GET only.
            paid_response = self._post_json(
                EXECUTION_GATE_ENDPOINT,
                body,
                extra_headers=payment_headers,
            )
            if paid_response.status_code == 200:
                return self._parse_execution_result(
                    paid_response,
                    binding=binding,
                    recovery_token=recovery["token"],
                )
            if paid_response.status_code == 202:
                pending = self._parse_execution_pending(
                    paid_response,
                    order_id=order_id,
                )
                pending.setdefault("recovery", recovery)
                pending.setdefault(
                    "payment_response",
                    self._parse_execution_settlement(paid_response),
                )
                return pending
            self._raise_http_error(
                paid_response, "Execution Gate settlement or delivery failed"
            )
        except SDKError as exc:
            if exc.recovery is None:
                exc.recovery = dict(recovery)
            raise

    def recover_execution(
        self,
        *,
        order_id: str,
        recovery_token: str,
        idempotency_key: str,
        integration_id: str,
        integration_version: str,
        action_id: str,
        input: Any,
        target_schema: Mapping[str, Any],
        acceptance_criteria: Any,
        expires_at: str | int | None,
    ) -> dict[str, Any]:
        """Recover an execution using GET only; this path cannot create payment."""
        self._validate_execution_request(
            order_id=order_id,
            idempotency_key=idempotency_key,
            integration_id=integration_id,
            integration_version=integration_version,
            action_id=action_id,
            target_schema=target_schema,
            expires_at=expires_at,
            enforce_expiry_window=False,
        )
        token = _execution_recovery_token(recovery_token)
        criteria = _normalize_acceptance_criteria(acceptance_criteria)
        request = {
            "order_id": order_id,
            "idempotency_key": idempotency_key,
            "integration_id": integration_id,
            "integration_version": integration_version,
            "action_id": action_id,
            "input": input,
            "target_schema": dict(target_schema),
            "acceptance_criteria": criteria,
            "acceptance_commitment": build_acceptance_commitment(criteria),
            "expires_at": str(expires_at).strip(),
        }
        _canonical_json(request)
        url = (
            "https://www.x402digitalvendingmachine.store/v1/executions/"
            f"{quote(order_id, safe='')}"
        )
        recovery = {"url": url, "token": token}
        self.last_recovery = recovery
        response = self._get_json(
            url,
            extra_headers={
                "Authorization": f"Bearer {token}",
                "X-Recovery-Token": token,
            },
        )
        if response.status_code == 200:
            binding = self._execution_binding_from_result(
                response,
                request=request,
                recovery_token=token,
            )
            return self._parse_execution_result(
                response,
                binding=binding,
                recovery_token=token,
            )
        if response.status_code == 202:
            pending = self._parse_execution_pending(response, order_id=order_id)
            pending.setdefault("recovery", recovery)
            return pending
        try:
            self._raise_http_error(response, "Execution Gate recovery failed")
        except SDKError as exc:
            exc.recovery = recovery
            raise

    @staticmethod
    def _validate_execution_request(
        *,
        order_id: str,
        idempotency_key: str,
        integration_id: str,
        integration_version: str,
        action_id: str,
        target_schema: Mapping[str, Any],
        expires_at: str | int | None,
        enforce_expiry_window: bool,
    ) -> None:
        _execution_identifier(order_id, "order_id")
        if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 128:
            raise SDKError("idempotency_key must be 8-128 characters.")
        _execution_identifier(integration_id, "integration_id")
        _execution_identifier(integration_version, "integration_version")
        _execution_identifier(action_id, "action_id")
        if not isinstance(target_schema, Mapping) or not target_schema:
            raise SDKError("target_schema must be a non-empty JSON object.")
        _execution_expires_epoch(expires_at, enforce_window=enforce_expiry_window)

    def _validate_execution_challenge(
        self,
        *,
        metadata: ChallengeMetadata,
        request: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, str]]:
        terms = metadata.execution_gate
        expected_fields = {
            "order_id", "integration_id", "integration_version", "action_id",
            "environment", "audience", "request_hash", "configuration_hash",
            "policy_hash", "qualification_report_hash", "expires_at",
            "permit_ttl_seconds", "recovery",
        }
        if not isinstance(terms, dict) or set(terms) != expected_fields:
            raise ProtocolError(
                "Execution Gate challenge has malformed extensions.executionGate."
            )
        for field in (
            "order_id", "integration_id", "integration_version", "action_id"
        ):
            if terms.get(field) != request[field]:
                raise ProtocolError(f"Execution Gate challenge changed {field}.")
        environment = terms.get("environment")
        audience = terms.get("audience")
        if not isinstance(environment, str) or not environment:
            raise ProtocolError("Execution Gate challenge omitted environment.")
        if not isinstance(audience, str) or not audience:
            raise ProtocolError("Execution Gate challenge omitted audience.")
        for field in (
            "configuration_hash", "policy_hash", "qualification_report_hash"
        ):
            self._require_prefixed_hash(terms.get(field), f"challenge {field}")
        if re.fullmatch(r"[0-9a-f]{64}", str(terms.get("request_hash"))) is None:
            raise ProtocolError("Execution Gate challenge request_hash is invalid.")

        buyer_expiry = _execution_expires_epoch(
            request.get("expires_at"), enforce_window=False
        )
        try:
            challenge_expiry = _execution_expires_epoch(
                terms.get("expires_at"), enforce_window=False
            )
        except SDKError as exc:
            raise ProtocolError("Execution Gate challenge expires_at is invalid.") from exc
        now = int(datetime.now(timezone.utc).timestamp())
        if (
            challenge_expiry <= now
            or challenge_expiry > buyer_expiry
            or challenge_expiry > now + 600
        ):
            raise ProtocolError("Execution Gate challenge expiry is outside buyer terms.")
        ttl = terms.get("permit_ttl_seconds")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 600:
            raise ProtocolError("Execution Gate challenge permit_ttl_seconds is invalid.")

        recovery = terms.get("recovery")
        expected_url = (
            "https://www.x402digitalvendingmachine.store/v1/executions/"
            f"{quote(str(request['order_id']), safe='')}"
        )
        if not isinstance(recovery, dict) or set(recovery) != {"url", "token"}:
            raise ProtocolError("Execution Gate challenge omitted recovery terms.")
        if recovery.get("url") != expected_url:
            raise ProtocolError("Execution Gate challenge changed the recovery URL.")
        try:
            token = _execution_recovery_token(recovery.get("token"))
        except SDKError as exc:
            raise ProtocolError("Execution Gate challenge recovery token is invalid.") from exc
        timeout = metadata.accepted.get("maxTimeoutSeconds")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600:
            raise ProtocolError("Execution Gate payment timeout is invalid.")

        binding = _execution_gate_binding(
            order_id=str(request["order_id"]),
            idempotency_key=str(request["idempotency_key"]),
            integration_id=str(request["integration_id"]),
            integration_version=str(request["integration_version"]),
            action_id=str(request["action_id"]),
            input=request["input"],
            target_schema=request["target_schema"],
            acceptance_criteria=request["acceptance_criteria"],
            expires_at=request["expires_at"],
            audience=audience,
            environment=environment,
            configuration_hash=str(terms["configuration_hash"]),
            policy_hash=str(terms["policy_hash"]),
            qualification_report_hash=str(terms["qualification_report_hash"]),
            amount_atomic=metadata.amount_atomic,
            recovery_token=token,
        )
        if terms["request_hash"] != binding["request_hash"]:
            raise ProtocolError("Execution Gate challenge request_hash does not bind the request.")
        return binding, {"url": expected_url, "token": token}

    def _execution_binding_from_result(
        self,
        response: Response,
        *,
        request: Mapping[str, Any],
        recovery_token: str | None,
    ) -> dict[str, Any]:
        outer = self._parse_json_object(response, "Execution Gate response")
        receipt = outer.get("receipt")
        payload = receipt.get("payload") if isinstance(receipt, dict) else None
        if not isinstance(payload, dict):
            raise ProtocolError("Execution Gate response omitted its receipt payload.")
        amount = payload.get("amount_atomic")
        if isinstance(amount, bool):
            raise ProtocolError("Execution receipt amount_atomic is invalid.")
        try:
            amount_atomic = int(str(amount))
        except (TypeError, ValueError) as exc:
            raise ProtocolError("Execution receipt amount_atomic is invalid.") from exc
        return _execution_gate_binding(
            order_id=str(request["order_id"]),
            idempotency_key=str(request["idempotency_key"]),
            integration_id=str(request["integration_id"]),
            integration_version=str(request["integration_version"]),
            action_id=str(request["action_id"]),
            input=request["input"],
            target_schema=request["target_schema"],
            acceptance_criteria=request["acceptance_criteria"],
            expires_at=request["expires_at"],
            audience=str(payload.get("audience", "")),
            environment=str(payload.get("environment", "")),
            configuration_hash=str(payload.get("configuration_hash", "")),
            policy_hash=str(payload.get("policy_hash", "")),
            qualification_report_hash=str(
                payload.get("qualification_report_hash", "")
            ),
            amount_atomic=amount_atomic,
            recovery_token=recovery_token,
        )

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
        require_amount_string: bool = False,
        prefer_base: bool = False,
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
        svm_accepted = next(
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
        base_accepted = next(
            (
                item
                for item in accepts
                if isinstance(item, dict)
                and item.get("scheme") == "exact"
                and item.get("network") == BASE_NETWORK
                and item.get("asset") == BASE_USDC_ASSET
                and item.get("payTo") == BASE_RECIPIENT_WALLET
            ),
            None,
        )
        if prefer_base and base_accepted is not None:
            accepted = base_accepted
            rail = "evm"
        elif svm_accepted is not None:
            accepted = svm_accepted
            rail = "svm"
        else:
            accepted = None
            rail = ""
        if accepted is None:
            raise ProtocolError(
                "No option matches a supported exact payment rail, official "
                "USDC asset, and pinned recipient."
            )
        amount = accepted.get("amount")
        if require_amount_string and (
            not isinstance(amount, str)
            or re.fullmatch(r"[1-9][0-9]*", amount) is None
        ):
            raise ProtocolError(
                "Payment amount must be a canonical positive integer string."
            )
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

        challenge_id = extra.get("challengeId") or extra.get("challenge_id")
        if not isinstance(challenge_id, str) or not challenge_id.strip():
            raise ProtocolError("Accepted terms omitted the challenge identifier.")
        fee_payer: str | None = None
        memo: str | None = None
        if rail == "evm":
            required_eip3009 = {
                "name": "USD Coin",
                "version": "2",
                "assetTransferMethod": "eip3009",
            }
            for field, expected in required_eip3009.items():
                if extra.get(field) != expected:
                    raise ProtocolError(
                        f"Base USDC terms require extra.{field}={expected!r}."
                    )
        else:
            fee_payer = extra.get("feePayer")
            memo = extra.get("memo")
            if not isinstance(fee_payer, str) or not fee_payer.strip():
                raise ProtocolError("Accepted terms omitted extra.feePayer.")
            if not isinstance(memo, str) or not memo.strip():
                raise ProtocolError("Accepted terms omitted extra.memo.")
            if len(memo.encode("utf-8")) > 256:
                raise ProtocolError("Payment memo exceeds 256 bytes.")

        extensions = payment_required.get("extensions")
        schema_gate: dict[str, Any] | None = None
        execution_gate: dict[str, Any] | None = None
        if isinstance(extensions, dict):
            candidate = extensions.get("schemaGate")
            if isinstance(candidate, dict):
                info = candidate.get("info")
                schema_gate = info if isinstance(info, dict) else candidate
            execution_candidate = extensions.get("executionGate")
            if isinstance(execution_candidate, dict):
                execution_gate = execution_candidate

        return ChallengeMetadata(
            resource=resource,
            accepted=accepted,
            rail=rail,
            fee_payer=fee_payer.strip() if fee_payer is not None else None,
            memo=memo,
            challenge_id=challenge_id.strip(),
            amount_atomic=amount_atomic,
            schema_gate=schema_gate,
            execution_gate=execution_gate,
        )

    def _extract_schema_gate_recovery(
        self,
        headers: Mapping[str, str],
        payment_required: Mapping[str, Any],
        *,
        order_id: str,
    ) -> dict[str, str]:
        """Read merchant recovery without making it signable x402 material."""
        header_url = self._mapping_header(
            headers, SCHEMA_GATE_RECOVERY_URL_HEADER
        )
        header_token = self._mapping_header(
            headers, SCHEMA_GATE_RECOVERY_TOKEN_HEADER
        )
        if header_url is not None or header_token is not None:
            if not header_url or not header_token:
                raise ProtocolError(
                    "Schema Gate recovery headers must be supplied together."
                )
            candidate: Any = {"url": header_url, "token": header_token}
        else:
            extensions = payment_required.get("extensions")
            schema_gate = (
                extensions.get("schemaGate")
                if isinstance(extensions, Mapping)
                else None
            )
            info = (
                schema_gate.get("info")
                if isinstance(schema_gate, Mapping)
                else None
            )
            candidate = (
                info.get("recovery")
                if isinstance(info, Mapping)
                and isinstance(info.get("recovery"), Mapping)
                else None
            )
            if candidate is None and isinstance(schema_gate, Mapping):
                candidate = schema_gate.get("recovery")

        expected_url = (
            "https://www.x402digitalvendingmachine.store/v1/orders/"
            f"{quote(order_id, safe='')}"
        )
        if (
            not isinstance(candidate, Mapping)
            or candidate.get("url") != expected_url
            or not isinstance(candidate.get("token"), str)
            or not candidate["token"].startswith("sg_")
        ):
            raise ProtocolError("Schema Gate challenge omitted valid recovery terms.")
        return {"url": expected_url, "token": candidate["token"]}

    @staticmethod
    def _without_schema_gate_recovery(
        payment_required: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Copy a challenge while removing recovery bearers from extensions."""
        sanitized = json.loads(_canonical_json(payment_required))
        extensions = sanitized.get("extensions")
        schema_gate = (
            extensions.get("schemaGate")
            if isinstance(extensions, dict)
            else None
        )
        if isinstance(schema_gate, dict):
            schema_gate.pop("recovery", None)
            info = schema_gate.get("info")
            if isinstance(info, dict):
                info.pop("recovery", None)
        return sanitized

    def _validate_recovery_not_echoed(
        self,
        headers: Mapping[str, str],
        *,
        recovery_token: str,
    ) -> None:
        encoded = self._mapping_header(headers, PAYMENT_SIGNATURE_HEADER)
        if not encoded:
            raise ProtocolError("x402 client did not produce PAYMENT-SIGNATURE.")
        envelope = self._decode_base64_json(encoded, PAYMENT_SIGNATURE_HEADER)
        if recovery_token in _canonical_json(envelope):
            raise ProtocolError(
                "Generated payment payload exposed the Schema Gate recovery token."
            )
        extensions = envelope.get("extensions")
        schema_gate = (
            extensions.get("schemaGate")
            if isinstance(extensions, Mapping)
            else None
        )
        info = (
            schema_gate.get("info")
            if isinstance(schema_gate, Mapping)
            else None
        )
        if isinstance(schema_gate, Mapping) and "recovery" in schema_gate:
            raise ProtocolError(
                "Generated payment payload exposed Schema Gate recovery metadata."
            )
        if isinstance(info, Mapping) and "recovery" in info:
            raise ProtocolError(
                "Generated payment payload exposed Schema Gate recovery metadata."
            )

    def _payment_client(
        self,
        metadata: ChallengeMetadata,
        *,
        wallet_key: Any | None,
        keypair_path: str | None,
        evm_wallet_key: Any | None,
    ) -> tuple[x402HTTPClientSync, str | None]:
        core_client = x402ClientSync()
        if metadata.rail == "evm":
            if evm_wallet_key is None:
                raise SDKError("A Base payment requires evm_wallet_key.")
            try:
                account = Account.from_key(evm_wallet_key)
            except Exception as exc:
                raise SDKError("evm_wallet_key is not a valid EVM private key.") from exc
            register_exact_evm_client(
                core_client,
                EthAccountSigner(account),
                networks=BASE_NETWORK,
            )
            return x402HTTPClientSync(core_client), account.address

        if metadata.rail != "svm":
            raise ProtocolError("Payment challenge selected an unsupported rail.")
        if not keypair_path and wallet_key is None:
            raise SDKError(
                "A Solana payment requires wallet_key or a local keypair_path."
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
        register_exact_svm_client(
            core_client,
            KeypairSigner(payer),
            networks=SOLANA_NETWORK,
            rpc_url=self.rpc_url,
        )
        return x402HTTPClientSync(core_client), None

    def _validate_payment_payload(
        self,
        headers: Mapping[str, str],
        metadata: ChallengeMetadata,
        *,
        expected_endpoint: str | None = None,
        strict_resource: bool = False,
        strict_terms: bool = False,
        expected_payer: str | None = None,
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
        if strict_resource and _canonical_json(resource) != _canonical_json(
            metadata.resource
        ):
            raise ProtocolError("Generated payment payload changed the resource metadata.")
        generated_terms = envelope.get("accepted")
        if not isinstance(generated_terms, dict):
            raise ProtocolError("Generated payment payload omitted accepted terms.")
        if strict_terms and _canonical_json(generated_terms) != _canonical_json(
            metadata.accepted
        ):
            raise ProtocolError("Generated payment payload changed accepted terms.")
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
        if metadata.rail == "evm":
            if not isinstance(payload, dict):
                raise ProtocolError("Generated EVM payload must be an object.")
            signature = payload.get("signature")
            authorization = payload.get("authorization")
            if (
                not isinstance(signature, str)
                or re.fullmatch(r"0x[0-9a-fA-F]{130}", signature) is None
            ):
                raise ProtocolError("Generated EIP-3009 signature is malformed.")
            if not isinstance(authorization, dict):
                raise ProtocolError("Generated EIP-3009 authorization is missing.")
            payer = authorization.get("from")
            if (
                not isinstance(payer, str)
                or re.fullmatch(r"0x[0-9a-fA-F]{40}", payer) is None
            ):
                raise ProtocolError("Generated EIP-3009 payer is malformed.")
            if expected_payer is not None and payer.lower() != expected_payer.lower():
                raise ProtocolError("Generated EIP-3009 payer changed the signer.")
            if authorization.get("to") != metadata.accepted.get("payTo"):
                raise ProtocolError("Generated EIP-3009 authorization changed payTo.")
            if authorization.get("value") != metadata.accepted.get("amount"):
                raise ProtocolError("Generated EIP-3009 authorization changed amount.")
            for field in ("validAfter", "validBefore"):
                value = authorization.get(field)
                if not isinstance(value, str) or re.fullmatch(r"[0-9]+", value) is None:
                    raise ProtocolError(
                        f"Generated EIP-3009 authorization has invalid {field}."
                    )
            if int(authorization["validBefore"]) <= int(authorization["validAfter"]):
                raise ProtocolError("Generated EIP-3009 validity window is invalid.")
            nonce = authorization.get("nonce")
            if (
                not isinstance(nonce, str)
                or re.fullmatch(r"0x[0-9a-fA-F]{64}", nonce) is None
            ):
                raise ProtocolError("Generated EIP-3009 nonce is malformed.")
            return

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

    def _parse_execution_result(
        self,
        response: Response,
        *,
        binding: Mapping[str, Any],
        recovery_token: str | None,
    ) -> dict[str, Any]:
        outer = self._parse_json_object(response, "Execution Gate response")
        if outer.get("order_id") != binding["order_id"]:
            raise ProtocolError("Execution Gate response changed order_id.")
        if outer.get("status") != "delivered":
            raise ProtocolError("Execution Gate response status must be delivered.")
        if outer.get("payment_settled") is not True:
            raise ProtocolError("Execution Gate response did not confirm settlement.")
        delivery = outer.get("delivery")
        if not isinstance(delivery, dict) or not isinstance(delivery.get("recovered"), bool):
            raise ProtocolError("Execution Gate response delivery is malformed.")
        result = outer.get("result")
        if not isinstance(result, dict):
            raise ProtocolError("Execution Gate response omitted result.")
        receipt = outer.get("receipt")
        if not isinstance(receipt, dict):
            raise ProtocolError("Execution Gate response omitted its signed receipt.")
        settlement = self._parse_execution_settlement(response)
        self._verify_execution_receipt(
            outer=outer,
            result=result,
            receipt=receipt,
            settlement=settlement,
            binding=binding,
            recovery_token=recovery_token,
        )
        outer["receipt_verified"] = True
        outer["prepare_verified"] = True
        outer["commit_verified"] = True
        outer["execution_verified"] = True
        outer.setdefault("payment_response", settlement)
        return outer

    def _parse_execution_pending(
        self,
        response: Response,
        *,
        order_id: str,
    ) -> dict[str, Any]:
        pending = self._parse_json_object(response, "Execution Gate pending response")
        if pending.get("order_id") != order_id:
            raise ProtocolError("Execution recovery response changed order_id.")
        if not isinstance(pending.get("status"), str) or not pending["status"]:
            raise ProtocolError("Execution recovery response omitted status.")
        if pending.get("payment_settled") is not True:
            raise ProtocolError("Execution recovery response did not confirm settlement.")
        if pending.get("outcome_unknown") is not True:
            raise ProtocolError("Execution recovery response must mark outcome_unknown.")
        pending["execution_verified"] = False
        return pending

    def _parse_execution_settlement(self, response: Response) -> dict[str, Any]:
        encoded = response.headers.get("PAYMENT-RESPONSE")
        if not encoded:
            raise ProtocolError("Execution response omitted PAYMENT-RESPONSE.")
        settlement = self._decode_base64_json(encoded, "PAYMENT-RESPONSE")
        if settlement.get("success") is not True:
            reason = settlement.get("errorReason") or settlement.get("error")
            raise PaymentError(
                f"Facilitator did not confirm settlement: {reason or settlement}"
            )
        if "network" in settlement and settlement.get("network") != SOLANA_NETWORK:
            raise ProtocolError("Settlement response changed the network.")
        transaction = settlement.get("transaction")
        if not isinstance(transaction, str) or not transaction:
            raise ProtocolError("Settlement response omitted transaction.")
        return settlement

    def _verify_execution_receipt(
        self,
        *,
        outer: Mapping[str, Any],
        result: Mapping[str, Any],
        receipt: Mapping[str, Any],
        settlement: Mapping[str, Any],
        binding: Mapping[str, Any],
        recovery_token: str | None,
    ) -> None:
        protected = receipt.get("protected")
        payload = receipt.get("payload")
        encoded_signature = receipt.get("signature")
        if not isinstance(protected, dict) or set(protected) != {"alg", "kid", "typ"}:
            raise ProtocolError("Execution receipt protected header is malformed.")
        if protected.get("alg") != "ES256":
            raise ProtocolError("Execution receipt algorithm must be ES256.")
        if protected.get("typ") != EXECUTION_GATE_RECEIPT_TYPE:
            raise ProtocolError("Execution receipt protected header has the wrong type.")
        kid = protected.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ProtocolError("Execution receipt protected header omitted kid.")
        if not isinstance(payload, dict) or not isinstance(encoded_signature, str):
            raise ProtocolError("Execution receipt payload or signature is malformed.")
        self._verify_execution_signature(
            protected=protected,
            payload=payload,
            encoded_signature=encoded_signature,
            kid=kid,
        )

        required_payload_fields = {
            "receipt_version", "service", "environment", "audience",
            "integration_id", "integration_version", "action_id", "order_id",
            "idempotency_hash", "request_hash", "configuration_hash",
            "policy_hash", "qualification_report_hash", "payload_hash",
            "dispatch_nonce", "payment_id", "network", "asset", "recipient",
            "amount_atomic", "payer", "settlement_id", "prepare_jti",
            "prepare_permit_hash", "prepare_ack_hash", "commit_jti",
            "commit_permit_hash", "commit_ack_hash", "effect_id",
            "effect_ack_hash", "result_hash", "recovery_url",
            "recovery_token_hash", "executed_at", "issued_at",
        }
        if set(payload) != required_payload_fields:
            raise ProtocolError("Execution receipt payload fields are malformed.")
        expected = {
            "receipt_version": 1,
            "service": "x402-execution-gate",
            "environment": binding["environment"],
            "audience": binding["audience"],
            "integration_id": binding["integration_id"],
            "integration_version": binding["integration_version"],
            "action_id": binding["action_id"],
            "order_id": binding["order_id"],
            "idempotency_hash": binding["idempotency_hash"],
            "request_hash": binding["request_hash"],
            "configuration_hash": binding["configuration_hash"],
            "policy_hash": binding["policy_hash"],
            "qualification_report_hash": binding["qualification_report_hash"],
            "payload_hash": binding["payload_hash"],
            "network": SOLANA_NETWORK,
            "asset": USDC_MINT,
            "recipient": RECIPIENT_WALLET,
            "amount_atomic": binding["amount_atomic"],
        }
        for field, expected_value in expected.items():
            actual = payload.get(field)
            if field == "amount_atomic" and not isinstance(actual, bool):
                try:
                    actual = int(str(actual))
                except (TypeError, ValueError):
                    pass
            if actual != expected_value:
                raise ProtocolError(f"Execution receipt changed {field}.")

        for field in (
            "configuration_hash", "policy_hash", "qualification_report_hash",
            "payload_hash", "prepare_permit_hash", "prepare_ack_hash",
            "commit_permit_hash", "commit_ack_hash", "effect_id",
            "effect_ack_hash", "result_hash",
        ):
            self._require_prefixed_hash(payload.get(field), f"receipt {field}")
        for field in ("idempotency_hash", "request_hash", "recovery_token_hash"):
            if re.fullmatch(r"[0-9a-f]{64}", str(payload.get(field))) is None:
                raise ProtocolError(f"Execution receipt {field} is invalid.")
        for field in (
            "dispatch_nonce", "payment_id", "payer", "settlement_id",
            "prepare_jti", "commit_jti", "executed_at", "issued_at",
        ):
            if not isinstance(payload.get(field), str) or not payload[field]:
                raise ProtocolError(f"Execution receipt omitted {field}.")
        if payload["prepare_jti"] == payload["commit_jti"]:
            raise ProtocolError("Execution receipt PREPARE and COMMIT JTIs must differ.")
        if payload["effect_ack_hash"] != payload["commit_ack_hash"]:
            raise ProtocolError("Execution receipt effect_ack_hash does not bind COMMIT.")

        required_result_fields = {
            "status", "nonce", "aud", "integration_id", "integration_version",
            "action_id", "configuration_hash", "policy_hash", "payload_hash",
            "order_id", "settlement_id", "effect_id", "executed_at",
        }
        if set(result) != required_result_fields or result.get("status") != "EXECUTED":
            raise ProtocolError("Execution result is malformed or not EXECUTED.")
        result_bindings = {
            "nonce": payload["dispatch_nonce"],
            "aud": binding["audience"],
            "integration_id": binding["integration_id"],
            "integration_version": binding["integration_version"],
            "action_id": binding["action_id"],
            "configuration_hash": binding["configuration_hash"],
            "policy_hash": binding["policy_hash"],
            "payload_hash": binding["payload_hash"],
            "order_id": binding["order_id"],
            "settlement_id": payload["settlement_id"],
            "effect_id": payload["effect_id"],
            "executed_at": payload["executed_at"],
        }
        for field, expected_value in result_bindings.items():
            if result.get(field) != expected_value:
                raise ProtocolError(f"Execution result changed {field}.")
        expected_result_hash = "sha256:" + _sha256_text(_canonical_json(dict(result)))
        if payload["result_hash"] != expected_result_hash:
            raise ProtocolError("Execution receipt result_hash does not bind result.")
        if payload["settlement_id"] != settlement.get("transaction"):
            raise ProtocolError("Execution settlement_id does not bind PAYMENT-RESPONSE.")
        if payload["recovery_url"] != binding["recovery_url"]:
            raise ProtocolError("Execution receipt changed recovery_url.")
        if recovery_token is not None:
            expected_token_hash = _sha256_text(recovery_token)
            if payload["recovery_token_hash"] != expected_token_hash:
                raise ProtocolError("Execution receipt changed recovery_token_hash.")
        elif binding.get("recovery_token_hash") is not None:
            if payload["recovery_token_hash"] != binding["recovery_token_hash"]:
                raise ProtocolError("Execution receipt changed recovery_token_hash.")
        if outer.get("order_id") != payload["order_id"]:
            raise ProtocolError("Execution receipt does not bind outer order_id.")

    @staticmethod
    def _require_prefixed_hash(value: Any, field: str) -> None:
        if re.fullmatch(r"sha256:[0-9a-f]{64}", str(value)) is None:
            raise ProtocolError(f"Execution {field} must be sha256:<lowercase hex>.")

    def _verify_execution_signature(
        self,
        *,
        protected: Mapping[str, Any],
        payload: Mapping[str, Any],
        encoded_signature: str,
        kid: str,
    ) -> None:
        jwk = self._load_execution_receipt_jwk(kid)
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
                self._base64url_encode(_canonical_json(dict(protected)).encode())
                + "."
                + self._base64url_encode(_canonical_json(dict(payload)).encode())
            ).encode("ascii")
            public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            raise ProtocolError("Execution receipt ES256 signature is invalid.") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("Execution receipt key or signature encoding is invalid.") from exc

    def _load_execution_receipt_jwk(self, kid: str) -> dict[str, Any]:
        cached = self._execution_receipt_keys.get(kid)
        if cached is not None:
            return cached
        response = self._get_json(EXECUTION_RECEIPT_KEY_ENDPOINT)
        if response.status_code != 200:
            self._raise_http_error(response, "Execution receipt JWKS lookup failed")
        document = self._parse_json_object(response, "execution receipt JWKS")
        if document.get("receipt_type") != EXECUTION_GATE_RECEIPT_TYPE:
            raise ProtocolError("Execution receipt JWKS has the wrong receipt_type.")
        if document.get("service") != "x402-execution-gate":
            raise ProtocolError("Execution receipt JWKS has the wrong service.")
        keys = document.get("keys")
        if not isinstance(keys, list):
            raise ProtocolError("Execution receipt JWKS omitted keys[].")
        published: dict[str, dict[str, Any]] = {}
        for item in keys:
            if not isinstance(item, dict) or not isinstance(item.get("kid"), str):
                raise ProtocolError("Execution receipt JWKS contains a malformed key.")
            required = {
                "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
            }
            for field, expected_value in required.items():
                if item.get(field) != expected_value:
                    raise ProtocolError(f"Execution receipt JWK has invalid {field}.")
            if not isinstance(item.get("x"), str) or not isinstance(item.get("y"), str):
                raise ProtocolError("Execution receipt JWK omitted P-256 coordinates.")
            published[item["kid"]] = dict(item)
        self._execution_receipt_keys.update(published)
        selected = self._execution_receipt_keys.get(kid)
        if selected is None:
            raise ProtocolError("Execution receipt kid is not published by the service.")
        return selected

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
