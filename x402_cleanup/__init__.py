"""One-call client for the x402 Digital Vending Machine."""

from __future__ import annotations

from typing import Any

from scripts.x402_client_sdk import (
    EXECUTION_GATE_ENDPOINT,
    EXECUTION_GATE_RECEIPT_TYPE,
    EXECUTION_RECEIPT_KEY_ENDPOINT,
    RECEIPT_KEY_ENDPOINT,
    SCHEMA_GATE_AMOUNT_ATOMIC,
    SCHEMA_GATE_ENDPOINT,
    PaymentError,
    ProtocolError,
    SDKError,
    X402ClientSDK,
    build_acceptance_commitment,
    canonicalize_acceptance_criteria,
)

__all__ = [
    "EXECUTION_GATE_ENDPOINT",
    "EXECUTION_GATE_RECEIPT_TYPE",
    "EXECUTION_RECEIPT_KEY_ENDPOINT",
    "RECEIPT_KEY_ENDPOINT",
    "SCHEMA_GATE_AMOUNT_ATOMIC",
    "SCHEMA_GATE_ENDPOINT",
    "PaymentError",
    "ProtocolError",
    "SDKError",
    "X402ClientSDK",
    "build_acceptance_commitment",
    "canonicalize_acceptance_criteria",
    "clean_text",
    "execution_gate",
    "gate_json",
    "recover_schema_gate",
    "recover_execution",
    "schema_gate",
]


def execution_gate(
    *,
    order_id: str,
    idempotency_key: str,
    integration_id: str,
    integration_version: str,
    action_id: str,
    input: Any,
    target_schema: dict[str, Any],
    acceptance_criteria: Any,
    max_amount_atomic: int,
    wallet_key: Any | None = None,
    keypair_path: str | None = None,
    expires_at: str | int | None = None,
) -> dict[str, Any]:
    """Purchase one explicitly authorized private-pilot execution."""
    return X402ClientSDK().execution_gate(
        order_id=order_id,
        idempotency_key=idempotency_key,
        integration_id=integration_id,
        integration_version=integration_version,
        action_id=action_id,
        input=input,
        target_schema=target_schema,
        acceptance_criteria=acceptance_criteria,
        max_amount_atomic=max_amount_atomic,
        wallet_key=wallet_key,
        keypair_path=keypair_path,
        expires_at=expires_at,
    )


def recover_execution(
    *,
    order_id: str,
    recovery_token: str,
    idempotency_key: str,
    integration_id: str,
    integration_version: str,
    action_id: str,
    input: Any,
    target_schema: dict[str, Any],
    acceptance_criteria: Any,
    expires_at: str | int | None = None,
) -> dict[str, Any]:
    """Recover a private-pilot execution with a GET-only request."""
    return X402ClientSDK().recover_execution(
        order_id=order_id,
        recovery_token=recovery_token,
        idempotency_key=idempotency_key,
        integration_id=integration_id,
        integration_version=integration_version,
        action_id=action_id,
        input=input,
        target_schema=target_schema,
        acceptance_criteria=acceptance_criteria,
        expires_at=expires_at,
    )


def schema_gate(
    *,
    order_id: str,
    idempotency_key: str,
    input: Any,
    target_schema: dict[str, Any],
    acceptance_criteria: Any,
    wallet_key: Any | None = None,
    keypair_path: str | None = None,
    expires_at: str | int | None = None,
    max_amount_atomic: int = SCHEMA_GATE_AMOUNT_ATOMIC,
) -> dict[str, Any]:
    """Purchase one Schema Gate evaluation or recover an exact retry."""
    return X402ClientSDK().schema_gate(
        order_id=order_id,
        idempotency_key=idempotency_key,
        input=input,
        target_schema=target_schema,
        acceptance_criteria=acceptance_criteria,
        wallet_key=wallet_key,
        keypair_path=keypair_path,
        expires_at=expires_at,
        max_amount_atomic=max_amount_atomic,
    )


def gate_json(**kwargs: Any) -> dict[str, Any]:
    """Alias for :func:`schema_gate`."""
    return schema_gate(**kwargs)


def recover_schema_gate(
    *,
    order_id: str,
    recovery_token: str,
    idempotency_key: str,
    input: Any,
    target_schema: dict[str, Any],
    acceptance_criteria: Any,
    expires_at: str | int | None = None,
) -> dict[str, Any]:
    """Recover a settled Schema Gate order without creating a new payment."""
    return X402ClientSDK().recover_order(
        order_id=order_id,
        recovery_token=recovery_token,
        idempotency_key=idempotency_key,
        input=input,
        target_schema=target_schema,
        acceptance_criteria=acceptance_criteria,
        expires_at=expires_at,
    )


def clean_text(
    text: str,
    *,
    wallet_key: Any | None = None,
    keypair_path: str | None = None,
) -> dict[str, Any]:
    """Purchase one normalization call and return its structured result."""
    return X402ClientSDK().clean_text(
        text,
        wallet_key=wallet_key,
        keypair_path=keypair_path,
    )
