"""One-call client for the x402 Digital Vending Machine."""

from __future__ import annotations

from typing import Any

from scripts.x402_client_sdk import (
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
    "PaymentError",
    "ProtocolError",
    "SDKError",
    "X402ClientSDK",
    "build_acceptance_commitment",
    "canonicalize_acceptance_criteria",
    "clean_text",
    "gate_json",
    "schema_gate",
]


def schema_gate(
    *,
    order_id: str,
    idempotency_key: str,
    input: Any,
    target_schema: dict[str, Any],
    acceptance_criteria: Any,
    wallet_key: Any | None = None,
    keypair_path: str | None = None,
    expires_at: str | None = None,
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
    "SCHEMA_GATE_AMOUNT_ATOMIC",
    "SCHEMA_GATE_ENDPOINT",
