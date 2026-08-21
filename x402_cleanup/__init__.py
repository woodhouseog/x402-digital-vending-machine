"""One-call client for the x402 Digital Vending Machine."""

from __future__ import annotations

from typing import Any

from scripts.x402_client_sdk import (
    PaymentError,
    ProtocolError,
    SDKError,
    X402ClientSDK,
)

__all__ = [
    "PaymentError",
    "ProtocolError",
    "SDKError",
    "X402ClientSDK",
    "clean_text",
]


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
