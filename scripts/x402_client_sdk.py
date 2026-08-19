#!/usr/bin/env python3
"""Python client wrapper for the x402 Solana USDC text-cleaning endpoint.

The client handles the two-step x402 flow:
1) Probe the cleaning endpoint and capture PAYMENT-REQUIRED challenge metadata.
2) Submit a funded Solana USDC transfer via an optional local keypair,
   then retry the request with a PAYMENT-SIGNATURE proof header.

Usage:
    python3 scripts/x402_client_sdk.py \
      --text "Messy   text   goes   here" \
      --keypair ~/.config/solana/id.json
"""

from __future__ import annotations

import argparse
import base64
import json
import time
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from base58 import b58decode
from requests import Response
from solders.keypair import Keypair
from solders.instruction import AccountMeta
from solders.pubkey import Pubkey
from solders.instruction import Instruction
from solders.sysvar import RENT as SYSVAR_RENT_ACCOUNT
from solders.transaction import Transaction

from solana.rpc.api import Client

# Staticly pinned Solana production values for this service.
SERVICE_ENDPOINT = "https://x402digitalvendingmachine.store/v1/clean"
MAINNET_RPC = "https://api.mainnet-beta.solana.com"
USDC_MINT = Pubkey.from_string("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
RECIPIENT_WALLET = "E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD"
SERVICE_ASSET = str(USDC_MINT)
USDC_DECIMALS = 6
PAYMENT_AMOUNT_USDC = Decimal("0.002")

TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
ASSOCIATED_TOKEN_PROGRAM_ID = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
SYSTEM_PROGRAM_ID = Pubkey.from_string("11111111111111111111111111111111")
SYSVAR_RENT_PUBKEY = SYSVAR_RENT_ACCOUNT


@dataclass
class ChallengeMetadata:
    """Normalized challenge fields used to produce a payment signature."""

    recipient: str
    amount: int
    mint: str
    network: str = SOLANA_NETWORK
    asset_contract: str = SERVICE_ASSET


class SDKError(RuntimeError):
    pass


class X402ClientSDK:
    def __init__(
        self,
        endpoint: str = SERVICE_ENDPOINT,
        rpc_url: str = MAINNET_RPC,
        timeout_seconds: int = 30,
    ) -> None:
        self.endpoint = endpoint
        self.rpc_url = rpc_url
        self.timeout_seconds = timeout_seconds
        self.rpc = Client(rpc_url)

    def clean_text(
        self,
        text: str,
        keypair_path: Optional[str] = None,
        verify_signature: bool = True,
        keypair_timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Run one full 402 loop and return the final JSON response payload."""
        if not text:
            raise SDKError("Text input must be a non-empty string.")

        probe = self._post_clean({"text": text})

        if probe.status_code == 200:
            return self._parse_json_payload(probe, require_payment=False)

        if probe.status_code != 402:
            self._raise_http_error(probe, "Expected a paid challenge flow")

        challenge_header = self._first_non_empty_header(
            probe.headers,
            "PAYMENT-REQUIRED",
            "PAYMENT",
            "X-PAYMENT",
            "WWW-AUTHENTICATE",
        )
        if not challenge_header:
            self._raise_http_error(
                probe,
                "Challenge response did not include PAYMENT-REQUIRED proof metadata",
            )

        challenge = self._decode_challenge(challenge_header)
        challenge_meta = self._extract_challenge_metadata(challenge)

        if not keypair_path:
            raise SDKError(
                "Purchase is required for this operation. Provide --keypair or set "
                "--keypair to a local Solana keypair JSON file path."
            )

        payer = self._load_keypair(keypair_path)
        signature = self._pay_and_capture_signature(
            payer,
            challenge_meta,
            keypair_timeout_seconds=keypair_timeout_seconds,
            verify_signature=verify_signature,
        )

        final_response = self._post_clean(
            {"text": text},
            proof_signature=signature,
            proof_payload=challenge,
        )

        if final_response.status_code != 200:
            self._raise_http_error(final_response, "Payment unlock flow did not complete")

        return self._parse_json_payload(final_response, require_payment=False)

    def _post_clean(
        self,
        payload: Dict[str, Any],
        proof_signature: Optional[str] = None,
        proof_payload: Optional[Dict[str, Any]] = None,
    ) -> Response:
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "x402-client-sdk/1.0",
            "Accept": "application/json",
        }
        if proof_signature:
            headers["PAYMENT-SIGNATURE"] = proof_signature
        elif proof_payload:
            headers["PAYMENT"] = self._encode_payment_payload(proof_payload)

        response = requests.post(
            self.endpoint,
            headers=headers,
            data=json.dumps(payload),
            timeout=self.timeout_seconds,
        )

        return response

    def _pay_and_capture_signature(
        self,
        payer: Keypair,
        challenge: ChallengeMetadata,
        keypair_timeout_seconds: Optional[int] = None,
        verify_signature: bool = True,
    ) -> str:
        """Build and submit the required USDC transfer transaction."""
        mint = Pubkey.from_string(challenge.mint)
        recipient = Pubkey.from_string(challenge.recipient)

        sender_ata = self._derive_associated_token_address(payer.pubkey(), mint)
        recipient_ata = self._derive_associated_token_address(recipient, mint)

        instructions = []
        if not self._account_exists(sender_ata):
            instructions.append(self._create_associated_token_account_ix(payer.pubkey(), payer.pubkey(), mint, sender_ata))
        if not self._account_exists(recipient_ata):
            instructions.append(self._create_associated_token_account_ix(payer.pubkey(), recipient, mint, recipient_ata))

        instructions.append(self._transfer_ata_ix(sender_ata, recipient_ata, payer.pubkey(), challenge.amount))

        recent = self.rpc.get_latest_blockhash().value.blockhash
        tx = Transaction.new_signed_with_payer(
            instructions,
            payer.pubkey(),
            [payer],
            recent,
        )

        signed_tx = bytes(tx)
        send_response = self.rpc.send_raw_transaction(signed_tx)
        if send_response.value is None:
            raise SDKError(f"RPC rejected payment tx: {send_response}")

        signature = str(send_response.value)

        if verify_signature:
            self._wait_for_confirmation(signature, max_wait=keypair_timeout_seconds or 90)

        return signature

    def _wait_for_confirmation(self, signature: str, max_wait: int = 90) -> None:
        """Poll RPC status for the payment signature until finality or timeout."""
        endpoint = self.rpc_url
        deadline = time.time() + max_wait
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignatureStatuses",
            "params": [[signature], {"searchTransactionHistory": True}],
        }

        while time.time() < deadline:
            resp = requests.post(endpoint, json=payload, timeout=self.timeout_seconds)
            try:
                data = resp.json()
            except ValueError:
                data = None

            if not isinstance(data, dict):
                time.sleep(1)
                continue

            status = (
                data.get("result", {}).get("value", [None])[0]
                if isinstance(data.get("result"), dict)
                else None
            )
            if status:
                if status.get("err") is not None:
                    raise SDKError(f"Payment signature failed on-chain: {status.get('err')}")

                conf = (status.get("confirmationStatus") or "").lower()
                if conf in {"confirmed", "finalized"}:
                    return

                # Older nodes may expose finalized via confirmations == 0.
                confirmations = status.get("confirmations")
                if confirmations in {0, "0"}:
                    return

            time.sleep(1)

        raise SDKError(
            f"Timed out waiting for payment confirmation for signature {signature}. "
            "Transaction may still settle shortly; re-run with a retry if needed."
        )

    def _account_exists(self, account: Pubkey) -> bool:
        info = self.rpc.get_account_info(account)
        return bool(info.value)

    @staticmethod
    def _derive_associated_token_address(owner: Pubkey, mint: Pubkey) -> Pubkey:
        return Pubkey.find_program_address(
            [bytes(owner), bytes(TOKEN_PROGRAM_ID), bytes(mint)],
            ASSOCIATED_TOKEN_PROGRAM_ID,
        )[0]

    @staticmethod
    def _create_associated_token_account_ix(
        payer: Pubkey,
        owner: Pubkey,
        mint: Pubkey,
        account: Pubkey,
    ) -> Instruction:
        # SPL Associated Token Program: CreateAssociatedTokenAccount
        return Instruction(
            program_id=ASSOCIATED_TOKEN_PROGRAM_ID,
            data=b"\x00",
            accounts=[
                AccountMeta(payer, is_signer=True, is_writable=True),
                AccountMeta(account, is_signer=False, is_writable=True),
                AccountMeta(owner, is_signer=False, is_writable=False),
                AccountMeta(mint, is_signer=False, is_writable=False),
                AccountMeta(SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
                AccountMeta(SYSVAR_RENT_PUBKEY, is_signer=False, is_writable=False),
            ],
        )

    @staticmethod
    def _transfer_ata_ix(
        source_ata: Pubkey,
        destination_ata: Pubkey,
        owner: Pubkey,
        atomic_amount: int,
    ) -> Instruction:
        if atomic_amount <= 0:
            raise SDKError(f"Invalid USDC transfer amount: {atomic_amount}")

        # SPL Token Transfer instruction index: 3
        transfer_payload = bytes([3]) + int(atomic_amount).to_bytes(8, byteorder="little", signed=False)
        return Instruction(
            program_id=TOKEN_PROGRAM_ID,
            data=transfer_payload,
            accounts=[
                AccountMeta(source_ata, is_signer=False, is_writable=True),
                AccountMeta(destination_ata, is_signer=False, is_writable=True),
                AccountMeta(owner, is_signer=True, is_writable=False),
            ],
        )

    @staticmethod
    def _encode_payment_payload(metadata: Dict[str, Any]) -> str:
        raw = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        return base64.b64encode(raw.encode("utf-8")).decode("ascii")

    @staticmethod
    def _decode_challenge(challenge_header: str) -> Dict[str, Any]:
        def attempt(raw: str) -> Optional[Dict[str, Any]]:
            try:
                return json.loads(raw)
            except Exception:
                pass

            try:
                decoded = base64.b64decode(raw, validate=True)
                decoded_str = decoded.decode("utf-8")
                return json.loads(decoded_str)
            except Exception:
                return None

        # direct JSON
        parsed = attempt(challenge_header)
        if parsed:
            return parsed

        # most challenge strings are sent as base64,<payload> / Bearer <payload>
        for split_token in (",", " "):
            if split_token not in challenge_header:
                continue
            parts = challenge_header.rsplit(split_token, 1)
            if len(parts) == 2:
                candidate = parts[1].strip()
                parsed = attempt(candidate)
                if parsed:
                    return parsed

        return {}

    @staticmethod
    def _extract_challenge_metadata(challenge: Dict[str, Any]) -> ChallengeMetadata:
        recipient = challenge.get("recipient") or challenge.get("payTo") or RECIPIENT_WALLET

        mint = challenge.get("asset_contract") or challenge.get("mint") or SERVICE_ASSET

        amount_raw = challenge.get("amount", str(PAYMENT_AMOUNT_USDC))
        amount_atoms = parse_amount_atomic(amount_raw, challenge.get("asset_decimals", USDC_DECIMALS))

        return ChallengeMetadata(
            recipient=recipient,
            amount=amount_atoms,
            mint=mint,
            network=challenge.get("network", SOLANA_NETWORK),
            asset_contract=mint,
        )

    @staticmethod
    def _first_non_empty_header(response_headers: Any, *header_names: str) -> str:
        for name in header_names:
            value = response_headers.get(name)
            if value:
                return value
            value = response_headers.get(name.lower())
            if value:
                return value
        return ""

    @staticmethod
    def _parse_json_payload(response: Response, *, require_payment: bool = False) -> Dict[str, Any]:
        try:
            payload = response.json()
        except ValueError:
            raise SDKError(f"Response was not JSON: {response.text[:300]}")

        if require_payment and not isinstance(payload, dict):
            raise SDKError("Unexpected response shape while expecting payment metadata")

        return payload

    @staticmethod
    def _raise_http_error(response: Response, context: str) -> None:
        try:
            details = response.text[:500]
        except Exception:
            details = "<no response body>"
        raise SDKError(
            f"{context}. HTTP {response.status_code} from {response.url}. Body: {details}"
        )

    @staticmethod
    def _load_keypair(keypair_path: str) -> Keypair:
        path = Path(keypair_path).expanduser()
        if not path.exists():
            raise SDKError(f"Could not locate keypair path: {path}")

        raw = path.read_text(encoding="utf-8").strip()
        if not raw:
            raise SDKError(f"Keypair file is empty: {path}")

        data = json.loads(raw)

        if isinstance(data, dict):
            secret = data.get("secret_key") or data.get("private_key") or data.get("secret")
            if not secret:
                raise SDKError(
                    "Keypair dict format not supported. Expected array[64] or encoded secret string."
                )
            if isinstance(secret, str):
                secret_bytes = b58decode(secret)
            else:
                secret_bytes = bytes(secret)
        elif isinstance(data, list):
            secret_bytes = bytes(data)
        elif isinstance(data, str):
            secret_bytes = b58decode(data)
        else:
            raise SDKError("Unsupported keypair format.")

        if len(secret_bytes) == 32:
            return Keypair.from_seed(secret_bytes)
        if len(secret_bytes) != 64:
            raise SDKError(
                f"Unsupported secret key length ({len(secret_bytes)}). Expect 32 or 64 bytes."
            )
        return Keypair.from_bytes(secret_bytes)


def parse_amount_atomic(amount_raw: Any, decimals: int = USDC_DECIMALS) -> int:
    """Accept decimal UI strings like "0.002" and integers, returning atomic units."""
    try:
        amount = Decimal(str(amount_raw))
    except Exception as exc:
        raise SDKError(f"Unable to parse amount '{amount_raw}': {exc}")

    if amount == 0:
        raise SDKError("Amount must be greater than 0")

    amount = amount.quantize(Decimal("1") if amount % 1 == 0 else Decimal("1.000000"), rounding=ROUND_HALF_UP)

    # If it looks like an on-chain integer atom value, use it directly.
    if amount.as_tuple().exponent == 0 and amount > Decimal("1"):
        return int(amount)

    precision = int(decimals)
    scale = Decimal(10) ** precision
    return int((amount * scale).to_integral_value(rounding=ROUND_HALF_UP))


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="x402 Solana text cleanup SDK wrapper")
    parser.add_argument("--text", required=True, help="Raw text to clean")
    parser.add_argument(
        "--text-to-clean",
        dest="text_to_clean",
        help="Backward-compatible alias for --text",
    )
    parser.add_argument(
        "--endpoint",
        default=SERVICE_ENDPOINT,
        help="Service endpoint URL (defaults to /v1/clean)",
    )
    parser.add_argument(
        "--rpc-url",
        default=MAINNET_RPC,
        help="Solana JSON RPC endpoint",
    )
    parser.add_argument(
        "--keypair",
        default=None,
        help="Optional path to a Solana keypair JSON file",
    )
    parser.add_argument(
        "--no-wait",
        action="store_true",
        help="Submit payment and immediately request unlock without waiting for RPC confirmation",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30,
        help="HTTP/RPC timeout in seconds",
    )
    return parser


def main() -> None:
    args = build_cli().parse_args()
    text = args.text_to_clean or args.text

    client = X402ClientSDK(endpoint=args.endpoint, rpc_url=args.rpc_url, timeout_seconds=args.timeout)
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
