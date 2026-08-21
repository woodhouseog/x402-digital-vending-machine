#!/usr/bin/env python3
"""Canonical x402 v2 exact-SVM client for the text-cleanup service.

The buyer signs only the transfer-authority portion of the transaction. The
facilitator supplies the fee-payer signature, broadcasts, and settles it. This
client never broadcasts a payment itself.
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

import requests
from base58 import b58decode
from requests import Response, Session
from solders.keypair import Keypair
from x402 import x402ClientSync
from x402.http import x402HTTPClientSync
from x402.mechanisms.svm import KeypairSigner
from x402.mechanisms.svm.exact.register import register_exact_svm_client


SERVICE_ENDPOINT = "https://www.x402digitalvendingmachine.store/v1/clean"
MAINNET_RPC = "https://api.mainnet-beta.solana.com"
SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
RECIPIENT_WALLET = "E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD"
PAYMENT_AMOUNT_ATOMIC = 2_000
USDC_DECIMALS = 6
PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED"
PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE"


class SDKError(RuntimeError):
    """Base error raised by the public SDK."""


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


class X402ClientSDK:
    """One-call client for the pinned production cleanup endpoint."""

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

    def _post_clean(
        self,
        text: str,
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
                self.endpoint,
                json={"text": text},
                headers=headers,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise SDKError(f"Request to {self.endpoint} failed: {exc}") from exc

    def _validate_payment_required(
        self, payment_required: dict[str, Any]
    ) -> ChallengeMetadata:
        if payment_required.get("x402Version") != 2:
            raise ProtocolError("Payment challenge must use x402Version 2.")

        resource = payment_required.get("resource")
        if not isinstance(resource, dict) or resource.get("url") != self.endpoint:
            raise ProtocolError(
                f"Payment resource must be exactly {self.endpoint}."
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
        if isinstance(amount, bool) or str(amount) != str(PAYMENT_AMOUNT_ATOMIC):
            raise ProtocolError(
                f"Payment amount must be {PAYMENT_AMOUNT_ATOMIC} atomic USDC."
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

        return ChallengeMetadata(
            resource=resource,
            accepted=accepted,
            fee_payer=fee_payer.strip(),
            memo=memo,
            challenge_id=challenge_id.strip(),
        )

    def _validate_payment_payload(
        self,
        headers: Mapping[str, str],
        metadata: ChallengeMetadata,
    ) -> None:
        encoded = self._mapping_header(headers, PAYMENT_SIGNATURE_HEADER)
        if not encoded:
            raise ProtocolError("x402 client did not produce PAYMENT-SIGNATURE.")
        envelope = self._decode_base64_json(encoded, PAYMENT_SIGNATURE_HEADER)
        if envelope.get("x402Version") != 2:
            raise ProtocolError("Generated payment payload is not x402 v2.")

        resource = envelope.get("resource")
        if not isinstance(resource, dict) or resource.get("url") != self.endpoint:
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
        for field in ("feePayer", "memo", "decimals"):
            if generated_extra.get(field) != expected_extra.get(field):
                raise ProtocolError(
                    f"Generated payment payload changed accepted.extra.{field}."
                )

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
