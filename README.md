# x402 Digital Vending Machine: Schema Gate

Schema Gate gives an automated buyer a signed, deterministic verdict on whether
JSON satisfies a declared schema and acceptance policy. A completed `ACCEPT` or
`REJECT` evaluation costs `0.010 USDC` (`10000` atomic units). Malformed
preflight requests, payment failures, and provider failures do not settle. An
exact retry with the same `idempotency_key` recovers the original receipt and
does not create a second charge. Every new task is a new paid use; installing
or integrating the SDK is free.

- Storefront: <https://www.x402digitalvendingmachine.store/>
- Schema Gate: `POST https://www.x402digitalvendingmachine.store/v1/schema-gate`
- Network: Solana mainnet
- Protocol: x402 v2, `exact` scheme

## Python integration

Install directly from the public source repository (no PyPI publication is
claimed):

```bash
python -m pip install "git+https://github.com/woodhouseog/x402-digital-vending-machine.git"
```

```python
from x402_cleanup import schema_gate

result = schema_gate(
    order_id="order-1042",
    idempotency_key="order-1042-v1",
    input={"sku": "A-7", "quantity": 2},
    target_schema={
        "type": "object",
        "required": ["sku", "quantity"],
        "properties": {
            "sku": {"type": "string"},
            "quantity": {"type": "integer", "minimum": 1},
        },
    },
    acceptance_criteria={"quantity_limit": 10},
    wallet_key=agent_key,
)

print(result["verdict"])
if result["verdict"] == "ACCEPT":
    print(result["output"])
print(result.get("receipt"), result.get("checks"))
```

The client canonicalizes `acceptance_criteria` with sorted compact JSON and
sends `acceptance_commitment = sha256:<hex>`. It probes without wallet use,
validates the returned resource, Solana network, USDC mint, recipient, and
dynamic price, then signs through the standard x402 v2 exact-SVM library only
after a valid HTTP `402`. `max_amount_atomic` defaults to the published `10000`
atomic-unit ceiling.

## Schema Gate request contract

Required JSON keys are `order_id`, `idempotency_key`, `input`, `target_schema`,
`acceptance_criteria`, and `acceptance_commitment`. `expires_at` is optional.
Use a new idempotency key for each new evaluation. Reuse a key only to recover
the exact same request.

The response uses `verdict`, optional structured `checks`, and a signed
`receipt`. `output` is present only for `ACCEPT`. `recovery` identifies an
idempotent replay when supplied. Both `ACCEPT` and `REJECT` are completed paid
verdicts; malformed/provider failures are not verdicts and remain unsettled.

## Legacy text cleanup

Clean noisy text before it reaches an agent's context window. The service
collapses repeated whitespace and returns compact structured JSON for a flat
`0.002 USDC` per call, with no account or API key.

- Storefront: <https://www.x402digitalvendingmachine.store/>
- Paid endpoint: `POST https://www.x402digitalvendingmachine.store/v1/clean`
- Price: `2000` atomic units (`0.002 USDC`)
- Network: Solana mainnet
- Protocol: x402 v2, `exact` scheme

### Legacy Python integration

Install the client directly from this repository:

```bash
python -m pip install "git+https://github.com/woodhouseog/x402-digital-vending-machine.git"
```

```python
from x402_cleanup import clean_text

result = clean_text(
    "Messy   unstructured\n\ntext",
    wallet_key=agent_key,
)
print(result["cleaned_text"])
```

The wrapper requests the 402 challenge, validates the exact terms, signs the
canonical Solana payment payload with the buyer wallet, resubmits the request,
and returns the service result with its settlement receipt.

### Legacy buyer contract

| Field | Required value |
| --- | --- |
| Resource | `https://www.x402digitalvendingmachine.store/v1/clean` |
| Method | `POST` |
| Request JSON | `{"text":"Text to normalize"}` |
| x402 version | `2` |
| Scheme | `exact` |
| Network | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` |
| Asset | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` |
| Amount | `2000` atomic units |
| Recipient | `E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD` |

An unpaid request returns HTTP `402` with a base64-encoded x402 v2
`PaymentRequired` object in `PAYMENT-REQUIRED`. Retry the same request with a
base64-encoded canonical `PaymentPayload` in `PAYMENT-SIGNATURE`. A wallet
address or raw transaction hash is not a valid payment payload.

A successful paid request returns HTTP `200`, a base64-encoded
`SettlementResponse` in `PAYMENT-RESPONSE`, and JSON shaped like:

```json
{
  "cleaned_text": "Messy unstructured text",
  "endpoint": "/v1/clean",
  "payment": {
    "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "amount": "2000",
    "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  }
}
```

No normalized output is returned until payment is accepted and settled.

## Discovery

- x402: <https://www.x402digitalvendingmachine.store/.well-known/x402.json>
- OpenAPI: <https://www.x402digitalvendingmachine.store/openapi.json>
- Agent summary: <https://www.x402digitalvendingmachine.store/llms.txt>
- MCP descriptor: [`mcp-x402-server-definition.json`](mcp-x402-server-definition.json)
- Client guide: [`docs_CLIENT_GUIDE.md`](docs_CLIENT_GUIDE.md)

`mcp-x402-server-definition.json` is a portable descriptor only. This project
does not claim that an MCP directory has registered or endorsed the service.

## Wallet safety

Keep wallet secrets local. Never place a seed phrase or private key in source
control, browser code, a discovery document, or an HTTP request body. The
client also avoids automatic paid retries after ambiguous network failures.
