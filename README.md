# x402 Digital Vending Machine

Clean noisy text before it reaches an agent's context window. The service
collapses repeated whitespace and returns compact structured JSON for a flat
`0.002 USDC` per call, with no account or API key.

- Storefront: <https://www.x402digitalvendingmachine.store/>
- Paid endpoint: `POST https://www.x402digitalvendingmachine.store/v1/clean`
- Price: `2000` atomic units (`0.002 USDC`)
- Network: Solana mainnet
- Protocol: x402 v2, `exact` scheme

## One-line Python integration

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

## Buyer contract

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

## Wallet safety

Keep wallet secrets local. Never place a seed phrase or private key in source
control, browser code, a discovery document, or an HTTP request body. The
client also avoids automatic paid retries after ambiguous network failures.
