# Schema Gate Python client guide

Install the public package directly from its GitHub repository:

```bash
python -m pip install "git+https://github.com/woodhouseog/x402-digital-vending-machine.git"
```

```python
from x402_cleanup import X402ClientSDK

client = X402ClientSDK(timeout_seconds=30)
criteria = {
    "canonical_json": True,
    "required_fields": ["/sku", "/quantity"],
    "forbidden_patterns": ["<script"],
    "max_output_bytes": 4096,
    "normalizer_version": "schema-gate-c14n-v1",
}

try:
    decision = client.schema_gate(
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
            "additionalProperties": False,
        },
        acceptance_criteria=criteria,
        keypair_path="~/.config/solana/id.json",
    )
except Exception as error:
    # Present after a valid 402, including ambiguous paid-delivery failures.
    print(getattr(error, "recovery", None) or client.last_recovery)
    raise
```

`acceptance_criteria` is not an open-ended business-rules object. It must have
exactly these five fields:

| Field | Contract |
|---|---|
| `canonical_json` | literal `true` |
| `required_fields` | up to 64 bounded RFC 6901 JSON Pointers |
| `forbidden_patterns` | up to 32 non-empty literal strings |
| `max_output_bytes` | integer from 2 through 100000 |
| `normalizer_version` | literal `schema-gate-c14n-v1` |

`idempotency_key` must contain 8-128 characters. `expires_at`, when supplied,
must be an RFC 3339 timestamp with a timezone or an epoch integer 30 seconds to
24 hours in the future.

The SDK computes the `sha256:<hex>` commitment, performs an unsigned preflight,
and requires exactly `10000` atomic USDC before creating a canonical x402 v2
exact-SVM `PaymentPayload`. Both final `ACCEPT` and `REJECT` receipts cost one
evaluation. Malformed preflight, payment, and provider failures do not settle.

The SDK verifies every delivered ES256 receipt against
`/.well-known/receipt-key.json` and binds it to the original request, output,
checks, recovery terms, and payment evidence. Never use an unverified `output`.

For explicit recovery, retain the server-issued token and call:

```python
recovered = client.recover_order(
    order_id="order-1042",
    recovery_token=client.last_recovery["token"],
    idempotency_key="order-1042-v1",
    input={"sku": "A-7", "quantity": 2},
    target_schema={...},
    acceptance_criteria=criteria,
)
```

This sends `GET /v1/orders/{order_id}` with the token and cannot initiate a
payment. An exact idempotent retry/recovery is free. Each new task needs a new
order and one paid evaluation. The SDK is free to integrate.

This repository does not claim PyPI publication, MCP registry acceptance,
external demand, or revenue.

## Private-pilot Execution Gate

Execution Gate is a private pilot for explicitly enabled integrations. It is
not a universal execution layer and is not currently advertised in the public
x402 manifest, OpenAPI document, `llms.txt`, or MCP descriptor. SDK symbols do
not imply general availability or compatibility with arbitrary execution
targets.

```python
from datetime import datetime, timedelta, timezone

execution = client.execution_gate(
    order_id="execution-1042",
    idempotency_key="execution-1042-v1",
    integration_id="canary",
    integration_version="v1",
    action_id="commit",
    input={"sku": "A-7", "quantity": 2},
    target_schema={"type": "object"},
    acceptance_criteria=criteria,
    expires_at=(datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    max_amount_atomic=17_500,  # Illustrative ceiling, not a quoted price.
    keypair_path="~/.config/solana/id.json",
)
```

`max_amount_atomic` is mandatory and has no SDK default. It is a hard caller
ceiling, not a quote or promised price; the SDK rejects a challenged amount
above it. The server price is bound into the payment and the dedicated ES256
execution receipt. That receipt also binds integration identity and policy,
PREPARE and COMMIT hashes, the effect acknowledgement, result, settlement, and
recovery token hash. Public verification keys, including retained rotation
keys, are read from `/.well-known/execution-gate-receipt-jwks.json`.

If paid delivery is ambiguous, use `client.last_recovery` or
`SDKError.recovery`, then call `client.recover_execution(...)` with the exact
original request fields, `expires_at`, and server-issued token. Recovery is a
GET-only operation and never loads a wallet, signs a transaction, or creates a
payment.

The pilot does not guarantee support for every provider or action, execution
success, customer adoption, demand, revenue, or continued availability.
