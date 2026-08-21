# x402 Schema Gate

Schema Gate is a pay-per-use JSON acceptance service for agents and automated
workflows. A buyer submits JSON, a bounded target schema, and an explicit
five-field acceptance policy. The service returns a signed `ACCEPT` or `REJECT`
receipt after one exact x402 v2 Solana USDC settlement.

## Install from GitHub

```bash
python -m pip install "git+https://github.com/woodhouseog/x402-digital-vending-machine.git"
```

This repository does not claim a PyPI publication or an MCP registry listing.

## One evaluation

```python
from x402_cleanup import schema_gate

criteria = {
    "canonical_json": True,
    "required_fields": ["/sku", "/quantity"],
    "forbidden_patterns": ["<script"],
    "max_output_bytes": 4096,
    "normalizer_version": "schema-gate-c14n-v1",
}

decision = schema_gate(
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

assert decision["receipt_verified"] is True
if decision["verdict"] == "ACCEPT":
    use_result = decision["output"]
```

The SDK canonicalizes the policy and sends its lowercase SHA-256 commitment.
For the policy above, the canonical commitment is:

```text
sha256:f3f8f6ac94fdc2d4eac59f404f26c1eb6cadb63a2625cd6642a0a7a2240b1c63
```

## Exact billing contract

- Endpoint: `POST https://www.x402digitalvendingmachine.store/v1/schema-gate`
- Price: exactly `10000` atomic USDC (`0.010 USDC`)
- Paid outcomes: completed signed `ACCEPT` and `REJECT` evaluations
- Free outcomes: malformed preflight, payment failure, provider failure
- Recovery: an exact retry or recovery-token lookup never creates a second charge
- Recurrence: each distinct task is a new paid evaluation; SDK integration is free

The SDK makes the unsigned preflight first and loads wallet material only after
it validates the pinned x402 resource, network, mint, recipient, and exact
price. It sends one paid request and does not automatically repeat a monetary
request after an ambiguous transport failure.

## Receipt verification and recovery

The SDK verifies the returned ES256 receipt using the service's published JWK:

<https://www.x402digitalvendingmachine.store/.well-known/receipt-key.json>

Verification covers the protected `alg`, `kid`, and receipt type plus the exact
order, idempotency hash, request hash, acceptance commitment, canonical input
and schema hashes, verdict, output hash, checks, recovery terms, and settlement
evidence. `output` is present only for `ACCEPT`.

The server supplies a recovery URL and `sg_` token in the initial 402. They are
exposed as `client.last_recovery`, `SDKError.recovery`, and the final response's
`recovery` object. An explicit token recovery is also available:

```python
from x402_cleanup import recover_schema_gate

recovered = recover_schema_gate(
    order_id="order-1042",
    recovery_token="sg_SERVER_ISSUED_TOKEN",
    idempotency_key="order-1042-v1",
    input={"sku": "A-7", "quantity": 2},
    target_schema={...},
    acceptance_criteria=criteria,
)
```

Original request material is required for recovery so the SDK can bind and
verify the signed receipt rather than trusting an order ID alone.

## Discovery

- x402: <https://www.x402digitalvendingmachine.store/.well-known/x402.json>
- OpenAPI: <https://www.x402digitalvendingmachine.store/openapi.json>
- Agent summary: <https://www.x402digitalvendingmachine.store/llms.txt>
- MCP descriptor: [`mcp-x402-server-definition.json`](mcp-x402-server-definition.json)
- Client guide: [`docs_CLIENT_GUIDE.md`](docs_CLIENT_GUIDE.md)

Keep wallet secrets local. Never put a seed phrase or private key in source
control, discovery documents, browser code, or request bodies.

## Private-pilot Execution Gate

Execution Gate is a private pilot for explicitly enabled integrations. It is
not a universal execution layer and is not currently advertised in the public
x402 manifest, OpenAPI document, `llms.txt`, or MCP descriptor. SDK symbols do
not imply general availability or compatibility with arbitrary execution
targets.

```python
from datetime import datetime, timedelta, timezone
from x402_cleanup import execution_gate

execution = execution_gate(
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
assert execution["execution_verified"] is True
```

`max_amount_atomic` is required and has no SDK default. It is the caller's hard
payment ceiling, not a quote or promised price. The returned 402 supplies the
price for that request, and the SDK rejects any amount above the caller's
ceiling without raising it automatically. The SDK binds that selected amount,
the integration policy, PREPARE and COMMIT evidence, effect acknowledgement,
result, recovery terms, and settlement into a dedicated ES256 receipt verified
against `/.well-known/execution-gate-receipt-jwks.json`.

The paid request is attempted once. An ambiguous transport failure exposes the
server-issued recovery token through `SDKError.recovery` and
`client.last_recovery`; recovery uses only `GET /v1/executions/{order_id}` and
cannot initiate another payment.

The pilot does not guarantee support for every provider or action, execution
success, customer adoption, demand, revenue, or continued availability.
