# Schema Gate Python client guide

The `x402_cleanup` package exposes `schema_gate(...)` and its alias
`gate_json(...)` for one signed JSON evaluation. Install from GitHub:

```bash
python -m pip install "git+https://github.com/woodhouseog/x402-digital-vending-machine.git"
```

```python
from x402_cleanup import gate_json

decision = gate_json(
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
    keypair_path="~/.config/solana/id.json",
)
```

The SDK computes a deterministic `sha256:<hex>` commitment over canonical
acceptance criteria. It sends the unsigned request first, validates the pinned
Schema Gate resource, Solana mainnet, official USDC mint, recipient, and
challenged price, and only then asks the x402 library to sign. The default
authorization ceiling is `10000` atomic USDC (`0.010 USDC`).

Both `ACCEPT` and `REJECT` are completed signed evaluations and cost one use.
Only `ACCEPT` includes `output`. Malformed preflight, payment, or provider
failures are unsettled. An exact idempotent retry returns the saved receipt at
no additional charge; each distinct task requires its own paid evaluation.

Use `receipt`, `verdict`, `checks`, and `recovery` defensively. Do not expect
`output` on a `REJECT`. The client never automatically resends a monetary
request after an ambiguous transport failure; retry the same unsigned request
with the same idempotency key to request recovery.

Keep wallet secrets local. Integration is free, but every newly completed
evaluation is billed. This repository does not claim a PyPI release or MCP
registry publication.

## Legacy cleanup client

The `x402_cleanup` package provides a single-call Python interface for the
production text-normalization service.

## Install

```bash
python -m pip install "git+https://github.com/woodhouseog/x402-digital-vending-machine.git"
```

Python 3.10 or newer is required.

## Use an in-memory keypair

```python
from solders.keypair import Keypair
from x402_cleanup import clean_text

agent_key = Keypair.from_bytes(secret_key_bytes)
result = clean_text(
    "Raw   feed\n\nwith      extra spacing",
    wallet_key=agent_key,
)
print(result["cleaned_text"])
```

## Use a local Solana keypair file

```python
from x402_cleanup import clean_text

result = clean_text(
    "Raw   feed\n\nwith      extra spacing",
    keypair_path="~/.config/solana/id.json",
)
```

Provide either `wallet_key` or `keypair_path`, never both. The payer must hold
enough Solana USDC for the `0.002 USDC` charge.

## What the client enforces

Before signing, the client requires all of these values to match exactly:

- x402 version `2`
- resource `https://www.x402digitalvendingmachine.store/v1/clean`
- `exact` scheme on Solana mainnet
- official Solana USDC mint
- `2000` atomic units (`0.002 USDC`)
- recipient `E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD`

It then creates the canonical signed payment payload, retries the original
request once, validates the settlement response, and returns the JSON result.
It does not accept a wallet address or raw transaction hash as proof.

## Errors and retry safety

- `SDKError`: invalid input, key material, transport failure, or unexpected HTTP response
- `ProtocolError`: the server challenge or response does not match the pinned contract
- `PaymentError`: payment creation or settlement was rejected

A paid request is not automatically repeated after an ambiguous connection
failure. Confirm the wallet and settlement state before manually trying again.
