# Python client guide

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
