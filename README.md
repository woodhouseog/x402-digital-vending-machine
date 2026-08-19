# Tollbooth API (Solana USDC x402)

This service is intentionally Solana-only:

- Payment settlement: `USDC` on Solana
- Destination wallet: `E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD`
- Proof style: x402 direct proof replay-safe by `tx_hash`

## What’s implemented

- Strict x402 402-challenge flow on `/v1/process` and `/v1/clean`
- On-chain-style proof validation (network, recipient, amount, and asset checks)
- Anti-replay ledger (SQLite) keyed by transaction hash
- Receipt and events dashboard at `/dashboard`
- Discoverability for AI clients (`/x402.json`, `/openapi.json`, `/llms.txt`, `/agents.txt`)

## Quick start

1. Ensure `.env` matches your target wallet and network.

   Example key values:
   - `PAYMENT_PROVIDER=solana`
   - `PAYMENT_CURRENCY=USDC`
   - `SERVICE_PRICE_USD=0.002`
   - `SUPPORTED_NETWORK=solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`
   - `USDC_CONTRACT_ADDRESS=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`
   - `RECEIVER_WALLET=E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD`
   - `DB_FILE=payment_registry.db`
   - `DASHBOARD_USERNAME=admin`
   - `DASHBOARD_PASSWORD=<strong-random-secret>`

2. Install requirements:

```bash
python -m pip install -r requirements.txt
```

3. Start:

```bash
python server.py
```

Or use the one-click launcher:

```bash
/Users/woodhouse/Desktop/CRYPTO\ TOOL\ USDC/launch-live.command
```

## One-click workflow

`launch-live.command` does:

- starts the server
- waits for `/__service`
- probes payment challenge on `/v1/process`
- submits an auto-generated local proof retry
- prints current dashboard/DB proof status and writes `/launch-live.ready-bundle.json`

### Cloudflare proxy-shield route (recommended for hidden origin)

Set these `.env` values to force the launcher to start your app through a fixed localtunnel host served via Cloudflare edge:

```bash
BASE_URL=https://www.x402digitalvendingmachine.store
FORCE_TUNNEL=1
TUNNEL_PROVIDER=localtunnel
TUNNEL_SUBDOMAIN=gold-bikes-yawn
TUNNEL_HOST=https://loca.lt
TUNNEL_LOCAL_HOST=127.0.0.1
TRUST_PROXY_HEADERS=1
```

Then in Squarespace DNS set a CNAME:

```txt
www -> gold-bikes-yawn.loca.lt
```

Keep `www` routed through this CNAME and avoid direct A-record internet exposure on `www` for the production path.

Then run:

```bash
/Users/woodhouse/Desktop/CRYPTO\ TOOL\ USDC/launch-live.command
```

### Use Cloudflare Tunnel (clean public URL, no localtunnel)

Install and configure one bypass-resistant tunnel:

```bash
brew install cloudflared
cloudflared tunnel login
cloudflared tunnel create crypto-tool-usdc
```

In `~/.cloudflared/config.yml`, add:

```yml
tunnel: <TUNNEL-ID>
credentials-file: /Users/<you>/.cloudflared/<TUNNEL-ID>.json

ingress:
  - hostname: api.yourdomain.com
    service: http://localhost:8080
  - service: http_status:404
```

Then route DNS and run:

```bash
cloudflared tunnel route dns <TUNNEL-ID> api.yourdomain.com
cloudflared tunnel run crypto-tool-usdc
```

Use your clean URL for one-click launch:

```bash
PUBLIC_BASE_URL=https://api.yourdomain.com launch-live.command
```

`/v1/payment-events` is still protected by session login and never uses URL token secrets.

The dashboard URL is printed and also stored in:

```bash
/Users/woodhouse/Desktop/CRYPTO\ TOOL\ USDC/.launcher_port
```

## Payment flow in practice

1. Call `POST /v1/process` with:

```json
{"text_to_clean":"hello world"}
```

2. You receive HTTP 402 with challenge metadata (`PAYMENT`, `PAYMENT-REQUIRED`, `PAYMENT-RESPONSE`, `WWW-Authenticate`).

3. Retry with the same body and a header like:

- `X-PAYMENT: <base64-or-json proof>`
- or `PAYMENT: <base64-or-json proof>`

Proof needs at minimum:

- `tx_hash` (Solana transaction signature string)
- `recipient` (`E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD`)
- `network` (`solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`)
- `amount` (`0.002`)
- `asset_contract` (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`)

A verified submission returns HTTP 200 with `{ "status": "success", "cleaned_result": "..." }` and a `PAYMENT-RESPONSE` header.

### Quick 402 Client Verification (x402_process_client.py)

Run this two-step flow with the sample client:

1. Trigger the 402 challenge on the process endpoint:

```bash
python3 /Users/woodhouse/Desktop/"CRYPTO TOOL USDC"/x402_process_client.py \
  --url https://www.x402digitalvendingmachine.store/v1/process \
  --text "Clean this line with excessive   spacing and odd punctuation!!!" \
  --skip-second-step
```

2. Re-submit with an already-built proof token (sample placeholder by default):

```bash
python3 /Users/woodhouse/Desktop/"CRYPTO TOOL USDC"/x402_process_client.py \
  --url https://www.x402digitalvendingmachine.store/v1/process \
  --text "Clean this line with excessive   spacing and odd punctuation!!!" \
  --proof payment_proof.sample.json
```

For raw API testing, both paid routes share the same middleware and endpoint marker:

- `POST /v1/process`
- `POST /v1/clean`

Use payload `{"text_to_clean": "..."}` and include `PAYMENT-SIGNATURE` (or `PAYMENT` / `X-PAYMENT`) on the second request when testing with custom tooling.

### Python SDK Wrapper (`scripts/x402_client_sdk.py`)

For one-command developer adoption, use the new reusable wrapper in `scripts/x402_client_sdk.py`:

```bash
python3 /Users/woodhouse/Desktop/"CRYPTO TOOL USDC"/scripts/x402_client_sdk.py \
  --text "Messy   unstructured   text   payload" \
  --endpoint https://x402digitalvendingmachine.store/v1/clean \
  --keypair /absolute/path/to/solana/keypair.json
```

The SDK performs:

1. `POST` probe to the service.
2. Automatic challenge handling on `402`.
3. On-chain 0.002 USDC payment flow with provided keypair (Solana mainnet).
4. Signed proof re-submission with `PAYMENT-SIGNATURE`.
5. Returns the final cleaned JSON response on `200 OK`.

You can also bypass wait confirmation for immediate local retries with `--no-wait`.

## Runtime routes

- `/`
- `/health`
- `/v1`
- `/v1/process` (POST)
- `/v1/clean` (POST)
- `/dashboard` (requires authenticated session via `/login`)
- `/v1/payment-events`
- `/login` (POST username/password form)
- `/logout`
- `/x402.json`
- `/.well-known/x402.json`
- `/openapi.json`
- `/.well-known/openapi.json`
- `/llms.txt`
- `/agents.txt`
- `/agent-card.json`
- `/.well-known/agent-card.json`

## Monitoring and revenue check

- `/dashboard` and `/v1/payment-events` are protected by `/login` session auth.
- `/v1/payment-events` JSON includes total revenue, 24h volume, attempts, and verified calls.

If you want a fresh state for a fresh launch, delete `payment_registry.db` before starting:

```bash
rm -f '/Users/woodhouse/Desktop/CRYPTO TOOL USDC/payment_registry.db'
```

## Backup strategy for the live event store

This project uses live-safe SQLite hot backups so the payment ledger remains protected under active traffic.

### Runnable backup script

Create and use:

```bash
/Users/woodhouse/Desktop/CRYPTO\ TOOL\ USDC/scripts/backup-payment-events.sh
```

Mark it executable:

```bash
chmod +x "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/scripts/backup-payment-events.sh"
```

### Operational automation schedule

#### Option A: Cron (simple)

Append this to your crontab:

```text
# Execute the live-safe database snapshot protocol every 15 minutes
*/15 * * * * "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/scripts/backup-payment-events.sh" >> "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/backups/backup_cron.log" 2>&1
```

#### Option B: Native launchd (macOS persistent daemon)

Create:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://apple.com">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.x402.backup</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/woodhouse/Desktop/CRYPTO TOOL USDC/scripts/backup-payment-events.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>900</integer> <!-- 900 seconds = 15 minutes -->
    <key>StandardOutPath</key>
    <string>/Users/woodhouse/Desktop/CRYPTO TOOL USDC/backups/backup_launchd.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/woodhouse/Desktop/CRYPTO TOOL USDC/backups/backup_launchd.log</string>
</dict>
</plist>
```

Load it with:

```bash
launchctl load ~/Library/LaunchAgents/com.x402.backup.plist
```

## Discovery checks

With live port in `.launcher_port`:

```bash
curl -sS http://localhost:$(cat /Users/woodhouse/Desktop/CRYPTO\ TOOL\ USDC/.launcher_port)/x402.json | jq .
curl -sS http://localhost:$(cat /Users/woodhouse/Desktop/CRYPTO\ TOOL\ USDC/.launcher_port)/openapi.json | jq '.paths | keys'
curl -i -H "Content-Type: application/json" \
  -d '{"text_to_clean":"hello"}' \
  http://localhost:$(cat /Users/woodhouse/Desktop/CRYPTO\ TOOL\ USDC/.launcher_port)/v1/process
```

## 📋 Operator Runbook: Live Log Monitoring & Telemetry

This section details how to monitor your live x402 digital vending machine node during real agent transactions. Use these command recipes and telemetry patterns to verify health, audit payments, and quickly diagnose network issues.

## The Core Monitoring View

Because your Python environment is pinned to an unbuffered stream (`-u`), you can watch transaction handshakes execute over the web in real-time.

```bash
tail -f "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/server_stdout.log"
```

## Anatomy of a Healthy 2-Step Transaction Loop

A standard, successful machine-to-machine exchange will emit exactly two log entries in close succession.

### Phase 1: The Initial Challenge Handshake (HTTP 402)

An external agent discovers your endpoint and probes it without a payment signature.

```
inbound_request | path=/v1/clean | ip=172.68.22.41 | agent=LangChainAgentCrawler/1.0 | signature=absent | text_len=142
outbound_lifecycle | path=/v1/clean | status=402 | challenge=issued | settled=no | latency=1.2ms
```

What to verify:

- Status must be 402
- challenge must be issued
- latency should be ultra-low (sub-5ms) because no blockchain queries are running yet

### Phase 2: On-Chain Verification & Delivery (HTTP 200)

The agent reads your challenge header, submits exactly 0.002 USDC on Solana Mainnet, and retries the request with the transaction hash.

```
inbound_request | path=/v1/clean | ip=172.68.22.41 | agent=LangChainAgentCrawler/1.0 | signature=5h8X...9Zuh | text_len=142
outbound_lifecycle | path=/v1/clean | status=200 | challenge=no | settled=yes | latency=2104.5ms
```

What to verify:

- Status must transition to 200
- settled must be yes

Note on latency:

- Latency will normally spike to 2-3 seconds during Phase 2 while the server performs an RPC lookup and verification before cleanup execution.

## Incident Isolation Patterns (Troubleshooting)

Use these targeted grep strings to isolate telemetry during investigations.

### A. Auditing Dashboard Intrusions (Brute-Force & Abuse Checks)

To isolate administrative dashboard access attempts and map unauthorized scans against your `/v1/payment-volume` query endpoint:

```bash
grep "path=/v1/payment-volume" "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/server_stdout.log" | grep "auth=denied"
```

### B. Catching Spoofed or Replayed Signatures

If a bad proof is sent or an old fake hash is replayed (`payment_not_verified`), extract them here:

```bash
grep "status=402" "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/server_stdout.log" | grep -v "signature=absent"
```

Diagnostic tip:

- If a single IP floods these logs, it likely indicates repeated failures from a script with unconfirmed wallets or stale transaction signatures.

### C. Isolating Downstream Bottlenecks

To diagnose performance stutters or inspect long clean runs:

```bash
awk -F'|' '/status=200/ {print $0}' "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/server_stdout.log" | grep -E "latency=[3-9][0-9]{3}ms"
```

## Routine Node Health Telemetry

Run this quick operational check during weekly reviews to get an overview of engagement metrics.

```bash
echo "=== Total Request Handshakes Probed ==="
grep -c "inbound_request" "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/server_stdout.log"

echo "=== Total Settled USDC Purchases Unlocked ==="
grep -c "settled=yes" "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/server_stdout.log"

echo "=== Top 5 Most Active AI Buyer IPs ==="
grep "inbound_request" "/Users/woodhouse/Desktop/CRYPTO TOOL USDC/server_stdout.log" | awk -F'|' '{print $3}' | sort | uniq -c | sort -nr | head -n 5
```

Use this operational playbook as your standard live verification flow when validating the node from machine clients.

## Operational Reminders for Production Maintenance

While the code, layouts, and scripts are working correctly, monitor these operational vectors to maintain optimal system health:

1. Log Ingestion Volume
   - Unbuffered output (`python -u`) is intentionally enabled for real-time visibility.
   - `server_stdout.log` can grow quickly under continuous machine traffic.
   - Set up periodic log retention or rotation (for example, Linux `logrotate`) to avoid unexpected disk pressure.

2. Cluster Endpoint Health
   - Verify your configured Solana mainnet RPC URLs in `server.py` are stable and not rate-limited.
   - If RPC latency rises, on-chain verification will become slower than the expected 2-3 second settlement window.
   - Keep a fallback RPC source plan ready before peak traffic windows.

### 📦 EXECUTION RECIPE: LOGROTATE CONFIGURATION

To automatically manage the rapid accumulation of unbuffered telemetry data in `server_stdout.log`, deploy this configuration block.

1. Create a service configuration file at `/etc/logrotate.d/x402-service`:
```bash
sudo nano /etc/logrotate.d/x402-service
```

2. Populate the file with the following deterministic rotation rules:
```text
/Users/woodhouse/Desktop/CRYPTO TOOL USDC/server_stdout.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    copytruncate  # Critical: Prevents breaking Python's active unbuffered file descriptor
}
```

3. Force a manual verification pass to ensure permissions and formatting are flawless:
```bash
sudo logrotate -d /etc/logrotate.d/x402-service
```

### Why This Specific Layout is Mandatory

- `copytruncate` Enforcement: Because `server.py` is continuously streaming unbuffered outputs, moving or deleting the live log file would break the active OS file descriptor, causing the server to stop logging or write to a stale descriptor.
- `compress` Opt-In: Compressing rotated logs ensures your 7-day historical trail uses minimal storage and keeps runtime host disk usage stable.

## Distribution Listing Playbook: Machine-to-Machine Discovery

Since this vending machine is optimized for autonomous clients, use these copy-paste assets to list it across AI and Solana discovery ecosystems.

### 1) Solana Agent Kit (SAK) Plugin Action

Create `src/actions/x402CleanAction.ts` with the following template:

```ts
import { Action } from "../types";
import { SolanaAgentKit } from "../agent";

export const x402CleanAction: Action = {
  name: "X402_TEXT_CLEANUP",
  description: "Collapses noisy whitespace and normalizes messy text using a pay-per-call Solana x402 USDC tollbooth node.",
  args: {
    text: { type: "string", description: "The raw text string that needs cleanup and formatting normalization." }
  },
  execute: async (agent: SolanaAgentKit, args: any) => {
    const targetUrl = "https://x402digitalvendingmachine.store/v1/clean";

    // 1. Send the initial unauthenticated probe to retrieve the 402 challenge code
    const initialResponse = await fetch(targetUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: args.text })
    });

    if (initialResponse.status !== 402) {
      throw new Error("Target endpoint failed to issue a standard x402 protocol gateway challenge.");
    }

    // 2. Parse the base64 payment block issued by your server
    const paymentRequiredHeader = initialResponse.headers.get("PAYMENT-REQUIRED");
    if (!paymentRequiredHeader) throw new Error("Missing required x402 payment header blueprint.");

    const challengeData = JSON.parse(Buffer.from(paymentRequiredHeader, "base64").toString());

    // 3. Execute the native on-chain USDC transfer of 0.002 units using SAK's internal wallet primitives
    const recipientWallet = "E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD";
    const usdcMint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    console.log(`Settling x402 invoice: Transferring ${challengeData.amount} USDC to node ledger...`);
    const transactionSignature = await agent.transferTokens(recipientWallet, challengeData.amount, usdcMint);

    // 4. Resubmit the request carrying the live signature proof to retrieve your server output
    const verifiedResponse = await fetch(targetUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "PAYMENT-SIGNATURE": transactionSignature
      },
      body: JSON.stringify({ text: args.text })
    });

    return await verifiedResponse.json();
  }
};
```

### 2) Solana AI Agent Registry Manifest

Use this schema package (submit through the active Solana Agent Registry workflow):

```json
{
  "name": "x402 Digital Vending Machine",
  "owner": "E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD",
  "endpoint": "https://x402digitalvendingmachine.store",
  "capabilities": ["TEXT_CLEANUP", "WHITESPACE_NORMALIZATION"],
  "protocols": {
    "x402": {
      "version": "2.0",
      "manifest_url": "https://x402digitalvendingmachine.store/.well-known/x402.json",
      "llms_roadmap": "https://x402digitalvendingmachine.store/llms.txt"
    }
  },
  "pricing": {
    "currency": "USDC",
    "amount_per_call": 0.002,
    "mint_address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  }
}
```

### 3) Moltweet / Public Announcement Copy

Use this announcement text when broadcasting your marketplace listing:

```text
🚨 LIVE COMMERCE NODE UPDATE: FULLY OPERATIONAL // PROTOCOL: x402 v2 🚨

I have successfully launched an autonomous, pay-per-call text normalization utility that is now fully operational on Solana Mainnet.
If you previously saw connection or proof-verification issues, I’m sorry — these have been fixed.
Please try again now; the service is working end-to-end.
No corporate accounts, no subscription lock-ins, and zero API registration keys required.

🤖 Target Node: x402 Digital Vending Machine
🛒 SKU Code: CLEAN-001 (Microservice)
💸 Flat Price: 0.002 USDC per execution call
🎯 Recipient Ledger Wallet: E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD
🌐 Public Gateway: https://x402digitalvendingmachine.store

Use this single website link for discovery, API access, and paid text-cleanup transactions.

Stop wasting compute allocations passing messy text strings to heavy downstream LLM contexts. Integrate our lightning-fast, zero-state tollbooth cleanup directly into your toolboxes today! #SolanaAgents #x402Standard #AgenticCommerce
```

### 4) Directory Listing Key Fields

Keep these reusable keys handy for alternate directories and marketplaces:

- Business / Listing Title: x402 Digital Vending Machine
- Primary URL: https://x402digitalvendingmachine.store
- Category Tagging: AI Infrastructure / Web3 Developer Tools / Autonomous Machine Commerce
- Short Pitch Statement: An autonomous, token-gated microservice node providing immediate, structured text cleanup for AI agents using native x402 v2 protocol payment challenges.
- Long Description Content:
  - The x402 Digital Vending Machine is a high-utility text normalization utility operating natively on the Solana blockchain. Built specifically for machine-to-machine interactions, it processes incoming data inputs without forcing programmatic clients through human-centric checkout routines, corporate API keys, or subscription account requirements. It uses a flat 0.002 USDC per execution structure, and includes unbuffered telemetry plus real-time payment/auth dashboards.
