import base64
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from flask_cors import CORS
from solana.rpc.api import Client

try:
    from solders.pubkey import Pubkey as PublicKey  # Compatibility for newer solders-backed stacks
    from solders.signature import Signature
except Exception:  # pragma: no cover
    try:
        from solana.publickey import PublicKey
        from solana.transaction import Signature  # type: ignore
    except Exception:  # pragma: no cover
        PublicKey = None
        Signature = None

import base58


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "x402-dashboard-secret-change-me")
CORS(app, resources={r"/v1/*": {"origins": "*"}})

# --- CANONICAL X402 PROTOCOL STATE ---
TARGET_RECIPIENT = "E2PxHWFSwzt6a3osZRQeT16tsb7BPLfXEMuDfjnZuhFD"
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
EXPECTED_AMOUNT_ATOMIC = 2000  # 0.002 USDC (USDC has 6 decimals on Solana)

RECEIVER_WALLET = TARGET_RECIPIENT
SERVICE_PRICE_USDC = 0.002
SERVICE_PRICE_ATOMIC = EXPECTED_AMOUNT_ATOMIC
SERVICE_PRICE_CONTRACT = USDC_MINT
SUPPORTED_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

DB_FILE = os.getenv("X402_DB_FILE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "payment-events.db"))
SOLANA_RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")

DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "").strip()
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "").strip()

solana_client = Client(SOLANA_RPC_URL)


def init_database():
    os.makedirs(os.path.dirname(os.path.abspath(DB_FILE)), exist_ok=True)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS payment_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seen_at TEXT NOT NULL,
                status TEXT NOT NULL,
                sender_address TEXT,
                recipient_address TEXT,
                amount_paid REAL NOT NULL DEFAULT 0,
                tx_hash TEXT,
                reason TEXT
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_payment_events_seen_at ON payment_events (seen_at DESC)"
        )
        conn.commit()


def _dashboard_auth_required():
    return bool(DASHBOARD_USERNAME and DASHBOARD_PASSWORD)


def _has_dashboard_session():
    if not _dashboard_auth_required():
        return True
    return session.get("dashboard_authenticated") is True


def _require_dashboard_access(json_fallback=False):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if _has_dashboard_session():
                return fn(*args, **kwargs)
            if json_fallback:
                return jsonify({"error": "authentication_required"}), 401
            return render_template("login.html")

        return wrapped

    return decorator


def _utc_timestamp():
    return datetime.now(timezone.utc).isoformat()


def _utc_now():
    return datetime.now(timezone.utc)


def _parse_event_time(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    if "+00:00" not in text and "-" not in text[-6:] and "+" not in text[-6:]:
        try:
            return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _set_recorded_event(status, sender_address=None, tx_hash=None, amount_paid=0.0, reason=None):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            "INSERT INTO payment_events (seen_at, status, sender_address, recipient_address, amount_paid, tx_hash, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                _utc_timestamp(),
                status,
                (sender_address or "").strip() or None,
                TARGET_RECIPIENT,
                float(amount_paid),
                (tx_hash or "").strip() or None,
                reason,
            ),
        )
        conn.commit()


def _event_exists(tx_hash):
    if not tx_hash:
        return False
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            "SELECT 1 FROM payment_events WHERE tx_hash = ? AND status = 'VERIFIED + DELIVERED' LIMIT 1",
            (tx_hash,),
        ).fetchone()
        return row is not None


def _fetch_payment_rows(limit=30):
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT seen_at, status, sender_address, recipient_address, amount_paid, tx_hash, reason"
            " FROM payment_events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def _fetch_verified_events():
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT seen_at, status, amount_paid, sender_address, tx_hash, reason"
            " FROM payment_events"
            " WHERE status = 'VERIFIED + DELIVERED'"
            " ORDER BY seen_at ASC"
        ).fetchall()


def _build_kpis():
    now = _utc_now()
    window_start_24h = now - timedelta(hours=24)
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.execute(
            "SELECT\n"
            "  COALESCE(SUM(amount_paid), 0) AS lifetime_revenue,\n"
            "  COALESCE(SUM(CASE WHEN status = 'VERIFIED + DELIVERED' THEN 1 ELSE 0 END), 0) AS verified_calls\n"
            " FROM payment_events"
        )
        lifetime, verified_calls = cur.fetchone()

        cur = conn.execute(
            "SELECT\n"
            "  COALESCE(SUM(amount_paid), 0) AS revenue_24h,\n"
            "  COALESCE(COUNT(*), 0) AS calls_24h\n"
            " FROM payment_events\n"
            " WHERE status = 'VERIFIED + DELIVERED' AND seen_at >= ?",
            (window_start_24h.isoformat(),),
        )
        revenue_24h, calls_24h = cur.fetchone()

        total_events = conn.execute("SELECT COUNT(*) FROM payment_events").fetchone()[0]

    return {
        "total_revenue": round(float(lifetime or 0.0), 6),
        "verified_calls": int(verified_calls or 0),
        "volume_24h": round(float(revenue_24h or 0.0), 6),
        "delivered_calls": int(calls_24h or 0),
        "total_events": int(total_events or 0),
    }


def _extract_signature_from_header(raw):
    if raw is None:
        return "", "No payment signature headers detected in request context."
    if not isinstance(raw, str):
        return "", "PAYMENT-SIGNATURE value is not a string."

    candidate = raw.strip()
    if not candidate:
        return "", "Payment signature header was empty."

    parsed = _safe_parse_signature_payload(candidate)
    if parsed:
        tx_hash = (
            parsed.get("tx_hash")
            or parsed.get("signature")
            or parsed.get("transaction")
            or parsed.get("tx")
        )

        if tx_hash is None and isinstance(parsed.get("payload"), dict):
            payload = parsed.get("payload")
            tx_hash = (
                payload.get("transaction")
                or payload.get("tx_hash")
                or payload.get("signature")
                or payload.get("tx")
            )

        if isinstance(tx_hash, str):
            tx_hash = tx_hash.strip().strip('"').strip("'")
            if tx_hash:
                return tx_hash, None

    return candidate, None


def _normalize_authorization_signature(header_value):
    if not isinstance(header_value, str):
        return []

    trimmed = header_value.strip()
    if not trimmed:
        return []

    candidates = [trimmed]
    if trimmed.lower().startswith("bearer "):
        candidates.append(trimmed[7:].strip())

    return [candidate for candidate in candidates if candidate]


def _safe_parse_signature_payload(value):
    if not isinstance(value, str):
        return None

    candidate = value.strip()
    try:
        payload = json.loads(candidate)
        if isinstance(payload, dict):
            return payload
    except Exception:
        pass

    try:
        padded = candidate + ("=" * (-len(candidate) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        payload = json.loads(decoded)
        if isinstance(payload, dict):
            return payload
    except Exception:
        return None

    return None


def _rpc_result(response):
    if response is None:
        return None
    if isinstance(response, dict):
        return response.get("result", response)
    return getattr(response, "value", None)


def _normalize_proof_reference(raw_value):
    if raw_value is None:
        return ""

    if not isinstance(raw_value, str):
        return ""

    return raw_value.strip().strip('"').strip("'")


def _classify_payment_proof(cleaned):
    if not cleaned:
        return "invalid"
    if len(cleaned) == 88:
        return "tx_signature"
    if len(cleaned) == 44:
        return "wallet"
    return "invalid"


def _extract_sender_from_tx(tx):
    tx_message = (tx.get("transaction") or {}).get("message") or {}
    account_keys = tx_message.get("accountKeys") or []

    if isinstance(account_keys, list):
        for key in account_keys:
            if isinstance(key, dict) and key.get("signer"):
                return key.get("pubkey")
        if account_keys:
            first = account_keys[0]
            if isinstance(first, str):
                return first
            if isinstance(first, dict):
                return first.get("pubkey")
    return None


def _coerce_pubkey(value):
    if PublicKey is None:
        return None
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if hasattr(PublicKey, "from_string"):
            return PublicKey.from_string(text)
    except Exception:
        pass
    try:
        return PublicKey(text)
    except Exception:
        return None


def _extract_usdc_delta_to_recipient(tx):
    meta = tx.get("meta", {}) if isinstance(tx, dict) else {}
    pre_token_balances = meta.get("preTokenBalances") or []
    post_token_balances = meta.get("postTokenBalances") or []

    recipient_received_atomic = 0
    for post in post_token_balances:
        if post.get("mint") != USDC_MINT:
            continue

        owner = post.get("owner")
        if owner != TARGET_RECIPIENT:
            continue

        account_index = post.get("accountIndex")
        post_amount = int((post.get("uiTokenAmount") or {}).get("amount", 0) or 0)
        pre_amount = 0

        for pre in pre_token_balances:
            if pre.get("accountIndex") == account_index:
                pre_amount = int((pre.get("uiTokenAmount") or {}).get("amount", 0) or 0)
                break

        delta = post_amount - pre_amount
        if delta > 0:
            recipient_received_atomic += delta

    return recipient_received_atomic


def _decode_signature_for_rpc(signature_candidate):
    if Signature is not None:
        try:
            return Signature.from_string(signature_candidate)
        except Exception:
            return None
    return signature_candidate


def _verify_signature_payment(tx_hash_str):
    try:
        try:
            candidate_signature = _decode_signature_for_rpc(tx_hash_str)
            tx_data = _rpc_result(
                solana_client.get_transaction(
                    candidate_signature,
                    encoding="jsonParsed",
                    commitment="confirmed",
                )
            )
        except Exception as e:
            return False, f"Transaction signature format is invalid: {e}", None

        if not tx_data:
            return False, "Transaction signature not found on-chain", None

        tx = tx_data
        meta = tx.get("meta", {}) if isinstance(tx, dict) else {}
        if meta.get("err") is not None:
            return False, "Transaction failed on-chain", None

        try:
            raw_sig = base58.b58decode(tx_hash_str)
            if len(raw_sig) != 64:
                return False, "Transaction signature format is invalid: string decoded to wrong size for signature", None
        except Exception:
            return False, "Transaction signature format is invalid: failed to decode string to signature", None

        sender_address = _extract_sender_from_tx(tx)
        recipient_received_atomic = _extract_usdc_delta_to_recipient(tx)

        if recipient_received_atomic == EXPECTED_AMOUNT_ATOMIC:
            return True, "Payment successfully settled on-chain.", {
                "sender": sender_address,
                "recipient": TARGET_RECIPIENT,
                "tx_hash": tx_hash_str,
                "amount_atomic": recipient_received_atomic,
                "amount": recipient_received_atomic / 1_000_000,
                "network": SUPPORTED_NETWORK,
            }

        received_whole = recipient_received_atomic / 1_000_000
        return (
            False,
            (
                f"Settlement mismatch: expected exactly {SERVICE_PRICE_USDC} USDC "
                f"for {TARGET_RECIPIENT}, detected {received_whole}"
            ),
            None,
        )

    except Exception as e:
        return False, f"Solana RPC Lookup Failure: {str(e)}", None


def _verify_wallet_payment(wallet_str):
    proof = _normalize_proof_reference(wallet_str)
    if len(proof) != 44:
        return False, "Wallet address format is invalid", None

    recipient_pubkey = _coerce_pubkey(TARGET_RECIPIENT)
    if recipient_pubkey is None:
        return False, "Wallet address format is invalid for recipient account.", None

    try:
        signatures_response = _rpc_result(
            solana_client.get_signatures_for_address(
                recipient_pubkey,
                limit=50,
            )
        )
    except Exception as e:
        return False, f"Solana RPC Lookup Failure: {str(e)}", None

    if not signatures_response:
        return False, "No transaction history found for the recipient account.", None

    cutoff_time = _utc_now() - timedelta(minutes=10)

    for item in signatures_response:
        if not isinstance(item, dict):
            continue

        signature = item.get("signature")
        if not signature:
            continue

        block_time = item.get("blockTime")
        if block_time is None:
            continue

        try:
            tx_seen = datetime.fromtimestamp(int(block_time), tz=timezone.utc)
        except Exception:
            continue

        if tx_seen < cutoff_time:
            break

        try:
            tx_data = _rpc_result(
                solana_client.get_transaction(
                    signature,
                    encoding="jsonParsed",
                    commitment="confirmed",
                )
            )
        except Exception as e:
            continue

        if not tx_data:
            continue

        tx = tx_data
        meta = tx.get("meta", {}) if isinstance(tx, dict) else {}
        if meta.get("err") is not None:
            continue

        sender_address = _extract_sender_from_tx(tx)
        if not sender_address or sender_address != proof:
            continue

        recipient_received_atomic = _extract_usdc_delta_to_recipient(tx)
        if recipient_received_atomic != EXPECTED_AMOUNT_ATOMIC:
            continue

        return True, "Payment successfully settled on-chain.", {
            "sender": sender_address,
            "recipient": TARGET_RECIPIENT,
            "tx_hash": signature,
            "amount_atomic": recipient_received_atomic,
            "amount": recipient_received_atomic / 1_000_000,
            "network": SUPPORTED_NETWORK,
        }

    return False, "No matching 0.002 USDC settlement found for this wallet in the last 10 minutes.", None


def verify_solana_settlement(tx_hash_str):
    """
    Query the live Solana chain and verify exactly 0.002 USDC was delivered
    to TARGET_RECIPIENT on the configured USDC mint account.
    """
    cleaned = _normalize_proof_reference(tx_hash_str)
    if not cleaned:
        return False, "No payment proof supplied.", None

    proof_type = _classify_payment_proof(cleaned)
    if proof_type == "tx_signature":
        return _verify_signature_payment(cleaned)
    if proof_type == "wallet":
        return _verify_wallet_payment(cleaned)

    return (
        False,
        "Transaction proof format is invalid: string decoded to wrong size for signature or not valid wallet.",
        None,
    )


def generate_402_challenge():
    """Build the protocol challenge payload used by 402 responses."""
    challenge_payload = {
        "x402Version": 2,
        "accepts": [
            {
                "scheme": "exact",
                "network": SUPPORTED_NETWORK,
                "amount": str(SERVICE_PRICE_ATOMIC),
                "asset": "USDC",
                "asset_contract": USDC_MINT,
                "payTo": TARGET_RECIPIENT,
            }
        ],
        "resource": {
            "url": "/v1/clean",
            "description": "x402 Digital Vending Machine text cleanup",
            "mimeType": "application/json",
        },
        "challenge_id": os.urandom(16).hex(),
    }
    return challenge_payload


def log_x402_event(status, challenge, settled, signature, tx_hash=None, msg=None):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    log_parts = [
        f"[x402 Log] status={status} | challenge={challenge} | settled={settled} | signature={signature}"
    ]
    if tx_hash:
        log_parts.append(f"tx={tx_hash}")
    if msg:
        log_parts.append(f"msg={msg}")
    print(f"{timestamp} " + " | ".join(log_parts), flush=True)


def _log_inbound_request(path, tx_hash_present):
    signature_state = "present"
    if not tx_hash_present:
        signature_state = "absent"
    return signature_state


@app.route('/v1/clean', methods=['POST'])
def handle_text_cleanup():
    payload = request.get_json(silent=True) or {}
    raw_text = payload.get("text") or payload.get("text_to_clean") or ""

    header_candidates = []
    for key in ["PAYMENT-SIGNATURE", "PAYMENT", "X-PAYMENT"]:
        value = request.headers.get(key)
        if value:
            header_candidates.append(value)

    authorization = request.headers.get("Authorization")
    header_candidates.extend(_normalize_authorization_signature(authorization))

    tx_hash = ""
    parse_error = "No payment signature headers detected in request context."
    for candidate in header_candidates:
        parsed_hash, parsed_error = _extract_signature_from_header(candidate)
        if parsed_hash:
            tx_hash = parsed_hash
            parse_error = None
            break
        if parsed_error and "No payment signature headers detected" not in parsed_error:
            parse_error = parsed_error

    # --- STEP 1: Handshake Phase (Missing Signature) ---
    if not tx_hash:
        challenge = generate_402_challenge()
        response_body = {
            "error": "Payment Required",
            "message": "0.002 USDC payment required before data delivery.",
            "accepts": [
                {
                    "asset": "USDC",
                    "amount": f"{SERVICE_PRICE_USDC:.3f}",
                    "network": "solana",
                }
            ],
            "x402Version": 2,
        }
        encoded = base64.b64encode(json.dumps(challenge).encode("utf-8")).decode("ascii")

        _set_recorded_event("PAYMENT REQUIRED", tx_hash=None, reason=parse_error)
        log_x402_event("402", "yes", "no", "absent")
        return jsonify(response_body), 402, {
            'PAYMENT-REQUIRED': encoded,
            'WWW-Authenticate': f'x402 challenge_id="{os.urandom(8).hex()}"',
        }

    if parse_error:
        _set_recorded_event("PAYMENT REJECTED", tx_hash=tx_hash, reason=parse_error)
        log_x402_event("402", "no", "no", "invalid", msg=parse_error)
        return jsonify({
            "error": "payment_not_verified",
            "message": parse_error,
            "service_delivered": False,
        }), 402

    normalized_proof = tx_hash.strip().replace('"', '').replace("'", "")
    is_valid, validation_msg, settlement = verify_solana_settlement(normalized_proof)

    if not is_valid:
        _set_recorded_event("PAYMENT REJECTED", tx_hash=normalized_proof, reason=validation_msg)
        log_x402_event("402", "no", "no", "invalid", tx_hash=normalized_proof, msg=validation_msg)
        return jsonify({
            "error": "payment_not_verified",
            "message": validation_msg,
            "service_delivered": False,
        }), 402

    clean_tx_hash = (settlement or {}).get("tx_hash") or normalized_proof
    if clean_tx_hash and _event_exists(clean_tx_hash):
        msg = "Replay detected for existing settlement signature."
        _set_recorded_event(
            "PAYMENT REJECTED",
            tx_hash=clean_tx_hash,
            reason=msg,
        )
        log_x402_event("409", "no", "no", "replayed", tx_hash=clean_tx_hash, msg=msg)
        return jsonify({
            "error": "payment_replayed",
            "message": msg,
            "service_delivered": False,
        }), 409

    # --- STEP 3: Content Delivery Phase (Payment Confirmed) ---
    sender = (settlement or {}).get("sender") or None
    _set_recorded_event(
        "VERIFIED + DELIVERED",
        sender_address=sender,
        tx_hash=clean_tx_hash,
        amount_paid=SERVICE_PRICE_USDC,
        reason="Settlement verified on-chain",
    )

    cleaned_text = " ".join(str(raw_text).split()).strip()
    log_x402_event("200", "no", "yes", "verified", tx_hash=clean_tx_hash)

    return jsonify({
        "status": "success",
        "endpoint": "/v1/clean",
        "service_delivered": True,
        "payment": {
            "recipient": TARGET_RECIPIENT,
            "sender": sender,
            "network": SUPPORTED_NETWORK,
            "amount": str(SERVICE_PRICE_USDC),
            "asset": "USDC",
            "tx": clean_tx_hash,
        },
        "cleaned_result": cleaned_text,
    }), 200


@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "online", "rpc_connected": True}), 200


@app.route('/', methods=['GET'])
def serve_storefront():
    return render_template(
        'landing.html',
        store_price='0.002',
        store_currency='USDC',
        store_wallet=RECEIVER_WALLET,
        store_asset=USDC_MINT,
        store_network=SUPPORTED_NETWORK,
        cache_bust=int(datetime.now(timezone.utc).timestamp()),
    )


@app.route('/login', methods=['GET', 'POST'])
def serve_login():
    if _has_dashboard_session():
        return redirect(url_for("serve_dashboard"))

    if request.method == 'GET':
        return render_template("login.html")

    username = (request.form.get('username') or '').strip()
    password = (request.form.get('password') or '').strip()

    if not _dashboard_auth_required():
        session['dashboard_authenticated'] = True
        return redirect(url_for("serve_dashboard"))

    if username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD:
        session['dashboard_authenticated'] = True
        return redirect(url_for("serve_dashboard"))

    return render_template("login.html", error="Invalid owner credentials."), 401


@app.route('/logout', methods=['POST'])
def serve_logout():
    session.pop('dashboard_authenticated', None)
    return redirect(url_for("serve_login"))


@app.route('/dashboard', methods=['GET'])
def serve_dashboard():
    if not _has_dashboard_session():
        return render_template("login.html"), 200

    kpis = _build_kpis()
    rows = _fetch_payment_rows(limit=150)

    return render_template(
        'dashboard.html',
        refresh=30,
        currency="USDC",
        payee=RECEIVER_WALLET,
        payment_provider="SOLANA",
        payment_mode="x402 onchain",
        total_revenue=kpis["total_revenue"],
        volume_24h=kpis["volume_24h"],
        total_calls=kpis["verified_calls"],
        delivered_calls=kpis["delivered_calls"],
        verified_calls=kpis["verified_calls"],
        total_events=kpis["total_events"],
        rows=rows,
    )


def _parse_window_param(window_value, default_hours=24):
    if not window_value:
        return default_hours
    candidate = str(window_value).strip().lower()
    if candidate.endswith("h"):
        numeric = candidate[:-1]
        if numeric.isdigit():
            return max(1, int(numeric))
    if candidate.isdigit():
        return max(1, int(candidate))
    return default_hours


def _build_empty_timeline(start_anchor, intervals, granularity):
    buckets = {}

    if granularity == 'day':
        for i in range(intervals):
            key = (start_anchor - timedelta(days=(intervals - 1 - i))).date().isoformat()
            buckets[key] = 0.0
        return buckets

    if granularity == 'week':
        for i in range(intervals):
            key_date = (start_anchor - timedelta(weeks=(intervals - 1 - i))).date().isoformat()
            buckets[key_date] = 0.0
        return buckets

    for i in range(intervals):
        bucket = start_anchor - timedelta(hours=(intervals - 1 - i))
        buckets[bucket.isoformat(timespec='seconds')] = 0.0

    return buckets


@app.route('/v1/payment-volume', methods=['GET'])
@_require_dashboard_access(json_fallback=True)
def get_payment_volume():
    window_value = request.args.get('window', '24h')
    granularity = (request.args.get('granularity', 'hour') or 'hour').lower()

    if granularity not in {'hour', 'day', 'week'}:
        granularity = 'hour'

    hours_to_lookback = _parse_window_param(window_value, default_hours=24)
    now = _utc_now()

    if granularity == 'day':
        interval_count = max(1, (hours_to_lookback + 23) // 24)
        now_truncated = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif granularity == 'week':
        interval_count = max(1, (hours_to_lookback + (24 * 7) - 1) // (24 * 7))
        now_truncated = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        interval_count = max(1, hours_to_lookback)
        now_truncated = now.replace(minute=0, second=0, microsecond=0)

    cutoff = now - timedelta(hours=hours_to_lookback)

    timeline_buckets = _build_empty_timeline(now_truncated, interval_count, granularity)
    verified_events = _fetch_verified_events()

    for row in verified_events:
        seen_at = _parse_event_time(row.get('seen_at'))
        if not seen_at:
            continue
        if seen_at < cutoff:
            continue

        bucket_label = None

        if granularity == 'day':
            bucket_dt = seen_at.replace(hour=0, minute=0, second=0, microsecond=0)
            bucket_label = bucket_dt.date().isoformat()
        elif granularity == 'week':
            bucket_dt = (seen_at - timedelta(days=seen_at.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
            bucket_label = bucket_dt.date().isoformat()
        else:
            bucket_dt = seen_at.replace(minute=0, second=0, microsecond=0)
            bucket_label = bucket_dt.isoformat(timespec='seconds')

        if bucket_label in timeline_buckets:
            timeline_buckets[bucket_label] += float(row.get('amount_paid') or 0)

    timeline = [
        {"timestamp": ts, "volume": round(float(volume), 6)}
        for ts, volume in timeline_buckets.items()
    ]

    total_volume = round(sum(item['volume'] for item in timeline), 6)
    verified_calls = 0
    with sqlite3.connect(DB_FILE) as conn:
        verified_calls = conn.execute(
            "SELECT COUNT(*) FROM payment_events WHERE status = 'VERIFIED + DELIVERED' AND seen_at >= ?",
            (cutoff.isoformat(),),
        ).fetchone()[0]

    peak_bucket = 0.0
    if timeline_buckets:
        peak_bucket = round(max(timeline_buckets.values()), 6)

    return jsonify({
        "window": window_value,
        "granularity": granularity,
        "summary": {
            "total_volume_usdc": total_volume,
            "verified_calls": int(verified_calls),
            "peak_hourly_usdc": peak_bucket,
        },
        "timeline": timeline,
    }), 200


if __name__ == '__main__':
    init_database()

    # Print clean terminal indicators on startup (Unbuffered)
    print(f"[x402 Core] Booting Live Transactional Gateway Node...", flush=True)
    print(f"[x402 Core] Enforcing 0.002 USDC Route Locks to Wallet: {RECEIVER_WALLET}", flush=True)
    app.run(host='127.0.0.1', port=8081, debug=False)
