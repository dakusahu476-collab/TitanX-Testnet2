import hashlib

import json

import math

import random

import re

import sys

import time

from datetime import datetime, timezone

from pathlib import Path



from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from curl_cffi import requests

from eth_account import Account

from eth_account.messages import encode_defunct



from utils.banner import show_banner



ROOT = Path(__file__).resolve().parent



RESET  = "\033[0m"

BOLD   = "\033[1m"

RED    = "\033[91m"

GREEN  = "\033[92m"

YELLOW = "\033[93m"



MY_PROJECT = "TitanX Testnet"

BASE_URL   = "https://testnet-api.titanx.cc"

REF_CODE   = "C9009B05E7"



HEADERS_BASE = {

    "accept": "*/*",

    "accept-encoding": "identity",

    "accept-language": "en-US,en;q=0.9",

    "cache-control": "no-cache",

    "content-type": "application/json",

    "origin": "https://testnet.titanx.cc",

    "pragma": "no-cache",

    "priority": "u=1, i",

    "referer": "https://testnet.titanx.cc/",

    "sec-ch-ua": '"Firefox";v="135", "Not?A_Brand";v="24"',

    "sec-ch-ua-mobile": "?0",

    "sec-ch-ua-platform": '"Windows"',

    "sec-fetch-dest": "empty",

    "sec-fetch-mode": "cors",

    "sec-fetch-site": "same-origin",

    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",

}





def log_green(msg):

    print(f"{GREEN}{BOLD}{msg}{RESET}", flush=True)





def log_yellow(msg):

    print(f"{YELLOW}{BOLD}{msg}{RESET}", flush=True)





def log_red(msg):

    print(f"{RED}{BOLD}{msg}{RESET}", flush=True)





def pnl_figure(amount):

    return f"{pnl_color(amount)}{amount:+.2f} USDCX{RESET}{YELLOW}{BOLD}"





def clean_text(value, fallback):

    text = "" if value is None else str(value)

    for symbol in "[]|#!@$%^&*()-":

        text = text.replace(symbol, " ")

    text = " ".join(text.split())

    return text if text else fallback





def pnl_color(value):

    return GREEN if value >= 0 else RED





def clean_message(value, fallback, limit=240):

    text = "".join(ch for ch in str(value) if ch >= " ")

    text = " ".join(text.split())

    if len(text) > limit:

        text = text[: limit - 3].rstrip() + "..."

    return text if text else fallback





def mask_proxy(proxy_url):

    try:

        value = proxy_url.split("://")[-1]

        after_at = value.split("@")[-1]

        host_part = after_at.split(":")[0]

        port_part = after_at.split(":")[1] if ":" in after_at else ""

        octets = host_part.split(".")

        if len(octets) == 4:

            masked_host = f"{octets[0]}*****{octets[3]}"

        elif len(host_part) > 4:

            masked_host = f"{host_part[:2]}*****{host_part[-2:]}"

        else:

            masked_host = "***"

        suffix = f":{port_part}" if port_part else ""

        return f"http://user:pass@{masked_host}{suffix}"

    except Exception:

        return "http://user:pass@***:***"





def load_config():

    try:

        with open(ROOT / "config.json") as handle:

            return json.load(handle)

    except Exception:

        return {}





def load_private_keys():
    """Load PRIVATEKEY or numbered PRIVATEKEY_1, PRIVATEKEY_2, ... from .env."""
    try:
        lines = (ROOT / ".env").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    values = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip().strip('"').strip("'")
        if name == "PRIVATEKEY" or re.fullmatch(r"PRIVATEKEY_\d+", name):
            if re.fullmatch(r"(0x)?[0-9a-fA-F]{64}", value):
                values[name] = value if value.startswith("0x") else "0x" + value
    numbered = sorted(
        ((int(name.split("_", 1)[1]), value) for name, value in values.items()
         if name.startswith("PRIVATEKEY_")),
        key=lambda item: item[0],
    )
    if numbered:
        return [value for _, value in numbered]
    return [values["PRIVATEKEY"]] if "PRIVATEKEY" in values else []


def load_proxies():

    try:

        return [l.strip() for l in open(ROOT / "proxy.txt").readlines() if l.strip()]

    except Exception:

        return []





def get_proxy(proxies, idx):

    if not proxies:

        return None

    return proxies[idx % len(proxies)]





def kv(key, value):

    return f"{key}:".ljust(14) + str(value)





def iso_ts(ms):

    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)

    base = dt.strftime("%Y-%m-%dT%H:%M:%S")

    frac = f"{ms % 1000:03d}".rstrip("0")

    return f"{base}.{frac}Z" if frac else f"{base}Z"





def decimal(value):

    text = str(value).strip()

    match = re.fullmatch(r"(-?)(\d*)(?:\.(\d*))?", text)

    if not match or (match.group(2) == "" and not match.group(3)):

        raise ValueError(f"invalid decimal {value}")

    sign, whole, frac = match.group(1), match.group(2), match.group(3) or ""

    if len(frac) > 10:

        raise ValueError(f"decimal {value} has more than 10 fractional digits")

    whole = re.sub(r"^0+(?=\d)", "", whole) or "0"

    frac = frac.ljust(10, "0")

    if whole == "0" and re.fullmatch(r"0*", frac):

        sign = ""

    return f"{sign}{whole}.{frac}"





def size_str(value):

    text = f"{float(value):.8f}".rstrip("0")

    return text[:-1] if text.endswith(".") else text





def canon_query(query):

    if not query:

        return ""

    text = query[1:] if query.startswith("?") else query

    if not text:

        return ""

    segments = [s for s in text.split("&") if s]

    if not segments:

        return ""

    return "&".join(sorted(segments, key=lambda s: s.split("=")[0].encode()))





def body_hash(body):

    if body is None or len(body) == 0:

        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    return hashlib.sha256(body.encode()).hexdigest()





class TitanError(Exception):

    def __init__(self, status, code, payload=None, message="", request_id=""):

        super().__init__(f"HTTP {status} {code}".strip())

        self.status = status

        self.code = code

        self.payload = payload

        self.message = message

        self.request_id = request_id



    def detail(self):

        code = str(self.code or self.status)

        if self.message:

            return f"{code}: {self.message}"

        return code





def parse_response(response):

    try:

        payload = response.json()

    except Exception:

        payload = None

    if response.status_code >= 400:

        code = ""

        message = ""

        request_id = ""

        if isinstance(payload, dict):

            error = payload.get("error")

            if isinstance(error, dict):

                code = error.get("code") or ""

                message = error.get("message") or ""

            if not code:

                code = payload.get("code") or ""

            if not message:

                message = payload.get("message") or ""

            request_id = payload.get("requestId") or payload.get("request_id") or ""

        if not message and payload is None:
            message = (getattr(response, "text", "") or "")[:1000]
        raise TitanError(response.status_code, str(code), payload, str(message), str(request_id))

    return payload if payload is not None else {}





def unsigned_call(method, path, body=None, query="", proxy=None, timeout=30):

    text = json.dumps(body, separators=(",", ":")) if body is not None else None

    proxies = {"http": proxy, "https": proxy} if proxy else None

    response = requests.request(

        method,

        f"{BASE_URL}{path}{query}",

        data=text,

        headers=HEADERS_BASE,

        proxies=proxies,

        timeout=timeout,

        impersonate="firefox135",

    )

    return parse_response(response)





class Session:

    def __init__(self, session_id, signer_key, proxy):

        self.session_id = session_id

        self.key = signer_key

        self.proxy = proxy

        self.nonces = {}



    def nonce(self, lane):

        value = max(self.nonces.get(lane, 0) + 1, int(time.time() * 1000))

        self.nonces[lane] = value

        return value



    def request_headers(self, method, path, query, body):

        nonce = self.nonce("request")

        ts = iso_ts(int(time.time() * 1000))

        message = "\n".join([

            "Daml-Perp-Request v=2",

            "aud: rest",

            f"origin: {BASE_URL}",

            f"session: {self.session_id}",

            "conn: ",

            f"method: {method}",

            f"path: {path}",

            f"query: {canon_query(query)}",

            f"body: {body_hash(body)}",

            f"ts: {ts}",

            f"nonce: {nonce}",

            "expires: ",

        ])

        return {

            "X-Session-Id": self.session_id,

            "X-Request-Ts": ts,

            "X-Request-Nonce": str(nonce),

            "X-Request-Sig": self.key.sign(message.encode()).hex(),

        }



    def call(self, method, path, body=None, query="", timeout=30):

        text = json.dumps(body, separators=(",", ":")) if body is not None else None

        headers = dict(HEADERS_BASE)

        headers.update(self.request_headers(method, path, query, text))

        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None

        response = requests.request(

            method,

            f"{BASE_URL}{path}{query}",

            data=text,

            headers=headers,

            proxies=proxies,

            timeout=timeout,

            impersonate="firefox135",

        )

        return parse_response(response)





def signed_call(session, method, path, canon, payload, query=""):

    body = json.dumps(payload, separators=(",", ":"))

    headers = dict(HEADERS_BASE)

    headers.update(session.request_headers(method, path, query, body))

    headers["X-Session-Sig"] = session.key.sign(canon.encode()).hex()

    proxies = {"http": session.proxy, "https": session.proxy} if session.proxy else None

    response = requests.request(

        method,

        f"{BASE_URL}{path}{query}",

        data=body,

        headers=headers,

        proxies=proxies,

        timeout=30,

        impersonate="firefox135",

    )

    return parse_response(response)






def authorize(wallet_key, session_key, proxy):
    public_hex = session_key.public_key().public_bytes_raw().hex()
    account = Account.from_key(wallet_key)

    expiry_ms = int(time.time() * 1000) + 7 * 24 * 60 * 60 * 1000
    user_nonce = int(time.time() * 1000) * 1_000_000

    message = "\n".join([
        "Daml-Perp-Session-Auth v=2",
        kv("scheme", "evm"),
        kv("credential", account.address.lower()),
        kv("sessionPubKey", public_hex),
        kv("expiry", iso_ts(expiry_ms)),
        kv("maxNotional", decimal(1_000_000)),
        kv("userNonce", str(user_nonce)),
        kv("label", ""),
        kv("scope", "full"),
    ])

    signed = Account.sign_message(
        encode_defunct(text=message),
        private_key=wallet_key,
    )

    # Preserve the signature's 0x prefix for inspection.
    signature = signed.signature.hex()

    return unsigned_call(
        "POST",
        "/v1/auth/session",
        {
            "scheme": "evm",
            "message": message,
            "signature": signature,
        },
        proxy=proxy,
    )






def fetch_markets(proxy):

    return unsigned_call("GET", "/v1/markets", proxy=proxy)





def fetch_mark(session, market):

    return session.call("GET", f"/v1/markets/{market}/mark")





def fetch_balance(session):

    return session.call("GET", "/v1/me/balance")





def fetch_positions(session):

    data = session.call("GET", "/v1/me/positions", query="?status=open&limit=50")

    return data.get("items") or []





def set_leverage(session, market, leverage):

    nonce = session.nonce("leverage")

    ts = iso_ts(int(time.time() * 1000))

    canon = "\n".join([

        "Daml-Perp-Leverage v=1",

        kv("sessionId", session.session_id),

        kv("market", market),

        kv("leverage", leverage),

        kv("nonce", str(nonce)),

        kv("ts", ts),

    ])

    return signed_call(

        session,

        "PUT",

        f"/v1/me/leverage/{market}",

        canon,

        {"market": market, "leverage": leverage, "nonce": nonce, "ts": ts},

    )





def slip_price(price, side, slippage_pct, sz_decimals):

    if price <= 0 or slippage_pct < 0:

        return None

    target = price * (1 + slippage_pct) if side == "buy" else price * (1 - slippage_pct)

    if target <= 0:

        return None

    cap = max(0, 6 - sz_decimals)

    digits = 4 - math.floor(math.log10(target))

    step = max(0, min(cap, digits))

    factor = 10 ** step

    target = math.floor(target * factor) / factor if side == "buy" else math.ceil(target * factor) / factor

    return target if target > 0 else None





def tick_step(price):

    if price <= 0:

        return 0.1

    digits = math.floor(math.log10(price)) + 1

    return max(10 ** (digits - 5), 0.1)





def grid_trigger(level, price, mark, guard, want_above):

    step = tick_step(max(price, mark))

    if want_above:

        target = max(level, max(price, mark) + guard)

        return round(math.ceil(target / step) * step, 10)

    target = min(level, min(price, mark) - guard)

    return round(math.floor(target / step) * step, 10)





def place_order(session, market, side, size, price, tif, reduce_only, take_profit, stop_loss):

    nonce = session.nonce("order")

    ts = iso_ts(int(time.time() * 1000))

    tp_trigger = (take_profit or {}).get("trigger") or 0

    sl_trigger = (stop_loss or {}).get("trigger") or 0

    canon = "\n".join([

        "Daml-Perp-Order v=1",

        kv("sessionId", session.session_id),

        kv("market", market),

        kv("side", side),

        kv("type", "limit"),

        kv("size", decimal(size)),

        kv("price", decimal(price)),

        kv("tif", tif),

        kv("reduceOnly", "true" if reduce_only else "false"),

        kv("tpTrigger", decimal(tp_trigger)),

        kv("tpLimit", decimal(0)),

        kv("tpSize", decimal(0)),

        kv("slTrigger", decimal(sl_trigger)),

        kv("slLimit", decimal(0)),

        kv("slSize", decimal(0)),

        kv("clientOrderId", ""),

        kv("nonce", str(nonce)),

        kv("ts", ts),

    ])

    payload = {

        "market": market,

        "side": side,

        "type": "limit",

        "size": size_str(size),

        "price": size_str(price),

        "tif": tif,

    }

    if reduce_only:

        payload["reduceOnly"] = True

    if take_profit:

        payload["tp"] = {"trigger": size_str(tp_trigger)}

    if stop_loss:

        payload["sl"] = {"trigger": size_str(sl_trigger)}

    payload["nonce"] = nonce

    payload["ts"] = ts

    return signed_call(session, "POST", "/v1/orders", canon, payload)





def fetch_sizing(session, market, price):

    return session.call("GET", "/v1/me/sizing", query=f"?market={market}&price={size_str(price)}")





def claim_faucet(session):

    try:

        result = session.call("POST", "/v1/me/faucet", body={})

    except TitanError as error:

        code = str(error.code)

        if code in ("conflict", "already_funded", "alreadyFunded") or error.status == 409:

            log_yellow("Faucet was already claimed for this wallet")

        else:

            log_yellow("Faucet is not open for this wallet yet")

        return

    amount = result.get("amount") or result.get("credited") or result.get("credit")

    if amount:

        log_green(f"Faucet credited {clean_text(amount, 0)} USDCX")

    else:

        log_green("Faucet claim accepted, deposit queued")





def position_name(position, fallback=""):

    for field in ("symbol", "market"):

        value = position.get(field)

        if value:

            return str(value)

    return fallback





def open_positions(session, market=""):

    found = []

    for position in fetch_positions(session):

        if float(position.get("size") or 0) == 0:

            continue

        name = position_name(position)

        if not market or not name or name == market:

            found.append(position)

    return found





def open_orders(session, market):

    data = session.call("GET", "/v1/me/orders", query=f"?market={market}&limit=50")

    return data.get("items") or []





def armed_triggers(session, market):

    data = session.call("GET", "/v1/me/triggers", query="?status=armed&limit=100")

    found = []

    for trigger in data.get("items") or []:

        name = trigger.get("market") or trigger.get("symbol") or ""

        if not name or name == market:

            found.append(trigger)

    return found





def resting_count(session, market):

    try:

        return len(open_orders(session, market)) + len(armed_triggers(session, market))

    except TitanError:

        return 0





def wait_flat(session, market):

    width = 0

    while True:

        held = open_positions(session, market)

        if not held:

            if width:

                print("\r" + " " * width + "\r", end="", flush=True)

            return

        live = float(held[0].get("unrealizedPnl") or 0)

        name = clean_text(position_name(held[0], market), clean_text(market, "market"))

        plain = f"Position {name} still open with {live:+.2f} USDCX unrealized"

        width = max(width, len(plain))

        print(f"\r{YELLOW}{BOLD}Position {name} still open with {pnl_figure(live)} unrealized{RESET}", end="", flush=True)

        time.sleep(5)





def await_close(session, market, width=0):

    last = None

    held_seen = False

    blind = 0

    while True:

        held = open_positions(session, market)

        if held:

            held_seen = True

            blind = 0

            last = held[0]

            live = float(last.get("unrealizedPnl") or 0)

            plain = f"PnL {live:+.2f} USDCX on {market}"

            width = max(width, len(plain))

            frame = f"PnL {pnl_figure(live)} on {market}"

            pad = " " * (width - len(plain))

            print(f"\r{YELLOW}{BOLD}{frame}{RESET}{pad}", end="", flush=True)

        elif held_seen:

            break

        elif resting_count(session, market):

            blind = 0

        elif blind >= 6:

            break

        else:

            blind += 1

        time.sleep(5)

    print("\r" + " " * width + "\r", end="", flush=True)

    return last





def run_market(session, market, info, config, pnl):

    max_lev = int(info.get("maxLeverage") or 1)

    sz_dec = int(info.get("szDecimals") or 0)

    min_notional = float(info.get("minNotional") or 0)

    position_cap = float(info.get("maxPositionNotional") or 0)



    wait_flat(session, market)



    balance = fetch_balance(session)

    before = float(balance.get("balance") or balance.get("available") or 0)

    if before <= 0:

        log_yellow(f"Empty balance on {clean_text(market, 'market')}, the entry is skipped")

        return False

    log_green(f"Balance {clean_text(f'{before:.2f}', 0)} USDCX, ready to trade")



    set_leverage(session, market, max_lev)

    log_yellow(f"Leverage on {clean_text(market, 'market')} set to {clean_text(max_lev, 1)}x")



    side = random.choice(["buy", "sell"])

    direction = 1 if side == "buy" else -1

    min_profit = float(config.get("min_profit_percent") or 0)

    min_loss = float(config.get("min_loss_percent") or 0)

    entry = None

    attempt = 0
    max_entry_attempts = max(1, int(config.get("max_entry_attempts", 5)))

    while entry is None and attempt < max_entry_attempts:

        attempt += 1

        mark = fetch_mark(session, market)

        reference = float((mark or {}).get("markPrice") or 0)

        if reference <= 0:

            log_red(f"No mark price for {clean_text(market, 'market')}, retrying the entry")

            continue

        cap_price = slip_price(reference, side, 0.0002, sz_dec)

        if not cap_price:

            log_red(f"No slippage price for {clean_text(market, 'market')}, retrying the entry")

            continue



        try:

            sizing = fetch_sizing(session, market, cap_price)

        except TitanError:

            sizing = {}

        key = "maxBuySize" if side == "buy" else "maxSellSize"

        server_size = float(sizing.get(key) or 0)

        cap_size = position_cap / cap_price if position_cap > 0 else 0

        if server_size > 0:

            size = min(server_size, cap_size) if cap_size > 0 else server_size

        else:

            size = cap_size if cap_size > 0 else (before * max_lev) / cap_price

        size = math.floor(size * (10 ** sz_dec)) / (10 ** sz_dec)

        if size <= 0 or size * reference < min_notional:

            log_yellow(f"Balance is below the smallest order size on {clean_text(market, 'market')}, retrying the entry")

            continue



        take_profit = None

        stop_loss = None

        guard = max(tick_step(reference) * 3, reference * 0.0005 * (3 ** (min(attempt, 3) - 1)))

        if min_profit > 0:

            level = slip_price(reference * (1 + direction * min_profit / 100 / max_lev), side, 0, sz_dec)

            if level:

                level = grid_trigger(level, cap_price, reference, guard, side == "buy")

            take_profit = {"trigger": size_str(level)} if level else None

        if min_loss > 0:

            level = slip_price(reference * (1 - direction * min_loss / 100 / max_lev), side, 0, sz_dec)

            if level:

                level = grid_trigger(level, cap_price, reference, guard, side == "sell")

            stop_loss = {"trigger": size_str(level)} if level else None



        try:

            order = place_order(session, market, side, size, cap_price, "ioc", False, take_profit, stop_loss)

        except TitanError as error:

            if error.status in (401, 403):

                raise error

            log_yellow(f"Entry on {clean_text(market, 'market')} was refused, retrying with room to spare")

            continue

        if order.get("ok") and order.get("fills") and not order.get("resting"):

            entry = order

            break

        if attempt % 3 == 0:

            log_red(f"Entry on {clean_text(market, 'market')} did not fill after three tries, opening a fresh entry")

        else:

            log_yellow(f"Entry on {clean_text(market, 'market')} did not fill, retrying at a fresh price")



    if entry is None:
        log_red(f"Entry skipped after {max_entry_attempts} attempts; no fill was confirmed")
        return False

    fill = 0.0

    for field in ("avgPrice", "avgFillPrice", "fillPrice", "price"):

        try:

            fill = float(entry.get(field) or 0)

        except (TypeError, ValueError):

            fill = 0.0

        if fill > 0:

            break

    shown = fill or cap_price

    tp_text = size_str(take_profit["trigger"]) if take_profit else "off"

    sl_text = size_str(stop_loss["trigger"]) if stop_loss else "off"

    log_green(f"Entry filled: {clean_text(side, 'side')} {clean_text(size_str(size), 0)} {clean_text(market, 'market')} at price {clean_text(size_str(shown), 0)}")

    log_yellow(f"Take profit at {clean_text(tp_text, 0)} and stop loss at {clean_text(sl_text, 0)}, both resting on the exchange")



    last = await_close(session, market)



    balance = fetch_balance(session)

    after = float(balance.get("balance") or balance.get("available") or 0)

    realized = after - before

    pnl["total"] += realized

    exit_price = size_str(last.get("markPrice")) if last else size_str(reference)

    log_yellow(f"Closed {clean_text(market, 'market')} at exit price {clean_text(exit_price, 0)} with realized {pnl_figure(realized)}")

    return True





def run_account(wallet_key, proxy, config, account_index=1):
    """Authorize and process one wallet with an independent session."""
    account = Account.from_key(wallet_key)
    log_green(f"Wallet {account_index}: {account.address}")
    session_key = Ed25519PrivateKey.generate()
    try:
        auth = authorize(wallet_key, session_key, proxy)
    except TitanError as error:
        log_red(f"Wallet {account_index} authorization failed: {error.detail()}")
        if error.request_id:
            log_yellow(f"Request ID: {error.request_id}")
        if error.payload is not None:
            print("Server response payload (redact sensitive data before sharing):")
            print(json.dumps(error.payload, indent=2, ensure_ascii=False)[:3000])
        return False

    session_id = auth.get("sessionId")
    if not session_id:
        log_red(f"Wallet {account_index}: authorization response has no sessionId")
        print(json.dumps(auth, indent=2, ensure_ascii=False)[:2000])
        return False

    session = Session(session_id, session_key, proxy)
    log_green(f"Wallet {account_index}: session authorized")
    if proxy:
        log_yellow(f"Proxy {mask_proxy(proxy)}")
    try:
        markets = fetch_markets(proxy)
        listing = markets.get("markets") or markets.get("items") or []
        meta = {m.get("market"): m for m in listing if isinstance(m, dict) and m.get("market")}
        wanted = [name for name, enabled in (config.get("pairs") or {}).items()
                  if enabled and name in meta]
        if not wanted:
            log_red("No enabled pair matched the markets returned by the server.")
            return False

        balance = fetch_balance(session)
        amount = balance.get("balance", balance.get("available", "unknown"))
        log_green(f"Wallet {account_index}: balance response received ({clean_text(amount, 'unknown')} USDCX)")
        if bool(config.get("dry_run", True)):
            log_yellow("DRY RUN enabled: no faucet claim, leverage change, or order was submitted.")
            return True

        if bool(config.get("claim_faucet", False)):
            claim_faucet(session)
        max_trades = max(1, int(config.get("max_trades_per_wallet", 1)))
        pnl = {"total": 0.0}
        completed = 0
        for _ in range(max_trades):
            market = random.choice(wanted)
            try:
                closed = run_market(session, market, meta[market], config, pnl)
            except TitanError as error:
                log_red(f"Wallet {account_index}: API error: {error.detail()}")
                if error.request_id:
                    log_yellow(f"Request ID: {error.request_id}")
                if error.payload is not None:
                    print(json.dumps(error.payload, indent=2, ensure_ascii=False)[:2000])
                if error.status in (400, 401, 403):
                    return False
                continue
            if closed:
                completed += 1
                log_yellow(f"Wallet {account_index}: completed {completed}/{max_trades}; realized {pnl_figure(pnl['total'])}")
        log_green(f"Wallet {account_index}: bounded run finished ({completed}/{max_trades} completed)")
        return True
    except TitanError as error:
        log_red(f"Wallet {account_index}: API error: {error.detail()}")
        if error.request_id:
            log_yellow(f"Request ID: {error.request_id}")
        if error.payload is not None:
            print(json.dumps(error.payload, indent=2, ensure_ascii=False)[:2000])
        return False
    except Exception as error:
        log_red(f"Wallet {account_index}: unexpected error: {type(error).__name__}: {error}")
        return False


def main():
    show_banner(MY_PROJECT)
    config = load_config()
    wallet_keys = load_private_keys()
    proxies = load_proxies()
    if not wallet_keys:
        log_red("No valid PRIVATEKEY or PRIVATEKEY_1..N entries found in .env.")
        log_yellow("Use dedicated testnet wallets. Never share .env or private keys.")
        return

    max_wallets = max(1, int(config.get("max_wallets", 3)))
    wallet_keys = wallet_keys[:max_wallets]
    log_yellow(f"Sequential mode: {len(wallet_keys)} wallet(s), one at a time.")
    results = []
    for index, wallet_key in enumerate(wallet_keys, start=1):
        proxy_url = get_proxy(proxies, index - 1)
        log_yellow(f"Starting wallet {index}/{len(wallet_keys)}")
        ok = run_account(wallet_key, proxy_url, config, account_index=index)
        results.append(ok)
        if not ok and bool(config.get("stop_on_wallet_error", True)):
            log_red("Stopping after an error. Inspect the response before retrying.")
            break
    passed = sum(1 for result in results if result)
    log_green(f"Run summary: {passed}/{len(results)} wallet(s) completed their checks.")


if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        print(f"\n{RED}Script stopped by user.{RESET}")

        sys.exit(0)
