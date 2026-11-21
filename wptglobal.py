"""
WPT Global Tournament Scanner

Authentication flow:
  1. Guest login to api.wptglobal.com
  2. AES-ECB decrypt token, double MD5
  3. WebSocket connect to gate-sec.wptglobal.com
  4. Send RequestLogon with 20-byte header frame
  5. Parse ResponseLogon (policy-based frame parser, flag 140)
  6. Extract MTT token from mttData

Tournament fetch:
  - POST protobuf to the MTT data host's /api/mtt/tournamentList
  - The MTT data host is a ROTATING CDN domain (lzqzwzx.com -> ekoqj.com -> ...),
    separate from the stable *.wptglobal.com auth tier. WPT hands back the
    current host at WS-login time (mttData.url). We try candidate hosts in
    order (last-known-good, then login-derived, then hardcoded fallback) and
    cache whichever serves data, so a WPT host migration self-heals.
  - Parse Mtt_Tournament_List_Response protobuf
  - Convert to TournamentRow objects for the scanner pipeline
"""
import asyncio
import base64
import hashlib
import json
import logging
import struct
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urlparse

import aiohttp
import websockets

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

try:
    from .wptglobal_proto import wpt_pb2
except ImportError:
    from wptglobal_proto import wpt_pb2

logger = logging.getLogger("wpt_scanner")

# ── Constants ──────────────────────────────────────────────────────────────────

AES_KEY_STR = '@lnFi8<eIKYazt:$_;MX9T/d(gk[JW3{Upcw'[:32]
GUEST_LOGIN_URL = "https://api.wptglobal.com/api/v1/user/guestlogin"
WS_URL = "wss://gate-sec.wptglobal.com"
# The MTT data host rotates AND failover-load-balances across multiple domains.
# Confirmed from the decrypted client bundle (hot-updates.wptglobal.com →
# assets/main/index.jsc, XXTEA key c1+VldgM9JnKxMZ9): the prod `apiMtt` list is
# `["mttapi.lzqzwzx.com", "mttapi.htsset.com"]`, with `ekoqj.com` a later dynamic
# addition. The client tries each in turn and fails over. Host lifecycle seen:
#   lzqzwzx.com (decommissioned ~2026-06-05) → ekoqj.com (decommissioned ~2026-06)
#   → htsset.com (LIVE 2026-06-10, the working failover the scanner was missing).
# MTT_LIST_PATH is stable; the host is resolved dynamically at fetch time by
# trying MTT_FALLBACK_BASES (the client's own failover list) plus any host
# derived from the WS-login mttData.url.
MTT_LIST_PATH = "/api/mtt/tournamentList"
# Client's hardcoded prod failover list, most-likely-live first (2026-06-10).
MTT_FALLBACK_BASES = [
    "https://mttapi.htsset.com",   # LIVE 2026-06-10
    "https://mttapi.lzqzwzx.com",  # dead, kept for when WPT rotates back
]
MTT_HARDCODED_BASE = MTT_FALLBACK_BASES[0]  # last-resort default = current live
MTT_LIST_URL = MTT_HARDCODED_BASE + MTT_LIST_PATH  # kept for back-compat
CLIENT_VERSION = "2.5.17"

# Frame constants
SERVER_TYPE_WPTO = 4
SERVER_ID_WPTO = 1001
MSG_ID_LOGON_REQUEST = 10000
MSG_ID_LOGON_RESPONSE = 10001

# Speed mapping
SPEED_MAP = {0: "Normal", 1: "Turbo", 2: "Hyper"}

# Status mapping
STATUS_MAP = {0: "Registering", 1: "Running", 2: "Late Registration", 3: "Ended"}

# GameMode mapping (from WPT client)
# 0 = NLH, 1 = PLO, 2 = PLO5, 3 = NLH Short Deck, etc.
GAME_MODE_MAP = {0: "NLH", 1: "PLO", 2: "PLO5", 3: "NLH SD", 4: "PLO6"}

# Token cache
_cached_mtt_token: str | None = None
_cached_mtt_url: str | None = None
_token_timestamp: float = 0
_TOKEN_TTL = 1800  # 30 minutes

# Last MTT host base (e.g. "https://mttapi.ekoqj.com") that successfully served
# a tournament list. Tried first on subsequent fetches so we stick to a working
# host across a WPT CDN rotation without re-probing every cycle.
_working_mtt_base: str | None = None

# WPT's own live host-discovery config. The desktop client GETs this S3 bucket
# (decrypted from assets/main/index.jsc: paths "/appfile/url_config" +
# "/appfile/url_config_version") to learn the CURRENT rotating MTT host list.
# Polling it makes the scanner self-heal EVERY future CDN rotation with no code
# change (history: lzqzwzx → ekoqj → htsset → jm4b/tmmfil → …).
MTT_URL_CONFIG = "https://mtt-url-config.wptglobal.com/appfile/url_config"
_config_mtt_bases: list[str] = []   # apiMtt hosts from the live url_config
_config_ts: float = 0.0
_CONFIG_TTL = 600  # refresh the live host list every 10 min


# ── Crypto helpers ─────────────────────────────────────────────────────────────

def _decrypt_token(encrypted_token: str) -> str:
    """AES-ECB decrypt then double MD5."""
    key = AES_KEY_STR.encode('utf-8')
    try:
        ciphertext = base64.b64decode(encrypted_token)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        decrypted_str = ''.join(chr(b) for b in decrypted if b != 0)
    except Exception as e:
        logger.warning(f"AES decrypt failed ({e}), using raw token")
        decrypted_str = encrypted_token

    md5_1 = hashlib.md5(decrypted_str.encode('utf-8')).hexdigest()
    md5_2 = hashlib.md5(md5_1.encode('utf-8')).hexdigest()
    return md5_2


# ── Frame builder ──────────────────────────────────────────────────────────────

def build_frame(server_type, server_id, msg_id, seq, player_id, room_id, payload_bytes):
    """Build WPT WebSocket binary frame with 20-byte header."""
    payload_len = len(payload_bytes) if payload_bytes else 0
    pack_len = 20 + payload_len
    header = struct.pack('>HHHH I I I',
        server_type,
        server_id,
        pack_len,
        msg_id,
        seq,
        player_id,
        room_id,
    )
    return header + (payload_bytes or b'')


# ── Frame parser (policy-based, flag 140) ──────────────────────────────────────

def reverse_bits(val, bits):
    """Reverse bits of a value."""
    result = 0
    for _ in range(bits):
        result = (result << 1) | (val & 1)
        val >>= 1
    return result


def swapoddeven_8bits(n):
    return ((n & 0xAA) >> 1) | ((n & 0x55) << 1)

def swapoddeven_16bits(n):
    return ((n & 0xAAAA) >> 1) | ((n & 0x5555) << 1)

def swapoddeven_32bits(n):
    return ((n & 0xAAAAAAAA) >> 1) | ((n & 0x55555555) << 1)


def get_value_by_op(op, bits, val, xor_value):
    """Reverse the encoding operation."""
    if op == 0:  # XOR
        if bits == 8:
            return (val ^ xor_value) & 0xFF
        elif bits == 16:
            return (val ^ xor_value) & 0xFFFF
        elif bits == 32:
            return (val ^ xor_value) & 0xFFFFFFFF
    elif op == 1:  # reverse bits
        return reverse_bits(val, bits)
    elif op == 2:  # swap odd/even
        if bits == 8:
            return swapoddeven_8bits(val)
        elif bits == 16:
            return swapoddeven_16bits(val)
        elif bits == 32:
            return swapoddeven_32bits(val)
    elif op == 3:  # NOT
        if bits == 8:
            return (~val) & 0xFF
        elif bits == 16:
            return (~val) & 0xFFFF
        elif bits == 32:
            return (~val) & 0xFFFFFFFF
    return val


def read_left_bits(value, total_bits, num_bits):
    """Read num_bits from the left (MSB) side of a value."""
    return (value >> (total_bits - num_bits)) & ((1 << num_bits) - 1)


def get_mid_bits(value, total_bits, start, end):
    """Read bits from start to end position."""
    shift = total_bits - end
    mask = (1 << (end - start)) - 1
    return (value >> shift) & mask


def read_right_bits(value, total_bits, num_bits):
    """Read num_bits from the right (LSB) side."""
    return value & ((1 << num_bits) - 1)


def concat_binary(high, low, low_bits):
    """Concatenate two binary numbers."""
    return (high << low_bits) | low


class ByteReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read_uint8(self):
        val = self.data[self.pos]
        self.pos += 1
        return val

    def read_uint16(self):
        val = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        return val

    def read_uint32(self):
        val = struct.unpack('>I', self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return val

    def remaining(self):
        return self.data[self.pos:]


def parse_frame(data):
    """Parse incoming WPT WebSocket frame with policy-based header decoding."""
    if len(data) < 8:
        logger.debug(f"Frame too short: {len(data)} bytes")
        return None

    reader = ByteReader(data)
    n = reader.read_uint32()
    r = reader.read_uint32()

    flag = read_left_bits(n, 32, 8)

    if flag == 122:  # 0x7A - simple format
        server_type = reader.read_uint16()
        server_id = reader.read_uint16()
        pack_len = reader.read_uint16()
        msg_id = reader.read_uint16()
        seq = reader.read_uint32()
        player_id = reader.read_uint32()
        room_id = reader.read_uint32()

    elif flag == 140:  # 0x8C - encoded format
        bit_pos = 8
        bit_width = get_mid_bits(n, 32, bit_pos, bit_pos + 4)
        bit_pos += 4

        fields = []
        ops = []
        current_val = n
        next_val = r
        total_bits = 32

        for _ in range(7):
            # Read field index (bit_width bits)
            if total_bits - bit_pos < bit_width:
                high_bits = total_bits - bit_pos
                high = read_right_bits(current_val, total_bits, high_bits)
                current_val = next_val
                remaining = bit_width - high_bits
                low = read_left_bits(current_val, total_bits, remaining)
                field_idx = concat_binary(high, low, remaining)
                bit_pos = remaining
            else:
                field_idx = get_mid_bits(current_val, total_bits, bit_pos, bit_pos + bit_width)
                bit_pos += bit_width

            # Read operation (2 bits)
            if total_bits - bit_pos < 2:
                high_bits = total_bits - bit_pos
                high = read_right_bits(current_val, total_bits, high_bits)
                current_val = next_val
                remaining = 2 - high_bits
                low = read_left_bits(current_val, total_bits, remaining)
                op = concat_binary(high, low, remaining)
                bit_pos = remaining
            else:
                op = get_mid_bits(current_val, total_bits, bit_pos, bit_pos + 2)
                bit_pos += 2

            if bit_pos >= total_bits:
                current_val = next_val
                bit_pos = 0

            fields.append(field_idx)
            ops.append(op)

        # Read skip count (3 bits from right of current value)
        skip_count = read_right_bits(current_val, total_bits, 3)
        for _ in range(skip_count):
            reader.read_uint8()

        # Read the actual field values
        result = [0] * 7
        for i in range(7):
            field_idx = fields[i]
            op = ops[i]
            if field_idx <= 3:  # u16 fields
                raw = reader.read_uint16()
                result[field_idx] = get_value_by_op(op, 16, raw, r)
            else:  # u32 fields (4, 5, 6)
                raw = reader.read_uint32()
                result[field_idx] = get_value_by_op(op, 32, raw, r)

        server_type = result[0]
        server_id = result[1]
        pack_len = result[2]
        msg_id = result[3]
        seq = result[4]
        player_id = result[5]
        room_id = result[6]
    else:
        logger.warning(f"Unknown frame flag: {flag} (0x{flag:02X})")
        return None

    payload = reader.remaining()
    logger.debug(
        f"Frame: serverType={server_type} serverId={server_id} "
        f"msgId={msg_id} payloadLen={len(payload)}"
    )
    return {
        'server_type': server_type,
        'server_id': server_id,
        'pack_len': pack_len,
        'msg_id': msg_id,
        'seq': seq,
        'player_id': player_id,
        'room_id': room_id,
        'payload': payload,
    }


# ── Authentication ─────────────────────────────────────────────────────────────

# Maintenance detection (2026-10-06): guest login 503 / Retry-After = WPT
# maintenance, not "MTT host unreachable".
WPT_MAINTENANCE = {"active": False, "since": 0.0, "last_log": 0.0}


def is_wpt_maintenance() -> bool:
    return bool(WPT_MAINTENANCE.get("active"))


async def _guest_login() -> dict | None:
    """Get guest credentials from WPT Global API."""
    headers = {
        "Content-Type": "application/json",
        "X-AppBundleID": "com.wptglobal.wptgmx",
    }
    payload = {
        "recaptcha_token": "",
        "recaptcha_siteKey": "",
        "device_uuid": str(uuid.uuid4()),
        "device_os": "windows_10",
        "device_name": "Desktop",
        "device_model": "PC",
        "location": {"latitude": 0, "longitude": 0},
        "domain_type": 0,
        "device_mac_address": "",
        "DeviceAgent": "",
        "deviceType": "windows",
        "is_emulator": 0,
        "hardware_id": str(uuid.uuid4()),
        "version": CLIENT_VERSION,
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(GUEST_LOGIN_URL, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                try:
                    _ra = resp.headers.get("Retry-After")
                    if resp.status == 503 or (resp.status >= 400 and _ra):
                        _now = time.time()
                        if not WPT_MAINTENANCE["active"]:
                            WPT_MAINTENANCE.update(active=True, since=_now, last_log=_now)
                            logger.warning(f"WPT MAINTENANCE: guest login HTTP {resp.status} "
                                           f"(retry-after {_ra}) — their side, not our host/proxy")
                        elif _now - WPT_MAINTENANCE["last_log"] >= 600:
                            WPT_MAINTENANCE["last_log"] = _now
                            logger.info(f"WPT still in maintenance (guest login HTTP {resp.status}, "
                                        f"{int((_now - WPT_MAINTENANCE['since']) // 60)} min)")
                        return None
                    # Cloudflare bot filter (2026-11-20): api.wptglobal.com started
                    # 403-ing our datacenter egress (HTML body, no JSON). Not a host
                    # rotation / "MTT host unreachable" — it's an IP-reputation block
                    # (direct + WARP both fail; needs residential egress). Classify it
                    # like maintenance so the scanner quiets (log once / 10 min) and
                    # returns [] instead of erroring every scan. Clears itself the
                    # moment guest login returns JSON again.
                    _ctype = (resp.headers.get("Content-Type") or "").lower()
                    if resp.status == 403 or "text/html" in _ctype:
                        _now = time.time()
                        if not WPT_MAINTENANCE["active"]:
                            WPT_MAINTENANCE.update(active=True, since=_now, last_log=_now)
                            logger.warning(f"WPT BLOCKED: guest login HTTP {resp.status} ({_ctype}) — "
                                           f"Cloudflare bot filter on api.wptglobal.com (datacenter egress "
                                           f"blocked, needs residential); quieting until it clears")
                        elif _now - WPT_MAINTENANCE["last_log"] >= 600:
                            WPT_MAINTENANCE["last_log"] = _now
                            logger.info(f"WPT still Cloudflare-blocked (guest login HTTP {resp.status}, "
                                        f"{int((_now - WPT_MAINTENANCE['since']) // 60)} min)")
                        return None
                except Exception as _me:
                    logger.debug(f"WPT maintenance check error: {_me}")
                data = await resp.json()
                result = data.get("data", data)
                if not result.get("token"):
                    logger.error("Guest login: no token in response")
                    return None
                logger.info(f"Guest login OK: user_id={result.get('user_id')}")
                if WPT_MAINTENANCE["active"]:
                    logger.info("WPT maintenance over — guest login OK")
                    WPT_MAINTENANCE["active"] = False
                return result
    except Exception as e:
        logger.error(f"Guest login failed: {e}")
        return None


async def _ws_get_mtt_token(login_data: dict) -> tuple[str | None, str | None]:
    """WebSocket login to get MTT token."""
    raw_token = login_data['token']
    token = _decrypt_token(raw_token)
    user_id = int(login_data['user_id'])

    # Build RequestLogon protobuf
    logon = wpt_pb2.RequestLogon()
    logon.version = CLIENT_VERSION
    logon.token = token
    logon.device_info = str(uuid.uuid4())
    logon.invitation_code = ""
    logon.client_type = 4  # OverSeas (WPTG desktop)
    logon.CurrentLanguage = "en"
    logon.os = "Windows"
    logon.os_version = "10.0"

    logon_bytes = logon.SerializeToString()

    frame = build_frame(
        server_type=SERVER_TYPE_WPTO,
        server_id=SERVER_ID_WPTO,
        msg_id=MSG_ID_LOGON_REQUEST,
        seq=0,
        player_id=user_id,
        room_id=0,
        payload_bytes=logon_bytes,
    )

    try:
        async with websockets.connect(
            WS_URL,
            additional_headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            },
            ping_interval=None,
            close_timeout=5,
        ) as ws:
            await ws.send(frame)
            logger.debug("Login frame sent, waiting for response")

            for _ in range(10):
                msg = await asyncio.wait_for(ws.recv(), timeout=10)
                if not isinstance(msg, bytes) or len(msg) < 6:
                    continue

                parsed = parse_frame(msg)
                if not parsed:
                    continue

                if parsed['msg_id'] == MSG_ID_LOGON_RESPONSE:
                    resp = wpt_pb2.ResponseLogon()
                    resp.ParseFromString(parsed['payload'])
                    # error=1 is normal for guest login (means "guest" mode)
                    # Only treat high error codes as failures
                    if resp.HasField('mttData'):
                        logger.info(f"Got MTT token (len={len(resp.mttData.token)})")
                        return resp.mttData.token, resp.mttData.url
                    else:
                        logger.warning("No mttData in ResponseLogon")
                        return None, None

    except asyncio.TimeoutError:
        logger.warning("WebSocket timeout waiting for login response")
    except websockets.exceptions.ConnectionClosed as e:
        logger.warning(f"WebSocket closed: {e}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")

    return None, None


async def _authenticate() -> str | None:
    """Full auth flow: guest login -> WebSocket -> MTT token. Returns token or None."""
    global _cached_mtt_token, _cached_mtt_url, _token_timestamp

    # Return cached token if still fresh
    if _cached_mtt_token and (time.time() - _token_timestamp) < _TOKEN_TTL:
        return _cached_mtt_token

    login_data = await _guest_login()
    if not login_data:
        return None

    mtt_token, mtt_url = await _ws_get_mtt_token(login_data)
    if mtt_token:
        _cached_mtt_token = mtt_token
        _cached_mtt_url = mtt_url
        _token_timestamp = time.time()
        return mtt_token

    return None


def _invalidate_token():
    """Force re-auth on next scan."""
    global _cached_mtt_token, _token_timestamp
    _cached_mtt_token = None
    _token_timestamp = 0


# ── MTT host resolution (rotating CDN) ──────────────────────────────────────────

def _derive_mtt_base(mtt_url: str | None) -> str | None:
    """Derive the MTT *API* base from the WS-login mttData.url.

    WPT hands back an H5 frontend URL (e.g. https://mtth5.ekoqj.com/...). The
    tournamentList API lives on the sibling `mttapi.<parent>` subdomain (the
    historical host was mttapi.lzqzwzx.com). Returns "https://mttapi.<parent>"
    or None. Assumes a 2-label parent (WPT uses .com domains).
    """
    if not mtt_url:
        return None
    try:
        host = urlparse(mtt_url if "://" in mtt_url else f"https://{mtt_url}").hostname
        if not host:
            return None
        labels = host.split(".")
        if len(labels) < 2:
            return None
        parent = ".".join(labels[-2:])
        return f"https://mttapi.{parent}"
    except Exception:
        return None


async def _refresh_mtt_url_config(force: bool = False) -> None:
    """Fetch WPT's live MTT url_config and cache its apiMtt host list.

    This is WPT's OWN host-discovery source, so it auto-heals CDN rotations
    without a code change. Cheap GET, cached for _CONFIG_TTL. On any failure we
    keep the previous cache (and the static MTT_FALLBACK_BASES still apply).
    """
    global _config_mtt_bases, _config_ts
    if not force and _config_mtt_bases and (time.time() - _config_ts) < _CONFIG_TTL:
        return
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                MTT_URL_CONFIG, timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status != 200:
                    return
                raw = await resp.text()
        cfg = json.loads(raw)
        # apiMtt is the tournamentList host list; fall back to the generic api list.
        hosts = cfg.get("apiMtt") or cfg.get("api") or []
        bases: list[str] = []
        for h in hosts:
            h = (h or "").strip().rstrip("/")
            if not h:
                continue
            bases.append(h if "://" in h else f"https://{h}")
        if bases:
            if bases != _config_mtt_bases:
                logger.info(f"WPT MTT url_config apiMtt hosts updated: {bases}")
            _config_mtt_bases = bases
            _config_ts = time.time()
    except Exception as e:
        logger.warning(f"WPT MTT url_config fetch failed: {e}")


def _candidate_mtt_bases() -> list[str]:
    """Ordered, de-duplicated list of MTT host bases to try.

    1. last-known-good host (sticky across cycles)
    2. hosts from WPT's live url_config (auto-discovered, self-healing)
    3. the static fallback list (client's hardcoded prod apiMtt hosts)
    4. host derived from the current login's mttData.url
    """
    ordered = (
        [_working_mtt_base]
        + list(_config_mtt_bases)
        + MTT_FALLBACK_BASES
        + [_derive_mtt_base(_cached_mtt_url)]
    )
    seen: set[str] = set()
    out: list[str] = []
    for b in ordered:
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    return out


# ── Tournament list fetch ──────────────────────────────────────────────────────

async def _fetch_tournament_list(mtt_token: str) -> list:
    """Fetch tournament list via protobuf API. Returns list of MttTournamentInfo.

    Tries each candidate MTT host in turn and caches the first that serves data
    so a WPT CDN host rotation self-heals without a code change.
    """
    global _working_mtt_base

    # Refresh WPT's live host list (cached); self-heals CDN rotations.
    await _refresh_mtt_url_config()

    req = wpt_pb2.Mtt_Tournament_List_Request()
    req.platForm = 0
    req.type.extend([0])
    req_bytes = req.SerializeToString()

    last_error = "no candidates"
    for base in _candidate_mtt_bases():
        url = f"{base}{MTT_LIST_PATH}?token={mtt_token}&newUI=true&lang=en"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    data=req_bytes,
                    headers={'Content-Type': 'application/x-protobuf'},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status != 200:
                        logger.warning(f"MTT API {base} returned status {resp.status}")
                        last_error = f"http {resp.status}"
                        continue
                    body = await resp.read()
                    if not body:
                        logger.warning(f"MTT API {base} returned empty body")
                        last_error = "empty body"
                        continue

                    list_resp = wpt_pb2.Mtt_Tournament_List_Response()
                    list_resp.ParseFromString(body)

                    if list_resp.ErrorCode != 0:
                        logger.warning(f"MTT API {base} error code: {list_resp.ErrorCode}")
                        # Token expiry is host-independent — stop probing, let the
                        # outer auth loop re-auth on the next attempt.
                        if list_resp.ErrorCode in (401, 403, -1):
                            _invalidate_token()
                            return []
                        last_error = f"errorcode {list_resp.ErrorCode}"
                        continue

                    # Success — remember this host for next time.
                    if _working_mtt_base != base:
                        logger.info(f"WPT MTT host now serving from {base}")
                        _working_mtt_base = base
                    logger.info(f"WPT Global: {len(list_resp.TournamentInfos)} tournaments")
                    return list(list_resp.TournamentInfos)

        except Exception as e:
            logger.warning(f"MTT API {base} request failed: {e}")
            last_error = str(e)
            # A previously-good host that now fails should not stay sticky.
            if base == _working_mtt_base:
                _working_mtt_base = None
            continue

    logger.error(f"All WPT MTT hosts failed (last error: {last_error})")
    return []


# ── Data mapping ───────────────────────────────────────────────────────────────

def _map_tournament(t) -> dict | None:
    """Map MttTournamentInfo protobuf to a TournamentRow-compatible dict.
    Returns None if tournament should be skipped (ended, private, etc.)."""
    detail = t.Detail
    if not detail:
        return None

    status_code = detail.Status
    # Skip ended tournaments
    if status_code >= 3:
        return None
    # Skip private tournaments
    if t.IsPrivate or getattr(detail, 'Private', False):
        return None

    # Name: TournamentNameI18N is JSON like {"En":"...","Tc":"..."} — extract English
    name = detail.TournamentName or "Unknown"
    i18n = detail.TournamentNameI18N
    if i18n:
        try:
            i18n_data = json.loads(i18n)
            en_name = i18n_data.get("En") or i18n_data.get("en")
            if en_name:
                name = en_name
        except (json.JSONDecodeError, AttributeError):
            pass

    # Buy-in = RegFee + SrvFee (total cost to enter)
    buy_in = (detail.RegFee or 0) + (detail.SrvFee or 0)

    # Game type
    game_mode = detail.GameMode
    game_type = GAME_MODE_MAP.get(game_mode, "NLH")

    # PKO: TournamentMode 1=HUNTER, 2=SUPER_HUNTER, 3=MYSTERY_BOUNTY
    # Mystery Bounty (mode 3) is freezeout, not PKO
    is_pko = detail.TournamentMode in (1, 2)

    # Speed
    speed = SPEED_MAP.get(detail.MttMode, "Normal")

    # Status
    status = STATUS_MAP.get(status_code, "Unknown")

    # Currency: DisplayCurrency "USD" = $, "GOLD" = ¥ (CNY)
    display_currency = detail.DisplayCurrency or "USD"
    currency = "¥" if display_currency == "GOLD" else "$"

    # Prize pool: GamePool is GTD-padded (like 888's ActualTourPrizePoolAmount).
    # The overlay basis is the MAIN-pool player contributions ONLY:
    #   main_contributions = net_buyin × players   (RegFee is the main-pool
    #   share of the buy-in; the bounty pool is a SEPARATE prize component)
    # Use max(GTD, main_contributions) as prize_pool. WPT's GamePool (GTD) and
    # the lobby "Prize Pool" both refer to the main pool only, so folding the
    # bounty pool in here inflates the pool above the GTD and zeroes out a real
    # prize-pool overlay. That bug hid the $14,700 overlay on the $110 Sunday
    # Slam Mystery Bounty (2026-06-14): bounty pool ~$22K pushed contributions
    # to $97.2K > $75K GTD → overlay read 0. It is the SAME double-count the PKO
    # branch at poker_scanner.py ~1283 already guards against; Mystery Bounty is
    # TournamentMode 3 / is_pko=False so that guard missed it. Excluding bounty
    # here at the source covers PKO + Mystery Bounty uniformly. The bounty pool
    # is still reported separately in raw_cells["bounty_pool"].
    net_buyin = detail.RegFee or 0
    bounty_pool = t.BountyPool or 0
    # msg 8225 2026-06-02: WPT exposes BOTH RegisteredCount and JoinedCount.
    # JoinedCount can be higher (includes re-entries / late joiners not yet
    # reflected in RegisteredCount). Use whichever is bigger so the lobby
    # number Darso sees lines up with our player count.
    current_entries = max(t.RegisteredCount or 0, getattr(t, "JoinedCount", 0) or 0)
    # PlayingPlayersCount = survivors still in (alive); 0/absent → treat as unknown
    # (None) rather than "zero alive". Feeds the PKO late-reg EV gate (pko_ev.py).
    players_alive = (getattr(t, "PlayingPlayersCount", 0) or 0) or None
    main_contributions = net_buyin * current_entries
    gtd = t.GamePool or 0.0  # GamePool = the GTD / guaranteed amount (main pool)
    prize_pool = max(gtd, main_contributions)

    # Start time: WillPlayStartTime is epoch milliseconds
    start_time_epoch = t.WillPlayStartTime
    time_left_sec = t.TimeLeftSec

    # Late reg: calculate remaining seconds
    # LateRegTime is epoch SECONDS when late reg ends — set for ALL tournaments
    # (even status=0 not-yet-started). Only use it for running tournaments.
    # TimeLeftSec is the authoritative countdown for status=1 tournaments.
    late_reg_seconds = -1
    late_reg_time = t.LateRegTime
    time_left_sec = t.TimeLeftSec

    if status_code == 1:
        # Running: use TimeLeftSec as primary (most accurate countdown)
        if time_left_sec and time_left_sec > 0:
            late_reg_seconds = time_left_sec
        elif late_reg_time and late_reg_time > 0:
            now_s = int(time.time())
            remaining = late_reg_time - now_s
            if remaining > 0:
                late_reg_seconds = remaining
    elif status_code == 2:
        # "Late Registration" status — but LateRegTime is often stale
        # (hours in the past). Only trust it if it's still in the future.
        if late_reg_time and late_reg_time > 0:
            now_s = int(time.time())
            remaining = late_reg_time - now_s
            if remaining > 0:
                late_reg_seconds = remaining
            # If LateRegTime is in the past, late reg is OVER — don't alert
    # status=0 (Registering): LateRegTime is the scheduled future end time,
    # not an indication of current late reg. Leave late_reg_seconds = -1.

    # Reg status string for the pipeline
    if status_code == 0:
        reg_status = "registering"
    elif status_code in (1, 2):
        reg_status = "late_registration" if late_reg_seconds > 0 else "running"
    else:
        reg_status = "unknown"

    # Satellite flag
    is_satellite = bool(detail.IsSatelliteMode)

    return {
        "name": name,
        "buy_in": buy_in,
        "currency": currency,
        "players": current_entries,
        "prize_pool": prize_pool,
        "reg_status": reg_status,
        "reg_seconds": late_reg_seconds,
        "is_pko": is_pko,
        "is_satellite": is_satellite,
        "confidence": 1.0,
        "source": "wpt_api",
        "name_quality": 1.0,
        "raw_cells": {
            "net_buyin": net_buyin,
            "rake": (detail.SrvFee or 0),
            "total_collected": main_contributions,
            "guaranteed": gtd,
            "game_type": game_type,
            "speed": speed,
            "tournament_id": str(detail.Id),
            "bounty_pool": bounty_pool,
            "players_alive": players_alive,
            "all_game_pool": t.AllGamePool or 0,
            # late_reg_end_ts (Unix seconds) lets the scheduler's
            # _fresh_reg_seconds() recompute remaining time at fire time
            # rather than displaying the stale scan-time value. Without this
            # WPT alerts could land showing 5m left when only ~100s remained
            # (msg 7833 2026-05-27). LateRegTime is the same Unix epoch
            # seconds we already use to derive reg_seconds for status 1/2;
            # passing it here re-uses the 888-style code path at poker_scanner
            # ~line 1990 (late_reg_end_ts handler).
            "late_reg_end_ts": (
                int(late_reg_time)
                if late_reg_time and late_reg_time > 0 and status_code in (1, 2)
                else None
            ),
        },
    }


def wpt_to_tournament_rows(tournaments: list) -> list:
    """Convert WPT tournament protobuf objects to TournamentRow objects."""
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from ocr_pipeline import TournamentRow

    rows = []
    for t in tournaments:
        mapped = _map_tournament(t)
        if not mapped:
            continue

        row = TournamentRow()
        row.name = mapped["name"]
        row.buy_in = mapped["buy_in"]
        row.currency = mapped["currency"]
        row.players = mapped["players"]
        row.prize_pool = mapped["prize_pool"]
        row.reg_status = mapped["reg_status"]
        row.reg_seconds = mapped["reg_seconds"]
        row.is_pko = mapped["is_pko"]
        row.is_satellite = mapped["is_satellite"]
        row.confidence = mapped["confidence"]
        row.source = mapped["source"]
        row.name_quality = mapped["name_quality"]
        row.raw_cells = mapped["raw_cells"]
        rows.append(row)

    return rows


# ── Public scan API ────────────────────────────────────────────────────────────

async def fetch_wpt_tournaments() -> list:
    """
    Full scan: authenticate (cached) and fetch tournament list.
    Returns list of MttTournamentInfo protobuf objects.
    """
    max_retries = 2
    for attempt in range(max_retries):
        mtt_token = await _authenticate()
        if not mtt_token:
            logger.warning(f"WPT auth failed (attempt {attempt + 1}/{max_retries})")
            _invalidate_token()
            if attempt < max_retries - 1:
                await asyncio.sleep(2)
            continue

        tournaments = await _fetch_tournament_list(mtt_token)
        if tournaments is not None:
            return tournaments

        # Token might be expired, invalidate and retry
        logger.warning(f"WPT tournament fetch failed (attempt {attempt + 1}/{max_retries}), re-authing")
        _invalidate_token()
        if attempt < max_retries - 1:
            await asyncio.sleep(2)

    return []


# JIT re-fetch (msg 8095 2026-06-01) — single-tournament refresh used at
# scheduled-alert fire time so the rendered player/pool/overlay numbers
# match reality within ~3s instead of the scan-cadence interval (~20-90s).
# Reuses the full-list endpoint with a short cache so a burst of alerts
# firing within seconds shares one API call.
_jit_cache: dict = {"ts": 0.0, "tournaments": []}
_JIT_TTL = 5.0  # seconds — short enough for "exact at fire", long enough to dedupe bursts


async def fetch_wpt_tournament_by_id(tid: str, timeout: float = 3.0) -> dict | None:
    """JIT refresh: return fresh mapped tournament dict for a specific ID.

    Returns the same dict shape as `_map_tournament()` (players, prize_pool,
    reg_seconds, raw_cells, etc.) so the alert fire path can directly read
    fresh values without unwrapping protobuf. Returns None when not found
    or fetch fails. 3s timeout ensures the fire path never hangs.
    """
    global _jit_cache
    now = time.time()
    tid_str = str(tid).strip()
    if not tid_str:
        return None

    # Cache hit: serve from the last full-list response if still fresh.
    if now - _jit_cache["ts"] < _JIT_TTL and _jit_cache["tournaments"]:
        for t in _jit_cache["tournaments"]:
            try:
                if str(t.Detail.Id) == tid_str:
                    return _map_tournament(t)
            except AttributeError:
                continue

    # Stale or first call — re-fetch the full list (reuses cached auth token).
    try:
        tournaments = await asyncio.wait_for(
            fetch_wpt_tournaments(),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.debug(f"WPT JIT timeout for tid {tid_str}")
        return None
    except Exception as e:
        logger.debug(f"WPT JIT refresh failed for {tid_str}: {e}")
        return None

    if not tournaments:
        return None

    _jit_cache["ts"] = now
    _jit_cache["tournaments"] = tournaments

    for t in tournaments:
        try:
            if str(t.Detail.Id) == tid_str:
                return _map_tournament(t)
        except AttributeError:
            continue
    return None


async def scan() -> list:
    """
    Main entry point for the scanner pipeline.
    Returns list of TournamentRow objects.
    """
    try:
        tournaments = await fetch_wpt_tournaments()
        if not tournaments:
            return []
        rows = wpt_to_tournament_rows(tournaments)
        logger.info(f"WPT Global scan: {len(rows)} tournament rows")
        return rows
    except Exception as e:
        logger.error(f"WPT Global scan error: {e}", exc_info=True)
        return []


# ── CLI test ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s %(message)s")
    sys.stdout.reconfigure(line_buffering=True)

    async def main():
        rows = await scan()
        print(f"\n=== WPT Global: {len(rows)} tournaments ===")
        for r in rows:
            pko = " [PKO]" if r.is_pko else ""
            sat = " [SAT]" if r.is_satellite else ""
            print(
                f"  ${r.buy_in:>7.2f} | {r.reg_status:<18} | "
                f"{r.players:>4} entries | ${r.prize_pool:>10,.2f} pool | "
                f"{r.name[:60]}{pko}{sat}"
            )

    asyncio.run(main())
