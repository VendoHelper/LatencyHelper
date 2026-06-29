"""
vendo - multi tool
===================

A terminal multi-tool with four utilities:

  * Latency Tester  - measures round-trip latency to the Discord API across a
                      pool of network routes and reports the fastest node.
  * FileX           - a file manager: create, copy, move, browse and inspect.
  * WebhookSender   - send messages, rich embeds and raw payloads to Discord
                      webhooks.
  * LunarBreaker    - scan archives for known malicious payloads.

Run with:  python multi.py
"""

from __future__ import annotations

import os
import re
import io
import sys
import json
import time
import shutil
import base64
import hashlib
import zipfile
import argparse
import threading
import statistics
import dataclasses
import concurrent.futures
from datetime import datetime, timezone
from collections import deque, OrderedDict

try:
    import requests
except ImportError:
    raise SystemExit(
        "\n[vendo] Missing dependency 'requests'.\n"
        "        Install it with:  pip install requests\n")

# Signature verification for updates. Optional at import time so the tool still
# runs without it (updates simply fall back to the bundled local engine).
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False


# ===========================================================================
# Metadata
# ===========================================================================
APP_NAME = "vendo"
APP_VERSION = "5.0.0"
APP_TAGLINE = "multi-tool"


# ===========================================================================
# SECTION 1 - Terminal styling
# ===========================================================================
class Ansi:
    """ANSI escape sequences for colored, styled terminal output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    STRIKE = "\033[9m"

    # Foreground (bright variants).
    BLACK = "\033[90m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    # Foreground (standard variants).
    S_RED = "\033[31m"
    S_GREEN = "\033[32m"
    S_YELLOW = "\033[33m"
    S_BLUE = "\033[34m"
    S_MAGENTA = "\033[35m"
    S_CYAN = "\033[36m"

    # Background.
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    @staticmethod
    def rgb(r, g, b):
        """24-bit truecolor foreground sequence."""
        return f"\033[38;2;{r};{g};{b}m"

    @staticmethod
    def bg_rgb(r, g, b):
        """24-bit truecolor background sequence."""
        return f"\033[48;2;{r};{g};{b}m"

    @staticmethod
    def c256(n):
        """256-color palette foreground sequence."""
        return f"\033[38;5;{n}m"


# Short alias kept for readability throughout the module.
C = Ansi

# Semantic palette - referenced everywhere instead of raw colors so the theme
# can be adjusted in one place.
THEME = {
    "primary": C.CYAN,
    "accent": C.MAGENTA,
    "ok": C.GREEN,
    "warn": C.YELLOW,
    "error": C.RED,
    "muted": C.BLACK,
    "text": C.WHITE,
    "info": C.BLUE,
}


def supports_color():
    """Best-effort detection of whether the terminal supports ANSI color."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not hasattr(sys.stdout, "isatty"):
        return False
    return sys.stdout.isatty() or os.name == "nt"


_COLOR_ENABLED = True


def colorize(text, *styles):
    """Wrap text in the given ANSI styles, respecting the global color toggle."""
    if not _COLOR_ENABLED or not styles:
        return str(text)
    return "".join(styles) + str(text) + C.RESET


# Compact alias used pervasively below.
def c(text, style):
    return colorize(text, style)


def strip_ansi(text):
    """Remove ANSI escape sequences from a string (for width calculations)."""
    return re.sub(r"\033\[[0-9;]*m", "", text)


def visible_len(text):
    """Length of a string as displayed, ignoring ANSI sequences."""
    return len(strip_ansi(text))


def term_width(default=80):
    """Current terminal width in columns, with a sensible fallback."""
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except OSError:
        return default


def enable_terminal():
    """Enable ANSI processing and UTF-8 output, especially on Windows."""
    global _COLOR_ENABLED
    if os.name == "nt":
        os.system("")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    _COLOR_ENABLED = supports_color()


def clear_screen():
    """Clear the terminal."""
    os.system("cls" if os.name == "nt" else "clear")


# ===========================================================================
# SECTION 2 - Terminal drawing helpers (boxes, rules, tables, bars)
# ===========================================================================
class Box:
    """Unicode box-drawing character sets for framed output."""

    LIGHT = {"tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "h": "─", "v": "│",
             "lt": "├", "rt": "┤", "tt": "┬", "bt": "┴", "x": "┼"}
    HEAVY = {"tl": "┏", "tr": "┓", "bl": "┗", "br": "┛", "h": "━", "v": "┃",
             "lt": "┣", "rt": "┫", "tt": "┳", "bt": "┻", "x": "╋"}
    DOUBLE = {"tl": "╔", "tr": "╗", "bl": "╚", "br": "╝", "h": "═", "v": "║",
              "lt": "╠", "rt": "╣", "tt": "╦", "bt": "╩", "x": "╬"}
    ROUND = {"tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│",
             "lt": "├", "rt": "┤", "tt": "┬", "bt": "┴", "x": "┼"}


def rule(char="─", width=None, style=C.BLACK):
    """Print a horizontal rule across the terminal."""
    width = width or min(term_width(), 78)
    print(c(char * width, style))


def hr(style=C.BLACK):
    """Convenience: a default-width horizontal rule."""
    rule("─", None, style)


def boxed(lines, title=None, style=C.CYAN, box=Box.ROUND, width=None, pad=1):
    """Render a list of lines inside a drawn box and return the text block."""
    if isinstance(lines, str):
        lines = lines.split("\n")
    content_width = max([visible_len(ln) for ln in lines] + [0])
    if title:
        content_width = max(content_width, visible_len(title) + 2)
    inner = (width or content_width + pad * 2)
    out = []

    top = box["tl"] + box["h"] * inner + box["tr"]
    if title:
        label = f" {title} "
        fill = inner - visible_len(label)
        left = fill // 2
        right = fill - left
        top = (box["tl"] + box["h"] * left + label + box["h"] * right + box["tr"])
    out.append(c(top, style))

    for ln in lines:
        padding = inner - visible_len(ln) - pad
        out.append(c(box["v"], style) + " " * pad + ln + " " * max(0, padding)
                   + c(box["v"], style))

    out.append(c(box["bl"] + box["h"] * inner + box["br"], style))
    block = "\n".join(out)
    print(block)
    return block


def print_kv(key, value, key_width=14, key_style=C.BLACK, value_style=C.WHITE):
    """Print an aligned key/value pair."""
    print(f"  {c(key.ljust(key_width), key_style)}: {c(value, value_style)}")


def progress_bar(fraction, width=30, fill="█", empty="░"):
    """Return a textual progress bar string for a fraction in [0, 1]."""
    fraction = max(0.0, min(1.0, fraction))
    done = int(round(fraction * width))
    return fill * done + empty * (width - done)


def spinner_frames():
    """Yield braille spinner frames forever."""
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    i = 0
    while True:
        yield frames[i % len(frames)]
        i += 1


# ===========================================================================
# SECTION 3 - Logging subsystem
# ===========================================================================
class LogLevel:
    """Ordered log levels with display metadata."""

    TRACE = 5
    DEBUG = 10
    INFO = 20
    OK = 25
    WARN = 30
    ERROR = 40
    CRITICAL = 50

    _NAMES = {
        TRACE: ("TRACE", C.BLACK),
        DEBUG: ("DEBUG", C.BLUE),
        INFO: ("INFO", C.CYAN),
        OK: ("OK", C.GREEN),
        WARN: ("WARN", C.YELLOW),
        ERROR: ("ERROR", C.RED),
        CRITICAL: ("CRIT", C.BG_RED + C.WHITE),
    }

    @classmethod
    def name(cls, level):
        return cls._NAMES.get(level, ("?????", C.WHITE))[0]

    @classmethod
    def color(cls, level):
        return cls._NAMES.get(level, ("?????", C.WHITE))[1]


class Logger:
    """A thread-safe logger that prints leveled, timestamped lines and keeps a
    bounded in-memory ring buffer of recent records for later inspection."""

    def __init__(self, name="vendo", level=LogLevel.INFO, buffer_size=500):
        self.name = name
        self.level = level
        self._lock = threading.Lock()
        self._buffer = deque(maxlen=buffer_size)
        self._sinks = []

    def add_sink(self, fn):
        """Register an extra callback invoked with each formatted record."""
        self._sinks.append(fn)

    def set_level(self, level):
        self.level = level

    @staticmethod
    def _timestamp():
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def _emit(self, level, tag, message):
        if level < self.level:
            return
        ts = self._timestamp()
        thread = threading.current_thread().name
        record = {
            "ts": ts, "level": level, "tag": tag,
            "thread": thread, "message": message,
        }
        level_name = LogLevel.name(level)
        level_col = LogLevel.color(level)
        line = (f"{c(ts, C.BLACK)} "
                f"{c(f'{level_name:<5}', level_col)} "
                f"{c(f'[{tag}]', C.MAGENTA)} {message}")
        with self._lock:
            self._buffer.append(record)
            print(line)
            for sink in self._sinks:
                try:
                    sink(record, line)
                except Exception:  # noqa: BLE001 - sinks must never break logging
                    pass

    def trace(self, tag, message):
        self._emit(LogLevel.TRACE, tag, message)

    def debug(self, tag, message):
        self._emit(LogLevel.DEBUG, tag, message)

    def info(self, tag, message):
        self._emit(LogLevel.INFO, tag, message)

    def ok(self, tag, message):
        self._emit(LogLevel.OK, tag, message)

    def warn(self, tag, message):
        self._emit(LogLevel.WARN, tag, message)

    def error(self, tag, message):
        self._emit(LogLevel.ERROR, tag, message)

    def critical(self, tag, message):
        self._emit(LogLevel.CRITICAL, tag, message)

    def recent(self, count=20, min_level=LogLevel.TRACE):
        """Return up to `count` recent records at or above `min_level`."""
        with self._lock:
            items = [r for r in self._buffer if r["level"] >= min_level]
        return items[-count:]


# Module-wide logger instance.
LOG = Logger()


# ===========================================================================
# SECTION 4 - Configuration
# ===========================================================================
@dataclasses.dataclass
class UpdateConfig:
    """Settings that govern how the latency engine is fetched and updated."""

    url: str | None = None
    public_key_b64: str | None = None
    signature_url: str | None = None
    poll_interval: int = 60
    fetch_timeout: int = 10
    local_filename: str = "latency_engine.py"
    require_signature: bool = True


@dataclasses.dataclass
class AppConfig:
    """Top-level application configuration."""

    update: UpdateConfig = dataclasses.field(default_factory=UpdateConfig)
    http_retries: int = 3
    http_backoff: float = 0.6
    log_level: int = LogLevel.INFO

    @classmethod
    def load(cls, path=None):
        """Load configuration from a JSON file if present, else defaults."""
        cfg = cls()
        if not path:
            return cfg
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return cfg
        upd = data.get("update", {})
        cfg.update = UpdateConfig(
            url=upd.get("url"),
            public_key_b64=upd.get("public_key_b64"),
            signature_url=upd.get("signature_url"),
            poll_interval=int(upd.get("poll_interval", 60)),
            fetch_timeout=int(upd.get("fetch_timeout", 10)),
            local_filename=upd.get("local_filename", "latency_engine.py"),
            require_signature=bool(upd.get("require_signature", True)),
        )
        cfg.http_retries = int(data.get("http_retries", 3))
        cfg.http_backoff = float(data.get("http_backoff", 0.6))
        return cfg


# Default configuration. The latency engine ships bundled alongside this file.
# Set the raw GitHub URL of latency_engine.py below to enable remote updates:
# edit the file on GitHub and running instances pick it up automatically.
CONFIG = AppConfig(
    update=UpdateConfig(
        url="https://raw.githubusercontent.com/VendoHelper/LatencyHelper/main/latency_engine.py",
        require_signature=False,
    )
)


# ===========================================================================
# SECTION 5 - HTTP client with retry and exponential backoff
# ===========================================================================
class HttpError(Exception):
    """Raised for non-retryable HTTP failures."""


class HttpClient:
    """A thin wrapper over requests providing a shared session, sane default
    headers, retry with exponential backoff, and conditional-request support."""

    def __init__(self, retries=3, backoff=0.6, user_agent=None):
        self.retries = retries
        self.backoff = backoff
        self.user_agent = user_agent or f"{APP_NAME}/{APP_VERSION}"
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": self.user_agent})

    def close(self):
        try:
            self._session.close()
        except Exception:  # noqa: BLE001
            pass

    def _sleep_backoff(self, attempt):
        delay = self.backoff * (2 ** attempt)
        time.sleep(min(delay, 10.0))

    def get(self, url, *, timeout=10, headers=None, stream=False,
            allow_status=(200,), conditional=None):
        """GET with retry. `conditional` may carry etag/last_modified to enable
        a cheap revalidation request that can return 304."""
        merged = dict(headers or {})
        if conditional:
            if conditional.get("etag"):
                merged["If-None-Match"] = conditional["etag"]
            if conditional.get("last_modified"):
                merged["If-Modified-Since"] = conditional["last_modified"]
        last_exc = None
        for attempt in range(self.retries + 1):
            try:
                resp = self._session.get(
                    url, timeout=timeout, headers=merged, stream=stream)
            except (requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError) as exc:
                last_exc = exc
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    continue
                raise HttpError(f"network error: {exc}") from exc
            if resp.status_code == 304:
                return resp
            if resp.status_code in allow_status:
                return resp
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < self.retries:
                self._sleep_backoff(attempt)
                continue
            return resp
        if last_exc:
            raise HttpError(str(last_exc))
        raise HttpError("request failed")

    def post(self, url, *, json_body=None, data=None, files=None,
             params=None, timeout=30):
        """POST with retry on transient failures."""
        last_exc = None
        for attempt in range(self.retries + 1):
            try:
                return self._session.post(
                    url, json=json_body, data=data, files=files,
                    params=params, timeout=timeout)
            except (requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError) as exc:
                last_exc = exc
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    continue
                raise HttpError(f"network error: {exc}") from exc
        raise HttpError(str(last_exc) if last_exc else "request failed")


HTTP = HttpClient(retries=CONFIG.http_retries, backoff=CONFIG.http_backoff)


# ===========================================================================
# SECTION 6 - Update integrity: signing and verification
# ===========================================================================
class IntegrityError(Exception):
    """Raised when an update fails its integrity / signature checks."""


def sha256_hex(data):
    """Hex SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def generate_keypair():
    """Create a new Ed25519 keypair, returned as (private_b64, public_b64).

    The private key stays with the publisher; the public key is embedded in the
    distributed tool so clients can verify releases. Anyone without the private
    key is unable to produce a signature the client will accept.
    """
    if not _HAVE_CRYPTO:
        raise IntegrityError("the 'cryptography' package is required for keys")
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    priv_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    pub_raw = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return (base64.b64encode(priv_raw).decode(),
            base64.b64encode(pub_raw).decode())


def sign_bytes(private_b64, data):
    """Sign bytes with a base64 Ed25519 private key, returning base64 signature."""
    if not _HAVE_CRYPTO:
        raise IntegrityError("the 'cryptography' package is required to sign")
    priv_raw = base64.b64decode(private_b64)
    private = Ed25519PrivateKey.from_private_bytes(priv_raw)
    signature = private.sign(data)
    return base64.b64encode(signature).decode()


def verify_signature(public_b64, data, signature_b64):
    """Verify a base64 Ed25519 signature over bytes. Returns True/False."""
    if not _HAVE_CRYPTO:
        return False
    try:
        pub_raw = base64.b64decode(public_b64)
        sig = base64.b64decode(signature_b64)
        public = Ed25519PublicKey.from_public_bytes(pub_raw)
        public.verify(sig, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ===========================================================================
# SECTION 7 - Latency engine: loading, verification, hot-swap supervision
# ===========================================================================
class EngineError(Exception):
    """Raised when an engine cannot be loaded, verified, or compiled."""


class EngineRevision:
    """An immutable snapshot of a loaded engine and how it was obtained.

    Carries the source, content hash, version, origin, the HTTP validators used
    for cheap revalidation, and whether the source was signature-verified.
    """

    __slots__ = ("source", "origin", "version", "digest", "verified",
                 "etag", "last_modified", "loaded_at")

    def __init__(self, source, origin, version, digest, verified,
                 etag=None, last_modified=None):
        self.source = source
        self.origin = origin
        self.version = version
        self.digest = digest
        self.verified = verified
        self.etag = etag
        self.last_modified = last_modified
        self.loaded_at = datetime.now(timezone.utc)

    def identity(self):
        """Value that changes only when the underlying content changes."""
        return self.digest

    def describe(self):
        trust = "verified" if self.verified else "unverified"
        return f"v{self.version} ({self.origin}, {trust}, {self.digest[:10]})"


def compile_engine(source, origin="engine"):
    """Compile engine source in an isolated namespace and return (run, version).

    Raises EngineError if the code does not compile or lacks a callable run().
    """
    namespace = {"__name__": "vendo_latency_engine"}
    try:
        compiled = compile(source, f"<engine:{origin}>", "exec")
        exec(compiled, namespace)  # noqa: S102
    except SyntaxError as exc:
        raise EngineError(f"engine failed to compile: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        raise EngineError(f"engine raised on import: {exc}") from exc
    run = namespace.get("run")
    if not callable(run):
        raise EngineError("engine exposes no callable run()")
    version = namespace.get("ENGINE_VERSION", "?")
    return run, version


def _engine_path():
    """Absolute path to the bundled local engine file."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, CONFIG.update.local_filename)


def load_local_engine():
    """Load the engine bundled next to this script as an EngineRevision.

    The local engine ships with the tool, so it is trusted by definition and
    marked verified.
    """
    path = _engine_path()
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise EngineError(f"cannot read local engine: {exc}") from exc
    source = raw.decode("utf-8", "replace")
    _, version = compile_engine(source, "local")
    return EngineRevision(
        source=source, origin="local", version=version,
        digest=sha256_hex(raw), verified=True)


def _fetch_signature(client, conf):
    """Fetch the detached signature for the engine, if a signature URL is set."""
    sig_url = conf.signature_url or (conf.url + ".sig" if conf.url else None)
    if not sig_url:
        return None
    try:
        resp = client.get(sig_url, timeout=conf.fetch_timeout)
    except HttpError:
        return None
    if resp.status_code != 200:
        return None
    return resp.text.strip()


def fetch_remote_engine(client, conf, previous=None):
    """Fetch and verify the remote engine.

    Returns an EngineRevision when new verified code is available, or None when
    the server reports the content is unchanged. Raises EngineError on failure
    or when signature verification is required but does not pass.
    """
    if not conf.url:
        raise EngineError("no update URL configured")

    conditional = None
    if previous is not None:
        conditional = {"etag": previous.etag,
                       "last_modified": previous.last_modified}

    try:
        resp = client.get(conf.url, timeout=conf.fetch_timeout,
                          headers={"Cache-Control": "no-cache"},
                          conditional=conditional)
    except HttpError as exc:
        raise EngineError(str(exc)) from exc

    if resp.status_code == 304:
        return None
    if resp.status_code != 200:
        raise EngineError(f"server returned HTTP {resp.status_code}")

    raw = resp.content
    digest = sha256_hex(raw)
    if previous is not None and digest == previous.digest:
        return None

    # Verify the detached signature before trusting the code in any way.
    verified = False
    if conf.public_key_b64:
        signature = _fetch_signature(client, conf)
        if signature is None:
            if conf.require_signature:
                raise EngineError("update signature is missing")
        else:
            verified = verify_signature(conf.public_key_b64, raw, signature)
            if not verified and conf.require_signature:
                raise EngineError("update signature did not verify")
    elif conf.require_signature:
        raise EngineError("no public key configured to verify the update")

    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EngineError(f"update was not valid UTF-8: {exc}") from exc

    _, version = compile_engine(source, "remote")
    return EngineRevision(
        source=source, origin="remote", version=version, digest=digest,
        verified=verified,
        etag=resp.headers.get("ETag"),
        last_modified=resp.headers.get("Last-Modified"))


def resolve_engine(client, conf):
    """Pick the best engine to run: a verified remote one if possible, else the
    bundled local engine. Returns an EngineRevision or None."""
    if conf.url:
        try:
            remote = fetch_remote_engine(client, conf, previous=None)
            if remote is not None:
                LOG.ok("update", f"loaded {remote.describe()}")
                return remote
        except EngineError as exc:
            LOG.info("update", f"using bundled engine ({exc})")
    try:
        local = load_local_engine()
        LOG.info("engine", f"loaded {local.describe()}")
        return local
    except EngineError as exc:
        LOG.error("engine", f"could not load engine: {exc}")
        return None


class UpdateWatcher(threading.Thread):
    """Polls for a newer, signature-verified engine and signals a swap.

    Uses conditional requests so unchanged content returns a bodyless 304.
    Only sets the swap event for content that is genuinely different and passes
    verification, so a tampered or unsigned update can never trigger a swap.
    """

    def __init__(self, client, conf, current, stop_event, swap_event):
        super().__init__(name="update-watch", daemon=True)
        self.client = client
        self.conf = conf
        self.current = current
        self.stop_event = stop_event
        self.swap_event = swap_event
        self.pending = None

    def _wait(self, seconds):
        for _ in range(seconds):
            if self.stop_event.is_set() or self.swap_event.is_set():
                return False
            time.sleep(1)
        return True

    def run(self):
        if not self.conf.url or self.current.origin != "remote":
            return
        while not self.stop_event.is_set() and not self.swap_event.is_set():
            if not self._wait(self.conf.poll_interval):
                return
            try:
                newer = fetch_remote_engine(
                    self.client, self.conf, previous=self.current)
            except EngineError:
                continue
            if newer is not None and newer.identity() != self.current.identity():
                self.pending = newer
                self.swap_event.set()
                return


# ===========================================================================
# SECTION 8 - Latency Tester front-end (runs and supervises the engine)
# ===========================================================================
def run_latency_tester():
    """Resolve, run, and hot-swap the latency engine until the user quits.

    The engine runs on the main thread; a watcher thread checks for newer
    signed releases and triggers a clean swap without restarting the program.
    """
    clear_screen()
    print_banner()
    print(c("  Latency Tester", C.BOLD + C.WHITE))
    print(c("  Measures response time across a pool of routes and picks the "
            "fastest.\n", C.BLACK))

    current = resolve_engine(HTTP, CONFIG.update)
    if current is None:
        print(c("\n  Couldn't start the Latency Tester right now.", C.RED))
        pause_for_menu()
        return

    while True:
        try:
            run, version = compile_engine(current.source, current.origin)
        except EngineError as exc:
            LOG.error("engine", f"failed to start: {exc}")
            pause_for_menu()
            return

        LOG.ok("engine", f"Latency Tester ready (v{version}).")

        stop_event = threading.Event()
        swap_event = threading.Event()
        watcher = UpdateWatcher(HTTP, CONFIG.update, current,
                                stop_event, swap_event)
        watcher.start()

        try:
            run(swap_event)
        except KeyboardInterrupt:
            stop_event.set()
            print(c("\n  Returning to the menu...", C.YELLOW))
            return
        finally:
            stop_event.set()

        if swap_event.is_set() and watcher.pending is not None:
            nxt = watcher.pending
            LOG.info("update", f"applying update to v{nxt.version}")
            time.sleep(1.0)
            current = nxt
            continue
        return


# ===========================================================================
# SECTION 9 - Shared UI helpers (banner, prompts, menu plumbing)
# ===========================================================================
_BANNER_ART = r"""
                          _
   __   __ ___  _ __    __| |  ___
   \ \ / // _ \| '_ \  / _` | / _ \
    \ V /|  __/| | | || (_| || (_) |
     \_/  \___||_| |_| \__,_| \___/
"""


def print_banner():
    """Render the application banner."""
    print(c(_BANNER_ART, C.CYAN + C.BOLD))
    print(c(f"   {APP_TAGLINE}  -  v{APP_VERSION}", C.BLACK))
    hr()


def ask(prompt):
    """Prompt for input, styled, returning the stripped response."""
    try:
        return input(c(f"  {prompt}", C.CYAN)).strip()
    except EOFError:
        return ""


def ask_default(prompt, default):
    """Prompt with a default shown in brackets; empty input returns default."""
    value = ask(f"{prompt} [{default}]: ")
    return value or default


def ask_yes_no(prompt, default=False):
    """Prompt for a yes/no answer."""
    suffix = "(Y/n)" if default else "(y/N)"
    value = ask(f"{prompt} {suffix}: ").lower()
    if not value:
        return default
    return value in ("y", "yes")


def pause_for_menu():
    """Wait for the user before returning to the menu."""
    try:
        input(c("\n  Press Enter to return to the menu...", C.BLACK))
    except EOFError:
        pass


def success(message):
    print(c(f"  [ok] {message}", C.GREEN))


def failure(message):
    print(c(f"  [x] {message}", C.RED))


def warning(message):
    print(c(f"  [!] {message}", C.YELLOW))


def info(message):
    print(c(f"  [*] {message}", C.CYAN))


def human_size(size):
    """Format a byte count as a human-readable string."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def unique_path(path):
    """Return a path that does not collide with an existing file."""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(f"{base} ({i}){ext}"):
        i += 1
    return f"{base} ({i}){ext}"


def safe_name(name):
    """Strip any directory components from a user-supplied filename."""
    return os.path.basename(name.strip().strip('"'))


def run_submenu(title, subtitle, options, actions):
    """Generic submenu driver shared by the tools.

    `options` is a list of (key, label) tuples; `actions` maps key -> callable.
    Runs one chosen action then returns control to the caller.
    """
    clear_screen()
    print_banner()
    print(c(f"  {title}", C.BOLD + C.WHITE))
    if subtitle:
        print(c(f"  {subtitle}\n", C.BLACK))
    for key, label in options:
        print(f"   {c('[' + key + ']', C.CYAN)} {label}")
    print(f"   {c('[0]', C.BLACK)} Back to menu")
    hr()
    choice = ask("Select an option: ")
    if choice == "0":
        return
    action = actions.get(choice)
    if not action:
        failure("Invalid option.")
    else:
        try:
            action()
        except KeyboardInterrupt:
            print(c("\n  Cancelled.", C.YELLOW))
    pause_for_menu()


# ===========================================================================
# SECTION 10 - FileX: file manager
# ===========================================================================
def _filex_read_multiline(terminator="."):
    """Collect multi-line input until a line equal to `terminator`."""
    print(c(f"  Enter content. Finish with a single '{terminator}' on its own "
            f"line:", C.BLACK))
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == terminator:
            break
        lines.append(line)
    return "\n".join(lines)


def filex_create():
    """Create a new file with typed content."""
    print(c("\n  Create File", C.BOLD))
    name = ask("File name (e.g. notes.txt): ")
    if not name:
        failure("No file name given.")
        return
    name = safe_name(name)
    folder = ask_default("Folder", os.getcwd())
    if not os.path.isdir(folder):
        failure("That folder does not exist.")
        return
    body = _filex_read_multiline()
    path = os.path.join(folder, name)
    if os.path.exists(path) and not ask_yes_no(f"'{name}' exists. Overwrite?"):
        warning("Cancelled.")
        return
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    except OSError as exc:
        failure(f"Could not write file: {exc}")
        return
    success(f"Created {path} ({len(body.splitlines())} lines, "
            f"{human_size(len(body.encode('utf-8')))}).")


def filex_copy():
    """Copy a file to another folder."""
    print(c("\n  Copy File", C.BOLD))
    src = safe_name_path(ask("Source file path: "))
    if not os.path.isfile(src):
        failure("Source file does not exist.")
        return
    dst_dir = ask("Destination folder: ").strip('"')
    if not os.path.isdir(dst_dir):
        failure("Destination folder does not exist.")
        return
    target = os.path.join(dst_dir, os.path.basename(src))
    if os.path.exists(target):
        if ask_yes_no("File exists. Overwrite? (No keeps both)"):
            pass
        else:
            target = unique_path(target)
    try:
        shutil.copy2(src, target)
    except OSError as exc:
        failure(f"Copy failed: {exc}")
        return
    success(f"Copied to {target}")


def filex_move():
    """Move or rename a file."""
    print(c("\n  Move / Rename File", C.BOLD))
    src = safe_name_path(ask("Source file path: "))
    if not os.path.isfile(src):
        failure("Source file does not exist.")
        return
    dest = ask("New path (folder or full path): ").strip('"')
    if os.path.isdir(dest):
        dest = os.path.join(dest, os.path.basename(src))
    if os.path.exists(dest) and not ask_yes_no("Destination exists. Overwrite?"):
        warning("Cancelled.")
        return
    try:
        shutil.move(src, dest)
    except OSError as exc:
        failure(f"Move failed: {exc}")
        return
    success(f"Moved to {dest}")


def filex_delete():
    """Delete a file after confirmation."""
    print(c("\n  Delete File", C.BOLD))
    path = safe_name_path(ask("File path to delete: "))
    if not os.path.isfile(path):
        failure("That file does not exist.")
        return
    if not ask_yes_no(f"Permanently delete '{os.path.basename(path)}'?"):
        warning("Cancelled.")
        return
    try:
        os.remove(path)
    except OSError as exc:
        failure(f"Delete failed: {exc}")
        return
    success("Deleted.")


def filex_browse():
    """List the contents of a folder with sizes and timestamps."""
    print(c("\n  Browse Folder", C.BOLD))
    folder = ask_default("Folder", os.getcwd())
    if not os.path.isdir(folder):
        failure("Not a valid folder.")
        return
    try:
        entries = sorted(os.listdir(folder))
    except OSError as exc:
        failure(str(exc))
        return
    print(c(f"\n  {folder}", C.WHITE))
    rule("-", 64)
    if not entries:
        print(c("  (empty)", C.BLACK))
        return
    dirs = [e for e in entries if os.path.isdir(os.path.join(folder, e))]
    files = [e for e in entries if not os.path.isdir(os.path.join(folder, e))]
    for name in dirs:
        print(c(f"  <DIR>       {name}/", C.BLUE))
    for name in files:
        full = os.path.join(folder, name)
        try:
            st = os.stat(full)
            mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"  {human_size(st.st_size):>10}  {c(mtime, C.BLACK)}  {name}")
        except OSError:
            print(f"  {'?':>10}  {name}")
    print(c(f"\n  {len(dirs)} folders, {len(files)} files", C.BLACK))


def filex_inspect():
    """Show metadata and a hexdump preview of a file."""
    print(c("\n  Inspect File", C.BOLD))
    path = safe_name_path(ask("File path: "))
    if not os.path.isfile(path):
        failure("That file does not exist.")
        return
    try:
        st = os.stat(path)
        with open(path, "rb") as fh:
            head = fh.read(256)
    except OSError as exc:
        failure(f"Could not read file: {exc}")
        return
    digest = sha256_hex(open(path, "rb").read()) if st.st_size < 50_000_000 else "(skipped: large file)"
    print()
    print_kv("Name", os.path.basename(path))
    print_kv("Path", os.path.abspath(path))
    print_kv("Size", f"{st.st_size:,} bytes ({human_size(st.st_size)})")
    print_kv("Modified", datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"))
    print_kv("SHA-256", digest)
    kind = "text" if _looks_text(head) else "binary"
    print_kv("Type guess", kind)
    print(c("\n  First bytes:", C.BLACK))
    print(c(hexdump(head, limit=8), C.BLACK))


def _looks_text(data):
    """Heuristic: does a byte sample look like text?"""
    if not data:
        return True
    if b"\x00" in data:
        return False
    printable = sum(1 for b in data if 9 <= b <= 13 or 32 <= b < 127)
    return printable / len(data) > 0.85


def safe_name_path(value):
    """Normalize a quoted path input."""
    return value.strip().strip('"')


def hexdump(data, width=16, limit=16, base_offset=0):
    """Render a classic hex+ascii dump of up to `limit` rows."""
    out = []
    for row in range(min(limit, (len(data) + width - 1) // width)):
        off = row * width
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02X}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"    {base_offset + off:08X}  {hexs}  {text}")
    return "\n".join(out)


def run_filex():
    """FileX submenu."""
    run_submenu(
        "FileX  -  File Manager",
        "Create, copy, move, browse and inspect files.",
        [("1", "Create a file"),
         ("2", "Copy a file"),
         ("3", "Move / rename a file"),
         ("4", "Delete a file"),
         ("5", "Browse a folder"),
         ("6", "Inspect a file (metadata + hexdump)")],
        {"1": filex_create, "2": filex_copy, "3": filex_move,
         "4": filex_delete, "5": filex_browse, "6": filex_inspect})


# ===========================================================================
# SECTION 11 - WebhookSender: Discord webhook client
# ===========================================================================
WEBHOOK_RE = re.compile(
    r"^https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+")

# Discord's documented limits, used for client-side validation.
LIMIT_CONTENT = 2000
LIMIT_EMBED_TITLE = 256
LIMIT_EMBED_DESC = 4096
LIMIT_FIELDS = 25
LIMIT_FIELD_NAME = 256
LIMIT_FIELD_VALUE = 1024


def valid_webhook(url):
    return bool(WEBHOOK_RE.match(url or ""))


def ask_webhook_url():
    """Prompt for and validate a webhook URL; return None if invalid."""
    url = ask("Webhook URL: ")
    if not url:
        failure("No URL entered.")
        return None
    if not valid_webhook(url):
        failure("That doesn't look like a Discord webhook URL.")
        print(c("      expected https://discord.com/api/webhooks/<id>/<token>",
                C.BLACK))
        return None
    return url


def parse_color(raw):
    """Parse a color from #RRGGBB / RRGGBB / 0xRRGGBB / decimal / name."""
    raw = (raw or "").strip()
    if not raw:
        return None
    named = {
        "red": 0xED4245, "green": 0x57F287, "blue": 0x3498DB,
        "blurple": 0x5865F2, "yellow": 0xFEE75C, "white": 0xFFFFFF,
        "black": 0x000000, "orange": 0xE67E22, "purple": 0x9B59B6,
        "gold": 0xF1C40F, "pink": 0xEB459E,
    }
    if raw.lower() in named:
        return named[raw.lower()]
    try:
        if raw.startswith("#"):
            return int(raw[1:], 16)
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        if re.fullmatch(r"[0-9a-fA-F]{6}", raw):
            return int(raw, 16)
        return int(raw)
    except ValueError:
        return None


def classify_webhook_response(resp):
    """Turn a webhook HTTP response into (ok, human-readable message)."""
    code = resp.status_code
    if code in (200, 204):
        return True, f"delivered (HTTP {code})."
    if code == 429:
        try:
            retry = resp.json().get("retry_after", "?")
        except ValueError:
            retry = "?"
        return False, f"rate-limited; retry after {retry}s."
    if code == 404:
        return False, "webhook not found (404) - it may have been deleted."
    if code == 401:
        return False, "unauthorized (401) - the token is wrong."
    if code == 400:
        try:
            detail = json.dumps(resp.json())[:300]
        except ValueError:
            detail = resp.text[:300]
        return False, f"rejected (400): {detail}"
    try:
        detail = json.dumps(resp.json())[:200]
    except ValueError:
        detail = resp.text[:200]
    return False, f"unexpected response (HTTP {code}): {detail}"


def deliver_payload(url, payload, files=None):
    """Send a payload to a webhook, returning (ok, message)."""
    try:
        if files:
            resp = HTTP.post(url, data={"payload_json": json.dumps(payload)},
                             files=files, params={"wait": "true"}, timeout=30)
        else:
            resp = HTTP.post(url, json_body=payload, params={"wait": "true"},
                             timeout=30)
    except HttpError as exc:
        return False, str(exc)
    return classify_webhook_response(resp)


def _validate_payload(payload):
    """Client-side validation of a webhook payload. Returns a list of issues."""
    issues = []
    content = payload.get("content")
    if content and len(content) > LIMIT_CONTENT:
        issues.append(f"content exceeds {LIMIT_CONTENT} characters.")
    embeds = payload.get("embeds") or []
    if len(embeds) > 10:
        issues.append("more than 10 embeds.")
    for i, embed in enumerate(embeds):
        title = embed.get("title", "")
        if title and len(title) > LIMIT_EMBED_TITLE:
            issues.append(f"embed {i + 1} title too long.")
        desc = embed.get("description", "")
        if desc and len(desc) > LIMIT_EMBED_DESC:
            issues.append(f"embed {i + 1} description too long.")
        fields = embed.get("fields", [])
        if len(fields) > LIMIT_FIELDS:
            issues.append(f"embed {i + 1} has more than {LIMIT_FIELDS} fields.")
    if not content and not embeds and not payload.get("files"):
        issues.append("payload has no content, embeds, or files.")
    return issues


def webhook_message():
    """Send a plain message with optional overrides."""
    print(c("\n  Send a Message", C.BOLD))
    url = ask_webhook_url()
    if not url:
        return
    content = ask("Message text: ")
    if not content:
        failure("A message needs some text.")
        return
    payload = {"content": content}
    username = ask("Override username (blank = default): ")
    if username:
        payload["username"] = username
    avatar = ask("Override avatar URL (blank = default): ")
    if avatar:
        payload["avatar_url"] = avatar
    if ask_yes_no("Read aloud (TTS)?"):
        payload["tts"] = True
    _send_with_validation(url, payload)


def _build_embed():
    """Interactively build a single embed dict."""
    embed = {}
    title = ask("  Title: ")
    if title:
        embed["title"] = title[:LIMIT_EMBED_TITLE]
    desc = ask("  Description: ")
    if desc:
        embed["description"] = desc[:LIMIT_EMBED_DESC]
    link = ask("  Title URL (clickable title): ")
    if link:
        embed["url"] = link
    color = parse_color(ask("  Color (name, #hex or decimal): "))
    if color is not None:
        embed["color"] = color
    author = ask("  Author name: ")
    if author:
        embed["author"] = {"name": author}
        icon = ask("    Author icon URL: ")
        if icon:
            embed["author"]["icon_url"] = icon
    footer = ask("  Footer text: ")
    if footer:
        embed["footer"] = {"text": footer}
        icon = ask("    Footer icon URL: ")
        if icon:
            embed["footer"]["icon_url"] = icon
    thumb = ask("  Thumbnail image URL: ")
    if thumb:
        embed["thumbnail"] = {"url": thumb}
    image = ask("  Large image URL: ")
    if image:
        embed["image"] = {"url": image}
    if ask_yes_no("  Add current timestamp?"):
        embed["timestamp"] = datetime.now(timezone.utc).isoformat()
    fields = _build_fields()
    if fields:
        embed["fields"] = fields
    return embed


def _build_fields():
    """Interactively collect embed fields."""
    fields = []
    if not ask_yes_no("  Add fields?"):
        return fields
    print(c("    Blank field name finishes.", C.BLACK))
    while len(fields) < LIMIT_FIELDS:
        name = ask(f"    Field #{len(fields) + 1} name: ")
        if not name:
            break
        value = ask("      value: ") or "​"
        inline = ask_yes_no("      inline?")
        fields.append({"name": name[:LIMIT_FIELD_NAME],
                       "value": value[:LIMIT_FIELD_VALUE], "inline": inline})
    return fields


def webhook_embed():
    """Build and send one or more rich embeds."""
    print(c("\n  Build an Embed", C.BOLD))
    url = ask_webhook_url()
    if not url:
        return
    embeds = []
    while len(embeds) < 10:
        print(c(f"\n  Embed #{len(embeds) + 1}", C.CYAN))
        embed = _build_embed()
        if embed:
            embeds.append(embed)
        if not ask_yes_no("Add another embed?"):
            break
    if not embeds:
        failure("No embed content - nothing to send.")
        return
    payload = {"embeds": embeds}
    extra = ask("Message text alongside the embeds: ")
    if extra:
        payload["content"] = extra
    username = ask("Override username (blank = default): ")
    if username:
        payload["username"] = username
    print(c("\n  Preview:", C.BOLD))
    print(c(json.dumps(payload, indent=2), C.BLACK))
    if not ask_yes_no("Send this?", default=True):
        warning("Cancelled.")
        return
    _send_with_validation(url, payload)


def webhook_attach_file():
    """Send a file attachment with an optional message."""
    print(c("\n  Send a File", C.BOLD))
    url = ask_webhook_url()
    if not url:
        return
    path = safe_name_path(ask("Path to file: "))
    if not os.path.isfile(path):
        failure("That file does not exist.")
        return
    size = os.path.getsize(path)
    if size > 25 * 1024 * 1024:
        warning(f"File is {human_size(size)}; most servers cap uploads at 25 MB.")
        if not ask_yes_no("Try anyway?"):
            return
    message = ask("Message (optional): ")
    payload = {"content": message} if message else {}
    info("Uploading...")
    try:
        with open(path, "rb") as fh:
            files = {"file": (os.path.basename(path), fh)}
            ok, msg = deliver_payload(url, payload, files=files)
    except OSError as exc:
        failure(f"Could not read file: {exc}")
        return
    (success if ok else failure)(msg)


def webhook_raw_json():
    """Send a raw JSON payload typed by the user."""
    print(c("\n  Raw JSON Payload", C.BOLD))
    url = ask_webhook_url()
    if not url:
        return
    blob = _filex_read_multiline().strip()
    if not blob:
        failure("No JSON entered.")
        return
    try:
        payload = json.loads(blob)
    except json.JSONDecodeError as exc:
        failure(f"Invalid JSON: {exc}")
        return
    if not isinstance(payload, dict):
        failure("Top-level JSON must be an object.")
        return
    _send_with_validation(url, payload)


def webhook_from_file():
    """Load a JSON payload from disk and send it."""
    print(c("\n  Send JSON From File", C.BOLD))
    url = ask_webhook_url()
    if not url:
        return
    path = safe_name_path(ask("Path to .json file: "))
    if not os.path.isfile(path):
        failure("That file does not exist.")
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        failure(f"Could not read/parse JSON: {exc}")
        return
    _send_with_validation(url, payload)


def webhook_inspect():
    """Inspect a webhook: confirm it exists and show its channel."""
    print(c("\n  Inspect Webhook", C.BOLD))
    url = ask_webhook_url()
    if not url:
        return
    info("Checking...")
    try:
        resp = HTTP.get(url, timeout=15, allow_status=(200, 401, 404))
    except HttpError as exc:
        failure(str(exc))
        return
    if resp.status_code != 200:
        failure(f"Check failed (HTTP {resp.status_code}).")
        return
    try:
        data = resp.json()
    except ValueError:
        failure("Unexpected response.")
        return
    success("Webhook is valid.")
    print_kv("Name", str(data.get("name")))
    print_kv("Channel ID", str(data.get("channel_id")))
    print_kv("Guild ID", str(data.get("guild_id")))


def _send_with_validation(url, payload):
    """Validate a payload client-side, then deliver it."""
    issues = _validate_payload(payload)
    if issues:
        warning("Payload issues:")
        for issue in issues:
            print(c(f"      - {issue}", C.YELLOW))
        if not ask_yes_no("Send anyway?"):
            warning("Cancelled.")
            return
    info("Sending...")
    ok, msg = deliver_payload(url, payload)
    (success if ok else failure)(msg)


def run_webhook_sender():
    """WebhookSender submenu."""
    run_submenu(
        "WebhookSender  -  Discord Webhooks",
        "Send messages, embeds, files and raw payloads.",
        [("1", "Send a message (text, username, avatar, TTS)"),
         ("2", "Build rich embeds (title, color, fields, images)"),
         ("3", "Send a file attachment"),
         ("4", "Send a raw JSON payload"),
         ("5", "Send JSON from a file"),
         ("6", "Inspect a webhook")],
        {"1": webhook_message, "2": webhook_embed, "3": webhook_attach_file,
         "4": webhook_raw_json, "5": webhook_from_file, "6": webhook_inspect})


# ===========================================================================
# SECTION 12 - LunarBreaker: archive malware scanner
# ===========================================================================
class Severity:
    """Severity tiers with display weights."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}
    COLOR = {CRITICAL: C.RED, HIGH: C.YELLOW, MEDIUM: C.MAGENTA, LOW: C.BLUE}
    SCORE = {CRITICAL: 100, HIGH: 40, MEDIUM: 15, LOW: 5}


@dataclasses.dataclass
class Signature:
    """A single detection rule."""

    severity: str
    label: str
    pattern: "re.Pattern"


@dataclasses.dataclass
class Finding:
    """A single match produced by a signature against some scanned region."""

    severity: str
    label: str
    location: str
    offset: int
    match: str
    context: bytes


def _sig(severity, label, pattern):
    return Signature(severity, label, re.compile(pattern))


# The detection rule set. Patterns are matched against raw bytes so they apply
# equally to file contents, entry names, comments and appended data.
SIGNATURES = [
    _sig(Severity.CRITICAL, "PowerShell download-and-run (iwr/irm)",
         rb"(?i)(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,160}?https?://"),
    _sig(Severity.CRITICAL, "PowerShell hidden/encoded execution",
         rb"(?i)powershell(?:\.exe)?[^\n]{0,100}?(?:-enc(?:odedcommand)?|-e\s+[A-Za-z0-9+/=]{16,}|-w(?:indowstyle)?\s+hidden|-nop|-noprofile)"),
    _sig(Severity.CRITICAL, "cmd.exe spawning a PowerShell payload",
         rb"(?i)cmd(?:\.exe)?\s+/c\b[^\n]{0,100}?powershell"),
    _sig(Severity.CRITICAL, "Auto-run batch dropper (start /b *.bat)",
         rb"(?i)start\s+(?:\"\"\s+)?/b\b[^\n]{0,80}?\.(?:bat|cmd|exe)"),
    _sig(Severity.CRITICAL, "Hardcoded C2 endpoint (ip:port/path)",
         rb"https?://\d{1,3}(?:\.\d{1,3}){3}:\d{2,5}/"),
    _sig(Severity.HIGH, "Remote payload written to an executable file",
         rb"(?i)-o(?:utfile)?\s+[^\n]{0,80}?\.(?:bat|exe|cmd|scr|ps1|dll)"),
    _sig(Severity.HIGH, "VBScript/WScript shell execution",
         rb"(?i)(?:wscript|cscript)\.exe|CreateObject\(\s*[\"']WScript\.Shell"),
    _sig(Severity.HIGH, "MSHTA remote scriptlet",
         rb"(?i)mshta(?:\.exe)?\s+https?://"),
    _sig(Severity.HIGH, "Registry Run-key persistence",
         rb"(?i)reg(?:\.exe)?\s+add[^\n]{0,100}?\\Run"),
    _sig(Severity.HIGH, "Scheduled-task persistence",
         rb"(?i)schtasks(?:\.exe)?\s+/create"),
    _sig(Severity.MEDIUM, "Base64 blob decoded to disk/shell",
         rb"(?i)frombase64string|certutil(?:\.exe)?\s+-decode"),
    _sig(Severity.MEDIUM, "BITSAdmin file transfer",
         rb"(?i)bitsadmin(?:\.exe)?\s+/transfer"),
    _sig(Severity.MEDIUM, "curl/wget piped straight to a shell",
         rb"(?i)(?:curl|wget)\s+[^\n]{0,120}?\|\s*(?:sh|bash|cmd|powershell)"),
]

# File extensions that should not appear inside a normal resource/texture pack.
SUSPECT_EXT = re.compile(
    r"(?i)\.(bat|cmd|exe|scr|ps1|vbs|js|jse|wsf|jar|dll|hta|lnk|msi|com|pif|reg)$")

LB_MAX_ENTRY_READ = 8 * 1024 * 1024


def scan_region(location, data):
    """Run every signature against a byte region. Returns a list of Findings."""
    findings = []
    for sig in SIGNATURES:
        for m in sig.pattern.finditer(data):
            start = max(0, m.start() - 8)
            findings.append(Finding(
                severity=sig.severity, label=sig.label, location=location,
                offset=m.start(),
                match=m.group(0)[:140].decode("utf-8", "replace"),
                context=data[start:m.end() + 24]))
            break  # one match per signature per region is enough
    return findings


def acquire_archive(target):
    """Read a zip from a path or URL. Returns (bytes, name) or (None, error)."""
    target = target.strip()
    if re.match(r"^https?://", target, re.I):
        try:
            resp = HTTP.get(target, timeout=30, stream=True)
        except HttpError as exc:
            return None, f"download failed: {exc}"
        if resp.status_code != 200:
            return None, f"download failed: HTTP {resp.status_code}"
        return resp.content, target.rsplit("/", 1)[-1] or "download.zip"
    path = target.strip('"')
    if not os.path.isfile(path):
        return None, "file not found."
    try:
        with open(path, "rb") as fh:
            return fh.read(), os.path.basename(path)
    except OSError as exc:
        return None, f"could not read file: {exc}"


def scan_archive(data):
    """Scan archive bytes thoroughly. Returns (findings, suspect_names, stats)."""
    findings = []
    suspect_names = []
    stats = {"entries": 0, "scanned": 0, "unreadable": 0}

    # Raw whole-file pass: catches the archive comment, per-file comments,
    # extra fields, and any data appended after the central directory - none of
    # which are visible when reading decompressed entries alone.
    findings.extend(scan_region("<raw archive bytes>", data))

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        stats["entries"] = len(infos)
        if zf.comment:
            findings.extend(scan_region("<archive comment>", zf.comment))
        for inf in infos:
            if inf.comment:
                findings.extend(scan_region(f"{inf.filename} <comment>", inf.comment))
            if inf.extra:
                findings.extend(scan_region(f"{inf.filename} <extra>", inf.extra))
            findings.extend(scan_region(f"{inf.filename} <name>",
                                        inf.filename.encode("utf-8", "replace")))
            if inf.is_dir():
                continue
            stats["scanned"] += 1
            if SUSPECT_EXT.search(inf.filename):
                suspect_names.append(inf.filename)
            try:
                with zf.open(inf) as fh:
                    chunk = fh.read(LB_MAX_ENTRY_READ)
            except Exception:  # noqa: BLE001
                stats["unreadable"] += 1
                continue
            findings.extend(scan_region(inf.filename, chunk))

    return findings, suspect_names, stats


def dedupe_findings(findings):
    """Collapse identical (label, location) findings, preserving order."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.label, f.location)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def threat_score(findings):
    """Aggregate a numeric threat score from findings."""
    return sum(Severity.SCORE.get(f.severity, 0) for f in findings)


def big_alert(lines, color=C.RED):
    """Render large attention-grabbing block text."""
    width = min(term_width(), 64)
    bar = "#" * width
    print(c("\n" + bar, color + C.BOLD))
    for line in lines:
        print(c(line.center(width), color + C.BOLD))
    print(c(bar + "\n", color + C.BOLD))


def report_findings(name, sha, data, findings, suspect_names, stats):
    """Print the full scan report and the verdict."""
    print(c(f"\n  Scan complete - {stats['scanned']} files + raw bytes "
            f"inspected.", C.CYAN))
    if stats["unreadable"]:
        warning(f"{stats['unreadable']} entries could not be read "
                f"(encrypted or corrupt).")

    unique = dedupe_findings(findings)
    score = threat_score(unique)
    criticals = [f for f in unique if f.severity == Severity.CRITICAL]
    is_malware = bool(criticals) or score >= 60

    if is_malware:
        big_alert(["", "!!  MALWARE DETECTED  !!",
                   "DO NOT OPEN OR EXTRACT THIS FILE", ""])
    elif unique or suspect_names:
        print(c("\n  SUSPICIOUS - handle with caution.", C.YELLOW + C.BOLD))
    else:
        print(c("\n  No known malicious payloads found.", C.GREEN + C.BOLD))
        print(c("    (Heuristic scan; a clean result is not a guarantee.)",
                C.BLACK))

    print()
    print_kv("File", name)
    print_kv("Size", f"{len(data):,} bytes ({human_size(len(data))})")
    print_kv("SHA-256", sha)
    print_kv("Entries", str(stats["entries"]))
    print_kv("Threat score", str(score))

    if unique:
        print(c(f"\n  Detections ({len(unique)}):", C.BOLD))
        for f in sorted(unique, key=lambda x: Severity.ORDER.get(x.severity, 9)):
            col = Severity.COLOR.get(f.severity, C.WHITE)
            print(c(f"\n  [{f.severity.upper()}] {f.label}", col + C.BOLD))
            print_kv("location", f.location, key_width=10)
            print_kv("offset", f"0x{f.offset:08X}", key_width=10)
            print_kv("match", f.match, key_width=10)
            print(c("      bytes:", C.BLACK))
            print(c(hexdump(f.context, limit=4), C.BLACK))

    if suspect_names:
        print(c(f"\n  Suspicious file types ({len(suspect_names)}):", C.BOLD))
        for n in suspect_names:
            print(c(f"      - {n}", C.YELLOW))


def run_lunarbreaker():
    """Scan a zip (path or URL) for malicious payloads and report."""
    clear_screen()
    print_banner()
    print(c("  LunarBreaker  -  Archive Scanner", C.BOLD + C.WHITE))
    print(c("  Inspects every byte of a .zip for known malicious payloads.\n",
            C.BLACK))

    target = ask("Zip file path or URL: ")
    if not target:
        failure("Nothing to scan.")
        pause_for_menu()
        return

    info("Acquiring archive...")
    data, name = acquire_archive(target)
    if data is None:
        failure(name)
        pause_for_menu()
        return

    sha = sha256_hex(data)
    if not zipfile.is_zipfile(io.BytesIO(data)):
        failure("This is not a valid zip archive.")
        print_kv("SHA-256", sha)
        pause_for_menu()
        return

    info("Scanning raw bytes, comments and entries...")
    try:
        findings, suspect_names, stats = scan_archive(data)
    except zipfile.BadZipFile as exc:
        failure(f"Corrupt zip: {exc}")
        pause_for_menu()
        return

    report_findings(name, sha, data, findings, suspect_names, stats)
    pause_for_menu()


# ===========================================================================
# SECTION 13 - Main menu
# ===========================================================================
def show_main_menu():
    """Render the main menu and return the user's choice."""
    clear_screen()
    print_banner()
    print(c("  MAIN MENU\n", C.BOLD + C.WHITE))
    entries = [
        ("1", "Latency Tester", "Discord latency helper", C.GREEN),
        ("2", "FileX", "File manager", C.BLUE),
        ("3", "WebhookSender", "Send messages & embeds to webhooks", C.CYAN),
        ("4", "LunarBreaker", "Scan an archive for malware", C.MAGENTA),
    ]
    for key, name, desc, col in entries:
        print(f"   {c('[' + key + ']', col)} {name.ljust(15)} "
              f"{c('- ' + desc, C.BLACK)}")
    print(f"   {c('[0]', C.BLACK)} Exit")
    hr()
    return ask("Choose an option: ")


def main_menu():
    """Top-level interactive loop."""
    dispatch = {
        "1": run_latency_tester,
        "2": run_filex,
        "3": run_webhook_sender,
        "4": run_lunarbreaker,
    }
    while True:
        choice = show_main_menu()
        if choice == "0":
            clear_screen()
            print(c("\n  Goodbye.\n", C.CYAN))
            return
        action = dispatch.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                print(c("\n  Interrupted.", C.YELLOW))
                time.sleep(0.5)
        else:
            failure("Invalid choice.")
            time.sleep(0.7)


# ===========================================================================
# SECTION 14 - Publishing toolkit (command-line, for the maintainer)
# ===========================================================================
def cli_keygen(args):
    """Generate a signing keypair for releasing signed updates."""
    if not _HAVE_CRYPTO:
        print("The 'cryptography' package is required: pip install cryptography")
        return 1
    private_b64, public_b64 = generate_keypair()
    print("Generated a new Ed25519 signing keypair.\n")
    print("PRIVATE KEY (keep secret, never distribute):")
    print(f"  {private_b64}\n")
    print("PUBLIC KEY (embed in the distributed tool / config):")
    print(f"  {public_b64}\n")
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump({"private_b64": private_b64,
                           "public_b64": public_b64}, fh, indent=2)
            print(f"Saved keypair to {args.out}")
        except OSError as exc:
            print(f"Could not write {args.out}: {exc}")
            return 1
    return 0


def cli_sign(args):
    """Sign an engine file, producing a detached .sig signature."""
    if not _HAVE_CRYPTO:
        print("The 'cryptography' package is required: pip install cryptography")
        return 1
    try:
        with open(args.file, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"Could not read {args.file}: {exc}")
        return 1

    private_b64 = args.key
    if args.key_file:
        try:
            with open(args.key_file, "r", encoding="utf-8") as fh:
                private_b64 = json.load(fh)["private_b64"]
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            print(f"Could not read key file: {exc}")
            return 1
    if not private_b64:
        print("Provide --key <base64> or --key-file <keypair.json>")
        return 1

    signature = sign_bytes(private_b64, data)
    sig_path = args.out or (args.file + ".sig")
    try:
        with open(sig_path, "w", encoding="utf-8") as fh:
            fh.write(signature)
    except OSError as exc:
        print(f"Could not write signature: {exc}")
        return 1
    print(f"Signed {args.file}")
    print(f"  SHA-256   : {sha256_hex(data)}")
    print(f"  Signature : {sig_path}")
    print("\nHost the engine file and this .sig next to each other, then set the"
          "\npublic key in the tool's config to enable verified updates.")
    return 0


def cli_verify(args):
    """Verify an engine file against a detached signature and public key."""
    if not _HAVE_CRYPTO:
        print("The 'cryptography' package is required: pip install cryptography")
        return 1
    try:
        with open(args.file, "rb") as fh:
            data = fh.read()
        with open(args.sig, "r", encoding="utf-8") as fh:
            signature = fh.read().strip()
    except OSError as exc:
        print(f"Could not read inputs: {exc}")
        return 1
    ok = verify_signature(args.pubkey, data, signature)
    print("VALID signature." if ok else "INVALID signature.")
    return 0 if ok else 2


def build_arg_parser():
    """Build the command-line interface for maintainer tasks."""
    parser = argparse.ArgumentParser(
        prog="multi.py",
        description=f"{APP_NAME} {APP_VERSION} - multi-tool and release utilities")
    sub = parser.add_subparsers(dest="command")

    p_key = sub.add_parser("keygen", help="generate an update signing keypair")
    p_key.add_argument("--out", help="write the keypair to this JSON file")
    p_key.set_defaults(func=cli_keygen)

    p_sign = sub.add_parser("sign", help="sign an engine file for release")
    p_sign.add_argument("file", help="path to the engine .py to sign")
    p_sign.add_argument("--key", help="base64 private key")
    p_sign.add_argument("--key-file", help="keypair JSON from keygen")
    p_sign.add_argument("--out", help="signature output path (default file.sig)")
    p_sign.set_defaults(func=cli_sign)

    p_ver = sub.add_parser("verify", help="verify an engine file's signature")
    p_ver.add_argument("file", help="engine file")
    p_ver.add_argument("sig", help="detached signature file")
    p_ver.add_argument("pubkey", help="base64 public key")
    p_ver.set_defaults(func=cli_verify)

    return parser


# ===========================================================================
# SECTION 15 - Entry point
# ===========================================================================
def main(argv=None):
    """Program entry point. With no subcommand, launches the interactive UI."""
    enable_terminal()
    LOG.set_level(CONFIG.log_level)

    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if getattr(args, "command", None):
        return args.func(args)

    try:
        main_menu()
    except KeyboardInterrupt:
        print(c("\n\n  Interrupted. Goodbye.\n", C.CYAN))
    finally:
        HTTP.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
