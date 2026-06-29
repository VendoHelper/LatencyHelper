"""
latency_engine.py  —  vendo latency engine (remote-updatable module)
====================================================================

This is the entire "Latency Tester" tool as a standalone module. The host
(multi.py) fetches this file from a URL, executes it, and calls run().

That means you can edit THIS file at its hosted location and every user gets
the new behaviour AND the new route list on their next launch — no reinstall.

Contract with the host
-----------------------
  * Only dependency is `requests` + the standard library.
  * Expose a top-level `run()` function. The host calls it.
  * `run()` owns its own loop and handles Ctrl+C, returning when the user
    wants to go back to the main menu.

Edit the route list in _ROUTES below.
"""

import os
import re
import sys
import time
import threading
import statistics
import concurrent.futures
from datetime import datetime

import requests


ENGINE_VERSION = "2.0.0"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DISCORD_ENDPOINT = "https://discord.com/api/v10/gateway"
RUN_INTERVAL = 5 * 60      # seconds between latency sweeps (5 min)
REQUEST_TIMEOUT = 10       # per-request timeout, seconds
MAX_WORKERS = 16           # max concurrent measurements
DEBUG = True               # always-on verbose debug logging
SWEEP_SPREAD = 60          # spread each sweep's dispatches across ~this many
                           # seconds so output streams steadily instead of all
                           # at once (set to 0 to fire everything immediately)

# --- Network route pool (edit here; updates ship with this file) -----------
_ROUTES = [
    "http://np_a3wibw8o22-session-ZHGSLAJR-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
    "http://np_a3wibw8o22-session-BXILYV62-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
    "http://np_a3wibw8o22-session-X3G0NRMF-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
    "http://np_a3wibw8o22-session-KCDXCWGZ-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
    "http://np_a3wibw8o22-session-VGQVITF7-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
    "http://np_a3wibw8o22-session-KLY2GZC1-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
    "http://np_a3wibw8o22-session-29V7JG6Q-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
    "http://np_a3wibw8o22-session-KC6P2F0Y-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
    "http://np_a3wibw8o22-session-NE02SUN4-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
    "http://np_a3wibw8o22-session-EGCZWZTT-time-1440:Uhuw1tA77iGR1vcP@eu-1.nodeproxies.xyz:8080",
]


# ---------------------------------------------------------------------------
# Terminal colors / formatting (self-contained so the module has no host deps)
# ---------------------------------------------------------------------------
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREY    = "\033[90m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"


def c(text, color):
    return f"{color}{text}{C.RESET}"


def rule(char="─", width=72, color=C.GREY):
    print(c(char * width, color))


# ---------------------------------------------------------------------------
# Debug logging (always on)
# ---------------------------------------------------------------------------
_log_lock = threading.Lock()


def _ts():
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def dbg(tag, msg, color=C.GREY):
    if not DEBUG:
        return
    thread = threading.current_thread().name
    line = (f"{c(_ts(), C.GREY)} {c(f'[{tag:^7}]', color)} "
            f"{c(f'{thread:<14}', C.DIM)} {msg}")
    with _log_lock:
        print(line)


def _mask(route):
    """Hide credentials when printing a route (user:pass@host -> ***@host)."""
    return re.sub(r"//[^@/]+@", "//***@", route)


# ---------------------------------------------------------------------------
# Latency measurement
# ---------------------------------------------------------------------------
def measure_route(route, index, total):
    """Measure round-trip latency to the Discord API over one route."""
    proxies = {"http": route, "https": route}
    result = {"route": route, "ok": False, "status": None, "latency_ms": None,
              "gateway": None, "size_bytes": 0, "error": None, "phases": {}}

    label = f"node {index:>2}/{total}"
    dbg("DISPATCH", f"{label}  ->  {c(_mask(route), C.WHITE)}", C.BLUE)
    dbg("CONNECT", f"{label}  opening session, timeout={REQUEST_TIMEOUT}s", C.CYAN)

    start = time.perf_counter()
    try:
        dbg("SEND", f"{label}  GET {DISCORD_ENDPOINT}", C.CYAN)
        resp = requests.get(
            DISCORD_ENDPOINT, proxies=proxies, timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": f"vendo-latency/{ENGINE_VERSION}"})
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        result["latency_ms"] = round(elapsed_ms, 2)
        result["status"] = resp.status_code
        result["size_bytes"] = len(resp.content)
        result["ok"] = resp.status_code == 200

        elapsed_attr = getattr(resp, "elapsed", None)
        if elapsed_attr is not None:
            result["phases"]["server_ms"] = round(elapsed_attr.total_seconds() * 1000.0, 2)

        dbg("RECV", f"{label}  HTTP {resp.status_code}  "
                    f"{result['size_bytes']}B  in {elapsed_ms:.2f}ms", C.GREEN)
        for k, v in resp.headers.items():
            if k.lower() in ("via", "server", "cf-ray", "date", "content-type"):
                dbg("HEADER", f"{label}  {k}: {v}", C.DIM)
        try:
            result["gateway"] = resp.json().get("url")
            dbg("PARSE", f"{label}  gateway={result['gateway']}", C.CYAN)
        except (ValueError, AttributeError):
            result["gateway"] = None
            dbg("PARSE", f"{label}  response body was not JSON", C.YELLOW)
    except Exception as exc:  # noqa: BLE001 - capture every failure mode
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        result["latency_ms"] = round(elapsed_ms, 2)
        result["error"] = f"{type(exc).__name__}: {exc}"
        dbg("ERROR", f"{label}  {result['error']}  (after {elapsed_ms:.2f}ms)", C.RED)

    verdict = "REACHABLE" if result["ok"] else "UNREACHABLE"
    vcolor = C.GREEN if result["ok"] else C.RED
    dbg("RESULT", f"{label}  {c(verdict, vcolor)}  latency={result['latency_ms']}ms", vcolor)
    return result


def _log_single(index, total, res):
    tag = c("  OK  ", C.GREEN) if res["ok"] else c("FAILED", C.RED)
    print(c("  " + "·" * 68, C.GREY))
    print(f"  [{index:>2}/{total}] NODE   : {c(_mask(res['route']), C.WHITE)}")
    print(f"           STATUS : [{tag}]  http={res['status']}")
    if res["latency_ms"] is not None:
        print(f"           LATENCY: {c(f'{res['latency_ms']:.2f} ms', C.YELLOW)}")
    if res["phases"].get("server_ms") is not None:
        print(f"           RTT(srv): {res['phases']['server_ms']:.2f} ms")
    print(f"           PAYLOAD: {res['size_bytes']} bytes received")
    if res["gateway"]:
        print(f"           GATEWAY: {c(res['gateway'], C.CYAN)}")
    if res["error"]:
        print(f"           ERROR  : {c(res['error'], C.RED)}")


def _log_summary(results):
    ok = [r for r in results if r["ok"] and r["latency_ms"] is not None]
    bad = [r for r in results if not r["ok"]]

    print()
    print(c("  ╓" + "─" * 66 + "╖", C.BLUE))
    print(c("  ║  SWEEP SUMMARY".ljust(69) + "║", C.BLUE))
    print(c("  ╙" + "─" * 66 + "╜", C.BLUE))
    print(f"     Nodes measured    : {len(results)}")
    print(f"     Reachable         : {c(len(ok), C.GREEN)}")
    print(f"     Unreachable       : {c(len(bad), C.RED)}")
    rate = (len(ok) / len(results) * 100.0) if results else 0.0
    print(f"     Success rate      : {rate:.1f}%")

    if ok:
        latencies = [r["latency_ms"] for r in ok]
        print()
        print("     Latency statistics (reachable nodes):")
        print(f"       min    : {min(latencies):.2f} ms")
        print(f"       max    : {max(latencies):.2f} ms")
        print(f"       mean   : {statistics.mean(latencies):.2f} ms")
        print(f"       median : {statistics.median(latencies):.2f} ms")
        if len(latencies) > 1:
            print(f"       stdev  : {statistics.stdev(latencies):.2f} ms")

        best = min(ok, key=lambda r: r["latency_ms"])
        print()
        print(c("  ★" + "═" * 66 + "★", C.GREEN + C.BOLD))
        print(c("  ★ SELECTED NODE (lowest latency)".ljust(69) + "★", C.GREEN + C.BOLD))
        print(c(f"  ★   node     : {_mask(best['route'])}".ljust(69) + "★", C.GREEN + C.BOLD))
        print(c(f"  ★   latency  : {best['latency_ms']:.2f} ms".ljust(69) + "★", C.GREEN + C.BOLD))
        print(c(f"  ★   gateway  : {best['gateway']}".ljust(69) + "★", C.GREEN + C.BOLD))
        print(c("  ★" + "═" * 66 + "★", C.GREEN + C.BOLD))
        return best
    else:
        print()
        print(c("  [WARN] No reachable nodes this sweep - no node selected.", C.YELLOW))
        return None


def _drain_done(pending, results, total):
    """Print and remove any futures that have already finished (non-blocking)."""
    still = []
    for fut in pending:
        if fut.done():
            res = fut.result()
            results.append(res)
            dbg("COLLECT", f"{len(results)}/{total} results in", C.BLUE)
            _log_single(len(results), total, res)
        else:
            still.append(fut)
    pending[:] = still


def _sweep(sweep_num, stop_event=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(c("┌" + "─" * 70 + "┐", C.GREY))
    print(c(f"│ SCAN #{sweep_num:<4}  started {ts}".ljust(71) + "│", C.GREY))
    print(c("└" + "─" * 70 + "┘", C.GREY))
    dbg("SWEEP", f"begin sweep #{sweep_num} over {len(_ROUTES)} nodes", C.MAGENTA)
    dbg("POOL", f"spinning up thread pool, max_workers={MAX_WORKERS}", C.MAGENTA)

    total = len(_ROUTES)
    # Stagger dispatches across SWEEP_SPREAD seconds so the console stays busy
    # instead of dumping everything in one burst. Each node is launched gap
    # seconds after the previous one; results are drained live in between.
    gap = (SWEEP_SPREAD / total) if (SWEEP_SPREAD > 0 and total > 1) else 0.0
    if gap:
        dbg("PACE", f"staggering {total} dispatches ~{gap:.1f}s apart "
                    f"(~{SWEEP_SPREAD}s window)", C.MAGENTA)
        print(c(f"[INFO] Dispatching {total} measurements, "
                f"~{gap:.1f}s apart...", C.DIM))
    else:
        print(c(f"[INFO] Dispatching {total} concurrent measurements...", C.DIM))
    print()

    results = []
    pending = []
    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS, thread_name_prefix="probe") as pool:
        for i, route in enumerate(_ROUTES):
            if stop_event is not None and stop_event.is_set():
                dbg("PACE", "stop signalled mid-sweep - launching remainder now",
                    C.YELLOW)
                gap = 0.0
            dbg("LAUNCH", f"node {i + 1:>2}/{total} entering pool", C.BLUE)
            pending.append(pool.submit(measure_route, route, i + 1, total))

            # While waiting out the gap before the next launch, drain and print
            # any results that have already completed - keeps output flowing.
            deadline = time.perf_counter() + gap
            while True:
                _drain_done(pending, results, total)
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                time.sleep(min(0.25, remaining))

        dbg("POOL", f"all {total} tasks launched, awaiting stragglers", C.MAGENTA)
        # Collect whatever is left now that everything has been submitted.
        for future in concurrent.futures.as_completed(pending):
            res = future.result()
            results.append(res)
            dbg("COLLECT", f"{len(results)}/{total} results in", C.BLUE)
            _log_single(len(results), total, res)

    sweep_ms = (time.perf_counter() - t0) * 1000.0
    dbg("SWEEP", f"sweep #{sweep_num} finished in {sweep_ms:.2f}ms", C.MAGENTA)
    return _log_summary(results)


def _countdown(stop_event=None):
    """Sleep until the next sweep. Returns early if stop_event is set."""
    nxt = datetime.fromtimestamp(time.time() + RUN_INTERVAL).strftime("%H:%M:%S")
    print()
    print(c(f"[IDLE] Next sweep in {RUN_INTERVAL // 60} min (~{nxt}).", C.DIM))
    print(c("[IDLE] Engine sleeping to conserve resources... (Ctrl+C to stop)", C.DIM))
    rule()
    elapsed = 0
    while elapsed < RUN_INTERVAL:
        if stop_event is not None and stop_event.is_set():
            dbg("IDLE", "stop signalled during idle - exiting sweep loop", C.YELLOW)
            return
        time.sleep(1)
        elapsed += 1
        if elapsed % 15 == 0:
            remaining = RUN_INTERVAL - elapsed
            dbg("IDLE", f"sleeping... {remaining}s until next sweep "
                        f"({elapsed}s elapsed)", C.DIM)


# ---------------------------------------------------------------------------
# Entry point called by the host (multi.py)
# ---------------------------------------------------------------------------
def run(stop_event=None):
    """Run sweeps every 5 min until Ctrl+C or until stop_event is set.

    The host may pass a threading.Event as stop_event so it can interrupt the
    engine (e.g. to hot-swap a newer version) without killing the process. The
    event is checked between sweeps and during the idle wait, so a swap takes
    effect at the next safe boundary rather than mid-measurement.
    """
    print(c("  ╔" + "═" * 60 + "╗", C.CYAN))
    print(c("  ║" + "LATENCY DIAGNOSTIC ENGINE".center(60) + "║", C.CYAN + C.BOLD))
    print(c("  ╚" + "═" * 60 + "╝", C.CYAN))
    dbg("BOOT", f"latency engine v{ENGINE_VERSION} initialising", C.GREEN)
    print(f"[BOOT] Engine version  : {ENGINE_VERSION}")
    print(f"[BOOT] Target endpoint : {DISCORD_ENDPOINT}")
    print(f"[BOOT] Nodes loaded    : {len(_ROUTES)}")
    print(f"[BOOT] Concurrency     : up to {MAX_WORKERS} simultaneous measurements")
    print(f"[BOOT] Re-run interval : {RUN_INTERVAL}s ({RUN_INTERVAL // 60} min)")
    print(f"[BOOT] Debug logging   : {c('ENABLED', C.GREEN)}")
    if stop_event is not None:
        print(f"[BOOT] Hot-swap        : {c('SUPERVISED', C.GREEN)} (host watches for updates)")
    dbg("BOOT", f"python={sys.version.split()[0]}  pid={os.getpid()}", C.DIM)
    dbg("BOOT", f"requests=={requests.__version__}  workers={MAX_WORKERS}", C.DIM)
    print(c("[BOOT] Press Ctrl+C at any time to return to the main menu.", C.YELLOW))
    print()

    sweep_num = 0
    try:
        while True:                       # carries on forever
            if stop_event is not None and stop_event.is_set():
                break
            sweep_num += 1
            _sweep(sweep_num, stop_event)
            if stop_event is not None and stop_event.is_set():
                break
            _countdown(stop_event)
    except KeyboardInterrupt:
        print()
        dbg("STOP", "KeyboardInterrupt received, tearing down engine", C.YELLOW)
        print(c("\n[STOP] Latency engine halted.", C.YELLOW))
        time.sleep(0.5)
        raise   # let the host distinguish Ctrl+C (quit) from a hot-swap stop

    dbg("STOP", "stop_event set - yielding so host can hot-swap", C.YELLOW)
    print(c("\n[SWAP] Engine yielding for update...", C.YELLOW))


# Allow running the engine directly for local testing.
if __name__ == "__main__":
    if os.name == "nt":
        os.system("")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    run()
