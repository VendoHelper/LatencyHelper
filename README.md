# vendo

A clean, fast terminal multi-tool. Four utilities in one menu — latency
testing, file management, Discord webhooks, and archive malware scanning.

```
                          _
   __   __ ___  _ __    __| |  ___
   \ \ / // _ \| '_ \  / _` | / _ \
    \ V /|  __/| | | || (_| || (_) |
     \_/  \___||_| |_| \__,_| \___/

     multi-tool  -  v5.0.0
```

---

## Features

| Tool | What it does |
|------|--------------|
| **Latency Tester** | Measures round-trip latency across a pool of network routes and reports the fastest node. Streams live diagnostics and refreshes on a schedule. Updates itself from a remote source automatically. |
| **FileX** | A file manager: create, copy, move/rename, delete, browse folders, and inspect files (metadata + hexdump). |
| **WebhookSender** | Send messages, rich embeds (title, color, fields, images), file attachments, and raw JSON payloads to Discord webhooks. Includes a webhook inspector. |
| **LunarBreaker** | Scans `.zip` archives for malicious payloads — PowerShell droppers, hidden `.bat` autostarts, C2 endpoints, and more — checking file contents, names, comments, and raw bytes. |

---

## Requirements

- **Python 3.10+**
- [`requests`](https://pypi.org/project/requests/)

```bash
pip install requests
```

---

## Running

```bash
python multi.py
```

You'll get the main menu — press a number to launch a tool, `0` to exit.
`Ctrl+C` returns you to the menu from inside any tool.

```
  MAIN MENU

   [1] Latency Tester  - Discord latency helper
   [2] FileX           - File manager
   [3] WebhookSender   - Send messages & embeds to webhooks
   [4] LunarBreaker    - Scan an archive for malware
   [0] Exit
```

---

## Tool guide

### 1 · Latency Tester
Runs continuously, measuring response time over each route and highlighting the
lowest-latency node every cycle. The engine code (`latency_engine.py`) is
fetched from a remote URL at launch, so improvements roll out to everyone
without re-downloading the tool. If the remote source is unreachable, it falls
back to the bundled local copy.

### 2 · FileX
- **Create** a file with typed multi-line content
- **Copy** / **Move / rename** / **Delete** files
- **Browse** a folder with sizes and timestamps
- **Inspect** a file — size, modified time, SHA-256, type guess, and a hexdump

### 3 · WebhookSender
- **Message** — text with optional username, avatar, and TTS
- **Embeds** — full builder: title, description, color (name/hex/decimal),
  author, footer, thumbnail, image, timestamp, and up to 25 fields
- **File attachment** — upload any file with an optional message
- **Raw JSON** — paste a payload for full control
- **From file** — load a `.json` payload from disk
- **Inspect** — verify a webhook and show its channel/guild

All sends are validated client-side against Discord's limits and report clear
errors (rate limits, 404/401, validation failures).

### 4 · LunarBreaker
Point it at a `.zip` (local path or URL). It reads every byte — including the
archive comment and any data appended after the central directory, which is a
common malware hiding spot — and matches against a signature set of known
malicious behaviours. Produces a threat score, a verdict, and a detailed
breakdown with hexdumps of each detection.

> LunarBreaker is a heuristic scanner. A clean result is not a guarantee of
> safety, and it does not replace a full antivirus.

---

## Configuration

Settings live in the `CONFIG` block near the top of `multi.py`:

```python
CONFIG = AppConfig(
    update=UpdateConfig(
        url="https://raw.githubusercontent.com/VendoHelper/LatencyHelper/main/latency_engine.py",
        require_signature=False,
    )
)
```

- **`url`** — raw URL of the hosted `latency_engine.py`. 

### Pushing an update

The Latency Tester pulls its engine from the URL above, so to update everyone:

1. Edit `latency_engine.py`
2. Upload it to your repo

Running instances pick up the new version automatically (allow a few minutes
for GitHub's CDN cache).



---

## Project layout

```
multi.py            The multi-tool (menu + all four tools + update loader)
latency_engine.py   The Latency Tester engine (hosted remotely for updates)
```

---

## Notes

- Works on Windows, macOS, and Linux. ANSI colors and UTF-8 are enabled
  automatically; set `NO_COLOR=1` to disable colors.
