# Clip Sanitizer

![License](https://img.shields.io/badge/license-MIT-blue.svg)

Windows tray app: select text anywhere, press `Ctrl+Alt+C`, and a sanitized copy
is on the clipboard, ready to paste into a ticket, chat, or email.

Emails, IPs, passwords, tokens, keys, user names, and similar values are replaced
with placeholders such as `<EMAIL>` or `<HASHED_PASSWORD_3F2A…>`.

Uses the same patterns and `config.json` format as
[Log Sanitizer](https://github.com/MoshikoKar/LogSanitizer), ported to Rust (Tauri 2).

Repository: [https://github.com/MoshikoKar/ClipSanitizer](https://github.com/MoshikoKar/ClipSanitizer)

## Description

Clip Sanitizer runs in the system tray and exposes a global hotkey that copies the
current selection (or falls back to clipboard text), runs it through a local
sanitizing engine, and puts the cleaned text back on the clipboard. A small
notification reports what was replaced. Nothing is logged or sent anywhere.

## Installation

### Requirements

- Rust (MSVC toolchain)
- Visual Studio C++ Build Tools
- WebView2 (included with Windows 10/11)

There is no Node.js step: the UI in `ui/` is plain HTML, CSS, and JS embedded into
the executable.

### Build from source

```powershell
git clone https://github.com/MoshikoKar/ClipSanitizer.git
cd ClipSanitizer\src-tauri
cargo test
cargo build --release
```

The release binary is `src-tauri\target\release\clip-sanitizer.exe` (single portable
exe).

Optional NSIS installer: install Tauri CLI (`cargo install tauri-cli --version "^2"`),
then run `cargo tauri build` in `src-tauri`.

## Usage

| Action | What happens |
|---|---|
| Select text, press **Ctrl+Alt+C** | Selection is copied, sanitized, and put on the clipboard. A notification shows what was replaced. |
| Press **Ctrl+Alt+C** with nothing selected | Text already on the clipboard is sanitized instead. |
| Tray → **Sanitize clipboard now** | Same as the hotkey, without pressing it. |
| Tray → **Pause hotkey** | Temporarily disables the global hotkey. |
| Click the tray icon (or **Open Clip Sanitizer**) | Opens the window: paste or type text, press **Sanitize** (Ctrl+Enter), review the highlighted result, **Copy**. |

The window also lets you switch individual patterns on or off. **Settings** covers:

- change the hotkey (click the field and press the new combination)
- *Also paste over the selection*, which replaces the selected text in place
- notifications on or off
- start with Windows
- which patterns file to use

Closing the window keeps the app running in the tray. Use **Quit** from the tray
menu to exit.

### Debug run

```powershell
cd src-tauri
cargo run
```

### Patterns

- Built-in patterns match Log Sanitizer: secrets, tokens and keys, emails, IPs,
  IPv6, MAC addresses, GUIDs, SIDs, card numbers, AD/LDAP attributes, and user
  and host names.
- Custom patterns live in a JSON file in
  [Log Sanitizer format](https://github.com/MoshikoKar/LogSanitizer). Default path:
  `%APPDATA%\app.clipsanitizer\patterns.json`. Use **Edit patterns file** in the
  tray menu or Settings, then **Reload patterns**.
- To share one config with Log Sanitizer, set *Patterns file* in Settings to its
  `config.json`.
- Regex syntax is Python-compatible via
  [fancy-regex](https://docs.rs/fancy-regex) (lookbehind/lookahead, named groups,
  `(?i)`, `\1` replacements). A runaway regex stops at a backtracking limit.

### Security notes

- Sanitized text is marked to exclude from clipboard history and cloud clipboard
  (does not show in Win+V).
- The original copy from a selection is a normal copy. If Windows clipboard
  history or cloud sync is on, the unsanitized original may be retained. Turn
  these off in *Settings → System → Clipboard* when sanitizing real secrets.
- Hashes use HMAC-SHA256 with a new random key per hotkey press.
- Settings live in `%APPDATA%\app.clipsanitizer\settings.json`.
- Troubleshooting: set `CLIP_SANITIZER_DEBUG=1` before start to log hotkey timing
  to `%APPDATA%\app.clipsanitizer\debug.log` (clipboard contents are never logged).
- Admin windows: a normal app cannot send Ctrl+C to elevated programs. Copy first,
  then use the hotkey, or run Clip Sanitizer as administrator.

## Features

- Global hotkey sanitize (selection or clipboard fallback)
- System tray with pause, sanitize-now, and settings entry points
- In-app sanitize window with pattern toggles and highlighted output
- Shared Log Sanitizer pattern / config format
- Portable release exe; optional NSIS installer via Tauri

## Tech Stack

- Rust 2021
- Tauri 2 (tray, global shortcut, autostart, single-instance)
- fancy-regex, arboard, windows-sys
- Plain HTML / CSS / JS UI (`ui/`)

## Project layout

```text
ui/                    window + notification (HTML/CSS/JS, no build step)
src-tauri/
  src/engine.rs        sanitizing engine + tests (port of log_sanitizer.py)
  src/win.rs           Win32 helpers (keys, clipboard, notification)
  src/main.rs          tray, hotkey flow, settings, UI commands
  tauri.conf.json      windows and bundle settings
  icons/               app / tray icons
```

## License

MIT - see the `LICENSE` file for details.

## Credits

Pattern format and behavior inspired by
[Log Sanitizer](https://github.com/MoshikoKar/LogSanitizer).
