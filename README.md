# Clip Sanitizer

[https://github.com/MoshikoKar/ClipSanitizer](https://github.com/MoshikoKar/ClipSanitizer)

A Windows tray app: **select text anywhere, press `Ctrl+Alt+C`, and a sanitized copy is on the clipboard**, ready to paste into a ticket, chat or email.
Emails, IPs, passwords, tokens, keys, user names and the like are replaced with placeholders such as `<EMAIL>` or `<HASHED_PASSWORD_3F2A…>`.

It uses the same patterns and `config.json` format as [Log Sanitizer](https://github.com/MoshikoKar/LogSanitizer), ported to Rust (Tauri 2).

## Using it
| Action | What happens |
|---|---|
| Select text, press **Ctrl+Alt+C** | The selection is copied, sanitized, and put on the clipboard. A small notification shows what was replaced. |
| Press **Ctrl+Alt+C** with nothing selected | The text already on the clipboard is sanitized instead. |
| Tray → **Sanitize clipboard now** | Same as above, without the hotkey. |
| Tray → **Pause hotkey** | Temporarily disables the global hotkey. |
| Click the tray icon (or **Open Clip Sanitizer**) | Opens the window: paste or type text, press **Sanitize** (Ctrl+Enter), review the highlighted result, **Copy**. |

The window also lets you switch individual patterns on or off. **Settings** covers:
- change the hotkey (click the field and press the new combination);
- *Also paste over the selection*, which replaces the selected text in place;
- notifications on or off;
- start with Windows;
- which patterns file to use.

Closing the window keeps the app running in the tray. Use **Quit** from the tray menu to exit.

## Patterns
- The built-in patterns match those in Log Sanitizer: secrets, tokens and keys, emails, IPs, IPv6, MAC addresses, GUIDs, SIDs, card numbers, AD/LDAP attributes, and user and host names.
- Custom patterns live in a JSON file in [Log Sanitizer format](https://github.com/MoshikoKar/LogSanitizer). By default this is `%APPDATA%\app.clipsanitizer\patterns.json`. Use **Edit patterns file** in the tray menu or Settings, then **Reload patterns**.
- To share one config with Log Sanitizer, set *Patterns file* in Settings to its `config.json`.
- Regex syntax is Python-compatible, using the [fancy-regex](https://docs.rs/fancy-regex) crate. It supports lookbehind and lookahead, `(?P<name>…)` groups, `(?i)` and `\1` replacements.
- A runaway regex stops at a backtracking limit and is reported, so it cannot freeze the app.

## Security notes
- **The sanitized text** is put on the clipboard marked *exclude from clipboard history and cloud clipboard*, so it does not show up in Win+V.
- **The original copy** made from your selection is a normal copy. If Windows clipboard history (Win+V) or cloud clipboard sync is on, the unsanitized original may be kept there. Turn these off in *Settings → System → Clipboard* if you sanitize real secrets.
- **Hashes** use HMAC-SHA256 with a new random key for every hotkey press. The same value gets the same token within one sanitize, but tokens cannot be linked across presses.
- Nothing is logged or sent anywhere. Settings are stored in `%APPDATA%\app.clipsanitizer\settings.json`.
- **Troubleshooting:** set the environment variable `CLIP_SANITIZER_DEBUG=1` before starting the app to log hotkey timing and key state to `%APPDATA%\app.clipsanitizer\debug.log`. Clipboard contents are never logged.
- **Admin windows:** Windows does not let a normal app send Ctrl+C to programs running as administrator. In those windows, copy first and then use the hotkey (it falls back to the clipboard), or run Clip Sanitizer as administrator.

## Build
Requirements: Rust (MSVC toolchain), the Visual Studio C++ Build Tools, and WebView2 (already part of Windows 10/11).
There is no Node.js step: the UI in `ui/` is plain HTML, CSS and JS that gets embedded into the exe.

```powershell
cd src-tauri
cargo test                     # engine tests
cargo run                      # debug build, opens the window
cargo build --release          # -> src-tauri\target\release\clip-sanitizer.exe (single portable exe)
```

Optional installer (NSIS): `cargo install tauri-cli --version "^2"`, then run `cargo tauri build` in `src-tauri`.

## Project layout
```
ui/                    window + notification (HTML/CSS/JS, no build step)
src-tauri/
  src/engine.rs        sanitizing engine + tests (port of log_sanitizer.py)
  src/win.rs           Win32: key simulation, clipboard change detection, no-focus notification
  src/main.rs          tray, hotkey flow, settings, commands used by the UI
  tauri.conf.json      windows, bundle settings
  icons/               app / tray icon
```
