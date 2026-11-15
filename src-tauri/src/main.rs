// Release builds are GUI-only (no console window).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod update;
mod win;

use engine::{Engine, PatternInfo, SanitizeResult};
use update::{UpdateChannel, auto_check_delay, current_version, run_auto_check, run_manual_check};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent, Wry};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};

const TOAST_MS: u64 = 2800;

// ----------------------------------------------------------------------------- settings

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
struct Settings {
    hotkey: String,
    /// After sanitizing, also press Ctrl+V so the selection is replaced in place.
    paste_after: bool,
    show_toast: bool,
    /// Pattern config in Log Sanitizer format; empty = patterns.json in the app config folder.
    patterns_file: String,
    /// Patterns switched off in the UI.
    disabled: Vec<String>,
    /// Automatic GitHub Releases update checks (manual tray check always works).
    check_updates: bool,
    /// `stable` (releases/latest) or `beta` (newest non-draft, including prereleases).
    update_channel: String,
    /// Last update version the user dismissed (skip auto-prompt until a different version).
    dismissed_update_version: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            hotkey: "Ctrl+Alt+C".into(),
            paste_after: false,
            show_toast: true,
            patterns_file: String::new(),
            disabled: vec![],
            check_updates: true,
            update_channel: "stable".into(),
            dismissed_update_version: String::new(),
        }
    }
}

struct AppState {
    engine: Mutex<Engine>,
    settings: Mutex<Settings>,
    load_message: Mutex<String>,
    toast_gen: AtomicU64,
    busy: AtomicBool,
    paused: AtomicBool,
}

struct TrayItems {
    pause: CheckMenuItem<Wry>,
    autostart: CheckMenuItem<Wry>,
}

fn config_dir(app: &AppHandle) -> PathBuf {
    let dir = app.path().app_config_dir().unwrap_or_else(|_| PathBuf::from("."));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn settings_path(app: &AppHandle) -> PathBuf {
    config_dir(app).join("settings.json")
}

fn patterns_path(app: &AppHandle, s: &Settings) -> PathBuf {
    if s.patterns_file.trim().is_empty() {
        config_dir(app).join("patterns.json")
    } else {
        PathBuf::from(s.patterns_file.trim())
    }
}

fn load_settings(app: &AppHandle) -> Settings {
    std::fs::read_to_string(settings_path(app)).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_settings_file(app: &AppHandle, s: &Settings) -> Result<(), String> {
    let json = serde_json::to_string_pretty(s).map_err(|e| e.to_string())?;
    std::fs::write(settings_path(app), json).map_err(|e| format!("Could not save settings: {e}"))
}

/// Built-ins + the patterns file + the UI's disabled list.
fn build_engine(app: &AppHandle, s: &Settings) -> (Engine, String) {
    let mut engine = Engine::default();
    let path = patterns_path(app, s);
    if !path.exists() && s.patterns_file.trim().is_empty() {
        let starter = "{\n  \"patterns\": []\n}\n";
        let _ = std::fs::write(&path, starter);
    }
    let msg = match std::fs::read_to_string(&path) {
        Ok(json) => match engine.load_config_str(&json) {
            Ok(m) => format!("{m} from {}", path.display()),
            Err(e) => format!("Patterns file not loaded: {e}"),
        },
        Err(e) => format!("Patterns file not loaded ({}): {e}", path.display()),
    };
    for name in &s.disabled {
        engine.set_enabled(name, false);
    }
    (engine, msg)
}

// ----------------------------------------------------------------------------- clipboard

/// Read clipboard text, retrying while the clipboard is locked or (right after a copy)
/// the source app has not finished providing the text yet.
fn read_clipboard_text() -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..12 {
        match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
            Ok(t) => return Ok(t),
            Err(arboard::Error::ContentNotAvailable) => last = "The clipboard has no text".into(),
            Err(e) => last = format!("Could not read the clipboard: {e}"),
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    Err(last)
}

/// Write text that is kept out of Win+V clipboard history and cloud clipboard sync.
fn write_clipboard_text(text: &str) -> Result<(), String> {
    use arboard::SetExtWindows;
    let mut last = String::new();
    for _ in 0..8 {
        match arboard::Clipboard::new().and_then(|mut c| c.set().exclude_from_history().exclude_from_cloud().text(text)) {
            Ok(()) => return Ok(()),
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    Err(format!("Could not write the clipboard: {last}"))
}

/// Opt-in troubleshooting log (set CLIP_SANITIZER_DEBUG=1). Never records clipboard contents.
fn debug_log(app: &AppHandle, msg: &str) {
    if std::env::var_os("CLIP_SANITIZER_DEBUG").is_none() {
        return;
    }
    use std::io::Write;
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(config_dir(app).join("debug.log")) {
        let _ = writeln!(f, "{ms} {msg}");
    }
}

fn fresh_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    getrandom::getrandom(&mut salt).expect("OS random generator");
    salt
}

// ----------------------------------------------------------------------------- toast

#[derive(Serialize, Clone)]
struct Toast {
    kind: &'static str, // "ok" | "info" | "error"
    title: String,
    body: String,
}

fn toast(app: &AppHandle, kind: &'static str, title: impl Into<String>, body: impl Into<String>) {
    let state = app.state::<AppState>();
    if !state.settings.lock().unwrap().show_toast && kind != "error" {
        return;
    }
    let Some(win) = app.get_webview_window("toast") else { return };
    let _ = app.emit_to("toast", "toast", Toast { kind, title: title.into(), body: body.into() });
    let generation = state.toast_gen.fetch_add(1, Ordering::SeqCst) + 1;
    let (Ok(hwnd), Ok(size)) = (win.hwnd(), win.outer_size()) else { return };
    let hwnd = hwnd.0 as isize;
    win::show_toast_window(hwnd, size.width as i32, size.height as i32);
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(TOAST_MS));
        if app.state::<AppState>().toast_gen.load(Ordering::SeqCst) == generation {
            win::hide_window(hwnd);
        }
    });
}

fn summary(result: &SanitizeResult) -> String {
    if result.total == 0 {
        return "Nothing sensitive found - text copied unchanged".into();
    }
    let top: Vec<String> = result.counts.iter().take(4).map(|(n, c)| format!("{n} {c}")).collect();
    top.join(" · ")
}

// ----------------------------------------------------------------------------- hotkey flow

/// Copy the current selection (Ctrl+C in the active app), sanitize it and put the result on the
/// clipboard. If nothing gets copied, the existing clipboard text is sanitized instead.
fn sanitize_flow(app: &AppHandle, copy_selection: bool) {
    let state = app.state::<AppState>();
    if state.busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let outcome = (|| -> Result<(SanitizeResult, bool), String> {
        let mut from_selection = false;
        if copy_selection {
            let vk = hotkey_vk(&state);
            debug_log(app, &format!("hotkey: held at start {:?}", win::held_keys(Some(vk))));
            win::wait_keys_released(Some(vk), Duration::from_millis(1500));
            let before = win::clipboard_seq();
            win::send_ctrl(b'C');
            from_selection = win::wait_clipboard_change(before, Duration::from_millis(700));
            debug_log(app, &format!("hotkey: keys released, ctrl+c sent, clipboard changed={from_selection}"));
            std::thread::sleep(Duration::from_millis(30)); // let the source app finish writing
        }
        let text = read_clipboard_text()?;
        if text.trim().is_empty() {
            return Err("Nothing to sanitize - select some text first".into());
        }
        let result = state.engine.lock().unwrap().sanitize(&text, &fresh_salt());
        write_clipboard_text(&result.text)?;
        if copy_selection && from_selection && state.settings.lock().unwrap().paste_after {
            std::thread::sleep(Duration::from_millis(30));
            win::send_ctrl(b'V');
            debug_log(app, "hotkey: ctrl+v sent");
        }
        Ok((result, from_selection))
    })();
    state.busy.store(false, Ordering::SeqCst);

    match outcome {
        Ok((result, from_selection)) => {
            let title = match (result.total, from_selection || !copy_selection) {
                (0, _) => "Copied - nothing to redact".to_string(),
                (n, true) => format!("Sanitized {n} value{} · ready to paste", if n == 1 { "" } else { "s" }),
                (n, false) => format!("No selection - sanitized clipboard ({n})"),
            };
            let mut body = summary(&result);
            if !result.warnings.is_empty() {
                body = format!("{body} | {}", result.warnings.join("; "));
            }
            toast(app, if result.total > 0 { "ok" } else { "info" }, title, body);
            let _ = app.emit_to("main", "sanitized", &result);
        }
        Err(e) => toast(app, "error", "Clip Sanitizer", e),
    }
}

/// Virtual-key code of the hotkey's main key (so we can wait for it to be released).
fn hotkey_vk(state: &State<AppState>) -> u16 {
    let hk = state.settings.lock().unwrap().hotkey.clone();
    let last = hk.rsplit('+').next().unwrap_or("").trim().to_uppercase();
    let last = last.trim_start_matches("KEY").trim_start_matches("DIGIT");
    match last.as_bytes() {
        [c] if c.is_ascii_alphanumeric() => *c as u16,
        _ => 0,
    }
}

fn register_hotkey(app: &AppHandle, hotkey: &str) -> Result<(), String> {
    let shortcut: Shortcut = hotkey.parse().map_err(|e| format!("Invalid hotkey '{hotkey}': {e}"))?;
    let gs = app.global_shortcut();
    let _ = gs.unregister_all();
    gs.register(shortcut).map_err(|e| format!("Could not register {hotkey} (maybe used by another app): {e}"))
}

// ----------------------------------------------------------------------------- windows & tray

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
        let _ = app.emit_to("main", "state-changed", ()); // refresh hotkey, patterns, autostart state
    }
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let hotkey = app.state::<AppState>().settings.lock().unwrap().hotkey.clone();
    let autostart_on = app.autolaunch().is_enabled().unwrap_or(false);
    let pause = CheckMenuItem::with_id(app, "pause", "Pause hotkey", true, false, None::<&str>)?;
    let autostart = CheckMenuItem::with_id(app, "autostart", "Start with Windows", true, autostart_on, None::<&str>)?;
    let menu = Menu::with_items(app, &[
        &MenuItem::with_id(app, "open", "Open Clip Sanitizer", true, None::<&str>)?,
        &MenuItem::with_id(app, "clipboard", "Sanitize clipboard now", true, None::<&str>)?,
        &PredefinedMenuItem::separator(app)?,
        &pause,
        &autostart,
        &MenuItem::with_id(app, "patterns", "Edit patterns file…", true, None::<&str>)?,
        &MenuItem::with_id(app, "reload", "Reload patterns", true, None::<&str>)?,
        &MenuItem::with_id(
            app,
            "check_updates",
            format!("Check for updates (v{})", current_version().display()),
            true,
            None::<&str>,
        )?,
        &PredefinedMenuItem::separator(app)?,
        &MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?,
    ])?;
    app.manage(TrayItems { pause, autostart });

    TrayIconBuilder::with_id("tray")
        .icon(app.default_window_icon().cloned().expect("app icon"))
        .tooltip(format!("Clip Sanitizer - select text and press {hotkey}"))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "clipboard" => {
                let app = app.clone();
                std::thread::spawn(move || sanitize_flow(&app, false));
            }
            "pause" => {
                let items = app.state::<TrayItems>();
                let paused = items.pause.is_checked().unwrap_or(false);
                app.state::<AppState>().paused.store(paused, Ordering::SeqCst);
                let _ = app.emit_to("main", "state-changed", ());
            }
            "autostart" => {
                let on = app.state::<TrayItems>().autostart.is_checked().unwrap_or(false);
                let _ = if on { app.autolaunch().enable() } else { app.autolaunch().disable() };
                let _ = app.emit_to("main", "state-changed", ());
            }
            "patterns" => {
                let _ = open_patterns_file(app.clone(), app.state::<AppState>());
            }
            "reload" => {
                if let Ok(view) = reload_patterns(app.clone(), app.state::<AppState>()) {
                    toast(app, "info", "Patterns reloaded", view.load_message);
                    let _ = app.emit_to("main", "state-changed", ());
                }
            }
            "check_updates" => {
                let app = app.clone();
                std::thread::spawn(move || run_update_check(&app, true));
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

// ----------------------------------------------------------------------------- commands (UI)

#[derive(Serialize)]
struct StateView {
    hotkey: String,
    paste_after: bool,
    show_toast: bool,
    patterns_file: String,
    patterns_path: String,
    autostart: bool,
    paused: bool,
    check_updates: bool,
    update_channel: String,
    load_message: String,
    patterns: Vec<PatternInfo>,
}

fn view(app: &AppHandle, state: &State<AppState>) -> StateView {
    let s = state.settings.lock().unwrap().clone();
    StateView {
        patterns_path: patterns_path(app, &s).display().to_string(),
        hotkey: s.hotkey,
        paste_after: s.paste_after,
        show_toast: s.show_toast,
        patterns_file: s.patterns_file,
        autostart: app.autolaunch().is_enabled().unwrap_or(false),
        paused: state.paused.load(Ordering::SeqCst),
        check_updates: s.check_updates,
        update_channel: s.update_channel,
        load_message: state.load_message.lock().unwrap().clone(),
        patterns: state.engine.lock().unwrap().patterns(),
    }
}

#[tauri::command]
fn get_state(app: AppHandle, state: State<AppState>) -> StateView {
    view(&app, &state)
}

#[tauri::command]
fn sanitize_text(text: String, state: State<AppState>) -> SanitizeResult {
    state.engine.lock().unwrap().sanitize(&text, &fresh_salt())
}

#[tauri::command]
fn copy_text(text: String) -> Result<(), String> {
    write_clipboard_text(&text)
}

#[tauri::command]
fn paste_text() -> Result<String, String> {
    read_clipboard_text()
}

#[tauri::command]
fn set_pattern_enabled(name: String, enabled: bool, app: AppHandle, state: State<AppState>) -> Result<(), String> {
    state.engine.lock().unwrap().set_enabled(&name, enabled);
    let mut s = state.settings.lock().unwrap();
    s.disabled.retain(|n| n != &name);
    if !enabled {
        s.disabled.push(name);
    }
    save_settings_file(&app, &s)
}

#[derive(Deserialize)]
struct SettingsInput {
    hotkey: String,
    paste_after: bool,
    show_toast: bool,
    patterns_file: String,
    autostart: bool,
    check_updates: bool,
    update_channel: String,
}

#[tauri::command]
fn save_settings(input: SettingsInput, app: AppHandle, state: State<AppState>) -> Result<StateView, String> {
    let old = state.settings.lock().unwrap().clone();
    if input.hotkey != old.hotkey {
        if let Err(e) = register_hotkey(&app, &input.hotkey) {
            let _ = register_hotkey(&app, &old.hotkey);
            return Err(e);
        }
    }
    let mut new = old.clone();
    new.hotkey = input.hotkey;
    new.paste_after = input.paste_after;
    new.show_toast = input.show_toast;
    new.patterns_file = input.patterns_file.trim().to_string();
    new.check_updates = input.check_updates;
    new.update_channel = match input.update_channel.trim().to_ascii_lowercase().as_str() {
        "beta" => "beta".into(),
        _ => "stable".into(),
    };
    save_settings_file(&app, &new)?;
    let reload = new.patterns_file != old.patterns_file;
    *state.settings.lock().unwrap() = new.clone();
    if reload {
        let (engine, msg) = build_engine(&app, &new);
        *state.engine.lock().unwrap() = engine;
        *state.load_message.lock().unwrap() = msg;
    }
    let _ = if input.autostart { app.autolaunch().enable() } else { app.autolaunch().disable() };
    if let Some(items) = app.try_state::<TrayItems>() {
        let _ = items.autostart.set_checked(input.autostart);
    }
    if let Some(tray) = app.tray_by_id("tray") {
        let _ = tray.set_tooltip(Some(format!("Clip Sanitizer - select text and press {}", new.hotkey)));
    }
    Ok(view(&app, &state))
}

fn run_update_check(app: &AppHandle, manual: bool) {
    let state = app.state::<AppState>();
    let (channel, dismissed, enabled) = {
        let s = state.settings.lock().unwrap();
        (
            UpdateChannel::parse(&s.update_channel),
            s.dismissed_update_version.clone(),
            s.check_updates,
        )
    };
    if !manual && !enabled {
        return;
    }
    let outcome = if manual {
        run_manual_check(channel)
    } else {
        run_auto_check(channel, &dismissed)
    };
    if let Some(ver) = outcome.dismissed_version {
        let mut s = state.settings.lock().unwrap();
        s.dismissed_update_version = ver;
        let _ = save_settings_file(app, &s);
    }
    if outcome.should_exit {
        app.exit(0);
    }
}

#[tauri::command]
fn reload_patterns(app: AppHandle, state: State<AppState>) -> Result<StateView, String> {
    let s = state.settings.lock().unwrap().clone();
    let (engine, msg) = build_engine(&app, &s);
    *state.engine.lock().unwrap() = engine;
    *state.load_message.lock().unwrap() = msg;
    Ok(view(&app, &state))
}

#[tauri::command]
fn open_patterns_file(app: AppHandle, state: State<AppState>) -> Result<(), String> {
    let path = patterns_path(&app, &state.settings.lock().unwrap());
    // notepad always exists and handles .json; explorer would depend on file associations
    std::process::Command::new("notepad.exe").arg(path).spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[tauri::command]
fn show_main_window(app: AppHandle) {
    show_main(&app);
}

// ----------------------------------------------------------------------------- main

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec!["--background"])))
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    if event.state == ShortcutState::Pressed && !app.state::<AppState>().paused.load(Ordering::SeqCst) {
                        debug_log(app, "hotkey: event received");
                        let app = app.clone();
                        std::thread::spawn(move || sanitize_flow(&app, true));
                    }
                })
                .build(),
        )
        .setup(|app| {
            let handle = app.handle().clone();
            let settings = load_settings(&handle);
            let (engine, msg) = build_engine(&handle, &settings);
            let hotkey = settings.hotkey.clone();
            app.manage(AppState {
                engine: Mutex::new(engine),
                settings: Mutex::new(settings),
                load_message: Mutex::new(msg),
                toast_gen: AtomicU64::new(0),
                busy: AtomicBool::new(false),
                paused: AtomicBool::new(false),
            });
            build_tray(&handle)?;
            match register_hotkey(&handle, &hotkey) {
                Ok(()) => toast(&handle, "info", "Clip Sanitizer is running",
                                format!("Select text anywhere and press {hotkey}")),
                Err(e) => {
                    toast(&handle, "error", "Hotkey not available", e);
                    show_main(&handle);
                }
            }
            if !std::env::args().any(|a| a == "--background") && cfg!(debug_assertions) {
                show_main(&handle);
            }
            {
                let app = handle.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(auto_check_delay());
                    run_update_check(&app, false);
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the main window only hides it; the app keeps running in the tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state, sanitize_text, copy_text, paste_text, set_pattern_enabled, save_settings,
            reload_patterns, open_patterns_file, show_main_window
        ])
        .run(tauri::generate_context!())
        .expect("error while running Clip Sanitizer");
}
