//! Verified GitHub Releases updater (Windows Widget Standard contract).
//!
//! Check → ask → download `SHA256SUMS.txt` + asset → verify SHA-256 → install/swap.
//! Uses `curl.exe` / `certutil.exe` (no extra HTTP crates). No tokens in the client.

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Detected from this project's git remote / `gh repo view` (not a skill default).
const REPO: &str = "MoshikoKar/ClipSanitizer";
const APP_NAME: &str = "ClipSanitizer";
const SETUP_ASSET: &str = "ClipSanitizer-Setup.exe";
const PORTABLE_ASSET: &str = "ClipSanitizer-portable.zip";
const SUMS_ASSET: &str = "SHA256SUMS.txt";

const CREATE_NO_WINDOW: u32 = 0x08000000;
const CURL_TIMEOUT_SECS: u64 = 30;
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;

static CHECK_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Pre-release label without leading `-` (e.g. `beta.1`), or empty for a final release.
    pub pre: String,
}

impl Version {
    pub fn parse(raw: &str) -> Option<Self> {
        let s = raw.trim().trim_start_matches('v');
        if s.is_empty() {
            return None;
        }
        let (core, pre) = match s.split_once('-') {
            Some((c, p)) => (c, p.to_string()),
            None => (s, String::new()),
        };
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self { major, minor, patch, pre })
    }

    /// Numeric semver: higher major/minor/patch wins; a release beats its own pre-release.
    pub fn cmp_semver(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)) {
            Ordering::Equal => match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (true, true) => Ordering::Equal,
                (false, false) => self.pre.cmp(&other.pre),
            },
            ord => ord,
        }
    }

    pub fn is_newer_than(&self, current: &Self) -> bool {
        self.cmp_semver(current) == std::cmp::Ordering::Greater
    }

    pub fn display(&self) -> String {
        if self.pre.is_empty() {
            format!("{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            format!("{}.{}.{}-{}", self.major, self.minor, self.patch, self.pre)
        }
    }
}

#[derive(Debug, Clone)]
pub struct AvailableUpdate {
    pub version: Version,
    pub notes: String,
    pub html_url: String,
    pub asset_name: String,
    pub asset_url: String,
    pub sums_url: String,
}

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    body: Option<String>,
    html_url: String,
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateChannel {
    Stable,
    Beta,
}

impl UpdateChannel {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "beta" => Self::Beta,
            _ => Self::Stable,
        }
    }
}

/// True when an installer uninstaller sits next to the running exe (Inno or NSIS).
pub fn is_installed_mode() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let Some(dir) = exe.parent() else {
        return false;
    };
    dir.join("unins000.exe").is_file() || dir.join("uninstall.exe").is_file()
}

pub fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("CARGO_PKG_VERSION is valid semver")
}

/// Look up a SHA-256 hex digest for `asset_name` inside a `SHA256SUMS.txt` body.
pub fn checksum_for_asset(sums_body: &str, asset_name: &str) -> Option<String> {
    for line in sums_body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, name) = if let Some((h, rest)) = line.split_once(char::is_whitespace) {
            let name = rest.trim().trim_start_matches('*').trim();
            (h.trim(), name)
        } else {
            continue;
        };
        if name.eq_ignore_ascii_case(asset_name) && is_sha256_hex(hash) {
            return Some(hash.to_ascii_lowercase());
        }
    }
    None
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn asset_name_for_mode(installed: bool) -> &'static str {
    if installed {
        SETUP_ASSET
    } else {
        PORTABLE_ASSET
    }
}

fn pick_release(releases: &[GhRelease], channel: UpdateChannel) -> Option<&GhRelease> {
    let candidates: Vec<_> = releases.iter().filter(|r| !r.draft).collect();
    match channel {
        UpdateChannel::Stable => candidates.into_iter().find(|r| !r.prerelease),
        UpdateChannel::Beta => {
            let mut best: Option<&GhRelease> = None;
            for r in candidates {
                let Some(v) = Version::parse(&r.tag_name) else {
                    continue;
                };
                match best {
                    None => best = Some(r),
                    Some(cur) => {
                        if let Some(cv) = Version::parse(&cur.tag_name) {
                            if v.is_newer_than(&cv) {
                                best = Some(r);
                            }
                        }
                    }
                }
            }
            best
        }
    }
}

fn release_to_update(rel: &GhRelease, installed: bool) -> Result<AvailableUpdate, String> {
    let version = Version::parse(&rel.tag_name)
        .ok_or_else(|| format!("Release tag '{}' is not valid semver", rel.tag_name))?;
    let want = asset_name_for_mode(installed);
    let asset = rel
        .assets
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(want))
        .ok_or_else(|| format!("Release {} has no asset named {want}", rel.tag_name))?;
    let sums = rel
        .assets
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case(SUMS_ASSET))
        .ok_or_else(|| format!("Release {} is missing {SUMS_ASSET}", rel.tag_name))?;
    Ok(AvailableUpdate {
        version,
        notes: rel.body.clone().unwrap_or_default(),
        html_url: rel.html_url.clone(),
        asset_name: asset.name.clone(),
        asset_url: asset.browser_download_url.clone(),
        sums_url: sums.browser_download_url.clone(),
    })
}

fn curl_get(url: &str, timeout_secs: u64) -> Result<Vec<u8>, String> {
    // No -f: capture body + trailing HTTP status so private-repo 404s are not
    // misreported as a missing release when the caller is simply unauthenticated.
    let mut cmd = Command::new("curl.exe");
    cmd.args([
        "-sSL",
        "--max-time",
        &timeout_secs.to_string(),
        "-A",
        &format!("{APP_NAME}-updater/{}", env!("CARGO_PKG_VERSION")),
        "-H",
        "Accept: application/vnd.github+json",
        "-w",
        "\n%{http_code}",
        url,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().map_err(|e| format!("Could not run curl.exe: {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let code = out.status.code().unwrap_or(-1);
        return Err(format!("Update check failed (curl exit {code}): {}", err.trim()));
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    let (body, status) = split_curl_http_status(&raw)
        .ok_or_else(|| "Update check failed: could not read HTTP status from curl".to_string())?;
    match status {
        200 => Ok(body.as_bytes().to_vec()),
        403 | 429 => Err(
            "Update check rate-limited or forbidden by GitHub; try again later".into(),
        ),
        404 => Err(format!(
            "Cannot read GitHub Releases for {REPO}.\n\n\
             The repository is private or has no public releases, so the updater \
             cannot check without a token (tokens are never embedded in the app).\n\n\
             Make the repository public, then try again."
        )),
        other => Err(format!("Update check failed (HTTP {other}).")),
    }
}

/// Split `curl -w "\\n%{{http_code}}"` output into body and status code.
fn split_curl_http_status(raw: &str) -> Option<(String, u16)> {
    let raw = raw.trim_end_matches(['\r', '\n']);
    let (body, code_str) = raw.rsplit_once('\n')?;
    let status: u16 = code_str.trim().parse().ok()?;
    Some((body.to_string(), status))
}

fn curl_download(url: &str, dest: &Path) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Could not create download dir: {e}"))?;
    }
    let mut cmd = Command::new("curl.exe");
    cmd.args([
        "-fsSL",
        "--max-time",
        &DOWNLOAD_TIMEOUT_SECS.to_string(),
        "-A",
        &format!("{APP_NAME}-updater/{}", env!("CARGO_PKG_VERSION")),
        "-o",
        dest.to_str().ok_or("Download path is not valid UTF-8")?,
        url,
    ])
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::piped());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().map_err(|e| format!("Could not run curl.exe: {e}"))?;
    if !out.status.success() {
        let _ = fs::remove_file(dest);
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!("Download failed: {}", err.trim()));
    }
    if !dest.is_file() {
        return Err("Download failed: file missing after curl".into());
    }
    Ok(())
}

fn file_sha256_hex(path: &Path) -> Result<String, String> {
    let mut cmd = Command::new("certutil.exe");
    cmd.args(["-hashfile", path.to_str().ok_or("Path is not valid UTF-8")?, "SHA256"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let out = cmd.output().map_err(|e| format!("Could not run certutil.exe: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "certutil failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let t = line.trim();
        if is_sha256_hex(t) {
            return Ok(t.to_ascii_lowercase());
        }
    }
    Err("certutil did not return a SHA-256 digest".into())
}

fn temp_update_dir() -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("{APP_NAME}-update-{}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|e| format!("Could not create temp dir: {e}"))?;
    Ok(dir)
}

fn cleanup_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

/// Fetch release metadata and return a newer compatible update, if any.
pub fn check_for_update(channel: UpdateChannel) -> Result<Option<AvailableUpdate>, String> {
    let current = current_version();
    let installed = is_installed_mode();
    let body = match channel {
        UpdateChannel::Stable => {
            let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
            curl_get(&url, CURL_TIMEOUT_SECS)?
        }
        UpdateChannel::Beta => {
            let url = format!("https://api.github.com/repos/{REPO}/releases?per_page=20");
            curl_get(&url, CURL_TIMEOUT_SECS)?
        }
    };

    let update = match channel {
        UpdateChannel::Stable => {
            let rel: GhRelease = serde_json::from_slice(&body)
                .map_err(|e| format!("Could not parse GitHub release JSON: {e}"))?;
            if rel.draft {
                return Ok(None);
            }
            release_to_update(&rel, installed)?
        }
        UpdateChannel::Beta => {
            let releases: Vec<GhRelease> = serde_json::from_slice(&body)
                .map_err(|e| format!("Could not parse GitHub releases JSON: {e}"))?;
            let Some(rel) = pick_release(&releases, UpdateChannel::Beta) else {
                return Ok(None);
            };
            match release_to_update(rel, installed) {
                Ok(u) => u,
                Err(_) => return Ok(None), // incompatible / missing assets => no update
            }
        }
    };

    if update.version.is_newer_than(&current) {
        Ok(Some(update))
    } else {
        Ok(None)
    }
}

/// Download, verify, and start install/swap. Returns `true` if the app should exit so the update can finish.
pub fn download_verify_and_apply(update: &AvailableUpdate) -> Result<bool, String> {
    let installed = is_installed_mode();
    let dir = temp_update_dir()?;
    let sums_path = dir.join(SUMS_ASSET);
    let asset_path = dir.join(&update.asset_name);

    let apply = (|| -> Result<bool, String> {
        curl_download(&update.sums_url, &sums_path)?;
        let sums_body =
            fs::read_to_string(&sums_path).map_err(|e| format!("Could not read {SUMS_ASSET}: {e}"))?;
        let expected = checksum_for_asset(&sums_body, &update.asset_name).ok_or_else(|| {
            format!("{SUMS_ASSET} has no SHA-256 entry for {}", update.asset_name)
        })?;

        curl_download(&update.asset_url, &asset_path)?;
        let actual = file_sha256_hex(&asset_path)?;
        if actual != expected {
            let _ = fs::remove_file(&asset_path);
            return Err(format!(
                "SHA-256 mismatch for {} (expected {expected}, got {actual}). Update aborted.",
                update.asset_name
            ));
        }

        if installed {
            start_setup_silent(&asset_path)?;
        } else {
            start_portable_swap(&asset_path)?;
        }
        Ok(true)
    })();

    if apply.is_err() {
        cleanup_dir(&dir);
    }
    apply
}

fn start_setup_silent(setup: &Path) -> Result<(), String> {
    let mut cmd = Command::new(setup);
    // Tauri NSIS uses /S; Inno-style assets (if ever used) accept /SILENT.
    cmd.args(["/S"]);
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not start installer: {e}"))
}

fn start_portable_swap(zip: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let pid = std::process::id();
    let script = r#"
$ErrorActionPreference = 'Stop'
$pidToWait = [int]$env:CLIP_SANITIZER_UPDATE_PID
$zip = $env:CLIP_SANITIZER_UPDATE_ZIP
$exe = $env:CLIP_SANITIZER_UPDATE_EXE
$dir = Split-Path -Parent $exe
$extract = Join-Path $dir '.clip-sanitizer-update'
try { Wait-Process -Id $pidToWait -Timeout 60 -ErrorAction SilentlyContinue } catch {}
Start-Sleep -Milliseconds 400
if (Test-Path $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force
$newExe = Get-ChildItem -LiteralPath $extract -Filter '*.exe' -File | Select-Object -First 1
if (-not $newExe) { throw 'No .exe in portable zip' }
$bak = "$exe.bak"
if (Test-Path -LiteralPath $exe) { Copy-Item -LiteralPath $exe -Destination $bak -Force }
Copy-Item -LiteralPath $newExe.FullName -Destination $exe -Force
$portableMarker = Join-Path $extract 'portable.txt'
if (Test-Path -LiteralPath $portableMarker) {
  Copy-Item -LiteralPath $portableMarker -Destination (Join-Path $dir 'portable.txt') -Force
}
Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
Start-Process -FilePath $exe
"#;
    let mut cmd = Command::new("powershell.exe");
    cmd.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script])
        .env("CLIP_SANITIZER_UPDATE_PID", pid.to_string())
        .env("CLIP_SANITIZER_UPDATE_ZIP", zip.to_string_lossy().as_ref())
        .env("CLIP_SANITIZER_UPDATE_EXE", exe.to_string_lossy().as_ref())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not start portable update helper: {e}"))
}

#[cfg(windows)]
fn message_box(title: &str, body: &str, yes_no: bool) -> i32 {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO,
    };
    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }
    let flags = if yes_no {
        MB_YESNO | MB_ICONQUESTION
    } else {
        MB_OK | MB_ICONINFORMATION
    };
    unsafe { MessageBoxW(std::ptr::null_mut(), wide(body).as_ptr(), wide(title).as_ptr(), flags) }
}

#[cfg(not(windows))]
fn message_box(_title: &str, _body: &str, _yes_no: bool) -> i32 {
    1
}

const IDYES: i32 = 6;

fn ask_install(update: &AvailableUpdate) -> bool {
    let notes = update.notes.trim();
    let notes = if notes.is_empty() {
        String::new()
    } else {
        let short: String = notes.chars().take(400).collect();
        format!("\n\n{short}")
    };
    let body = format!(
        "Clip Sanitizer {} is available (you have {}).\n\nDownload and install now?{notes}\n\n{}",
        update.version.display(),
        current_version().display(),
        update.html_url
    );
    message_box("Clip Sanitizer update", &body, true) == IDYES
}

fn inform(title: &str, body: &str) {
    let _ = message_box(title, body, false);
}

/// Try to acquire the check lock. Returns false if a check is already running.
pub fn try_begin_check() -> bool {
    CHECK_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
}

pub fn end_check() {
    CHECK_IN_FLIGHT.store(false, Ordering::SeqCst);
}

pub struct CheckOutcome {
    /// App should exit so installer / portable swap can finish.
    pub should_exit: bool,
    /// Version the user dismissed (same as offered), if they said No.
    pub dismissed_version: Option<String>,
}

/// Manual "Check for updates": always reports the result.
pub fn run_manual_check(channel: UpdateChannel) -> CheckOutcome {
    if !try_begin_check() {
        inform("Clip Sanitizer", "An update check is already running.");
        return CheckOutcome { should_exit: false, dismissed_version: None };
    }
    let outcome = (|| -> CheckOutcome {
        match check_for_update(channel) {
            Ok(None) => {
                inform(
                    "Clip Sanitizer",
                    &format!("You are up to date (v{}).", current_version().display()),
                );
                CheckOutcome { should_exit: false, dismissed_version: None }
            }
            Ok(Some(update)) => {
                if !ask_install(&update) {
                    return CheckOutcome {
                        should_exit: false,
                        dismissed_version: Some(update.version.display()),
                    };
                }
                match download_verify_and_apply(&update) {
                    Ok(true) => CheckOutcome { should_exit: true, dismissed_version: None },
                    Ok(false) => CheckOutcome { should_exit: false, dismissed_version: None },
                    Err(e) => {
                        inform("Update failed", &e);
                        CheckOutcome { should_exit: false, dismissed_version: None }
                    }
                }
            }
            Err(e) => {
                inform("Update check failed", &e);
                CheckOutcome { should_exit: false, dismissed_version: None }
            }
        }
    })();
    end_check();
    outcome
}

/// Background check: silent when up to date or offline; prompts only when a newer release exists
/// and that version was not dismissed.
pub fn run_auto_check(channel: UpdateChannel, dismissed: &str) -> CheckOutcome {
    if !try_begin_check() {
        return CheckOutcome { should_exit: false, dismissed_version: None };
    }
    let outcome = (|| -> CheckOutcome {
        let update = match check_for_update(channel) {
            Ok(Some(u)) => u,
            Ok(None) | Err(_) => {
                return CheckOutcome { should_exit: false, dismissed_version: None };
            }
        };
        if !dismissed.is_empty() && dismissed == update.version.display() {
            return CheckOutcome { should_exit: false, dismissed_version: None };
        }
        if !ask_install(&update) {
            return CheckOutcome {
                should_exit: false,
                dismissed_version: Some(update.version.display()),
            };
        }
        match download_verify_and_apply(&update) {
            Ok(true) => CheckOutcome { should_exit: true, dismissed_version: None },
            Ok(false) => CheckOutcome { should_exit: false, dismissed_version: None },
            Err(e) => {
                inform("Update failed", &e);
                CheckOutcome { should_exit: false, dismissed_version: None }
            }
        }
    })();
    end_check();
    outcome
}

/// Delay used before the first automatic check so startup stays responsive.
pub fn auto_check_delay() -> Duration {
    Duration::from_secs(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_semver_strips_v_and_pre() {
        let v = Version::parse("v1.2.3").unwrap();
        assert_eq!(v, Version { major: 1, minor: 2, patch: 3, pre: String::new() });
        let b = Version::parse("0.3.0-beta.1").unwrap();
        assert_eq!(b.pre, "beta.1");
        assert!(Version::parse("").is_none());
        assert!(Version::parse("1.2").is_none());
    }

    #[test]
    fn release_beats_prerelease_same_core() {
        let rel = Version::parse("1.0.0").unwrap();
        let pre = Version::parse("1.0.0-beta.1").unwrap();
        assert!(rel.is_newer_than(&pre));
        assert!(!pre.is_newer_than(&rel));
        assert!(!rel.is_newer_than(&rel));
    }

    #[test]
    fn newer_patch_detected() {
        let cur = Version::parse("0.1.1").unwrap();
        let next = Version::parse("0.1.2").unwrap();
        assert!(next.is_newer_than(&cur));
        assert!(!cur.is_newer_than(&next));
    }

    #[test]
    fn checksum_for_asset_parses_common_formats() {
        let body = "\
# comment
aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899  ClipSanitizer-Setup.exe
11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff *ClipSanitizer-portable.zip
";
        assert_eq!(
            checksum_for_asset(body, "ClipSanitizer-Setup.exe").as_deref(),
            Some("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899")
        );
        assert_eq!(
            checksum_for_asset(body, "ClipSanitizer-portable.zip").as_deref(),
            Some("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff")
        );
        assert!(checksum_for_asset(body, "missing.exe").is_none());
    }

    #[test]
    fn channel_parse() {
        assert_eq!(UpdateChannel::parse("stable"), UpdateChannel::Stable);
        assert_eq!(UpdateChannel::parse("BETA"), UpdateChannel::Beta);
        assert_eq!(UpdateChannel::parse(""), UpdateChannel::Stable);
    }

    #[test]
    fn pick_release_ignores_drafts_and_respects_channel() {
        let releases = vec![
            GhRelease {
                tag_name: "v0.2.0-beta.1".into(),
                draft: false,
                prerelease: true,
                body: None,
                html_url: String::new(),
                assets: vec![],
            },
            GhRelease {
                tag_name: "v0.1.5".into(),
                draft: false,
                prerelease: false,
                body: None,
                html_url: String::new(),
                assets: vec![],
            },
            GhRelease {
                tag_name: "v9.9.9".into(),
                draft: true,
                prerelease: false,
                body: None,
                html_url: String::new(),
                assets: vec![],
            },
        ];
        let stable = pick_release(&releases, UpdateChannel::Stable).unwrap();
        assert_eq!(stable.tag_name, "v0.1.5");
        let beta = pick_release(&releases, UpdateChannel::Beta).unwrap();
        assert_eq!(beta.tag_name, "v0.2.0-beta.1");
    }

    #[test]
    fn is_sha256_hex_rejects_bad() {
        assert!(is_sha256_hex(
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        ));
        assert!(!is_sha256_hex("abc"));
        assert!(!is_sha256_hex(
            "ggbbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
        ));
    }

    #[test]
    fn split_curl_http_status_reads_trailing_code() {
        let (body, code) = split_curl_http_status("{\"ok\":true}\n200").unwrap();
        assert_eq!(body, "{\"ok\":true}");
        assert_eq!(code, 200);
        let (body404, code404) = split_curl_http_status("{\"message\":\"Not Found\"}\n404\n").unwrap();
        assert!(body404.contains("Not Found"));
        assert_eq!(code404, 404);
    }
}
