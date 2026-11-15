# Changelog

All notable changes to Clip Sanitizer are documented in this file.

## [0.1.1] - 2026-11-15

### Added

- MIT `LICENSE` for the public repository
- Tag-triggered GitHub Actions workflow that publishes a GitHub Release from this changelog

### Changed

- Standardized root `README.md` (description, install, usage, features, tech stack, license)
- Hardened `.gitignore` for env/secrets, OS junk, and editor files

## [0.1.0] - 2026-11-15

### Added

- Initial Windows tray app (Tauri 2 / Rust) with global hotkey sanitize
- Clipboard and selection sanitizing using Log Sanitizer-compatible patterns
- Tray menu, in-app sanitize window, settings, and portable release build path
