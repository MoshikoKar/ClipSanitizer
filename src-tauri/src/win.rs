//! Small Win32 helpers: keyboard simulation, clipboard change detection, no-activate toast window.

use std::ffi::c_void;
use std::thread::sleep;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, MapVirtualKeyW, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP,
    MAPVK_VK_TO_VSC, VIRTUAL_KEY, VK_CONTROL,
    VK_LWIN, VK_MENU, VK_RWIN, VK_SHIFT,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetWindowLongPtrW, SetWindowLongPtrW, SetWindowPos, ShowWindow, SystemParametersInfoW, GWL_EXSTYLE, HWND_TOPMOST,
    SPI_GETWORKAREA, SWP_NOACTIVATE, SWP_SHOWWINDOW, SW_HIDE, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
};

const MODIFIERS: [VIRTUAL_KEY; 5] = [VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN, VK_RWIN];
const VK_UNASSIGNED: VIRTUAL_KEY = 0xE8; // tapped before releasing Alt so apps don't open their menu bar

fn is_down(vk: VIRTUAL_KEY) -> bool {
    unsafe { (GetAsyncKeyState(vk as i32) as u16 & 0x8000) != 0 }
}

fn key(vk: VIRTUAL_KEY, up: bool) -> INPUT {
    // Include the hardware scan code: some apps (Tk, Java, RDP clients) ignore keys without one.
    let scan = unsafe { MapVirtualKeyW(vk as u32, MAPVK_VK_TO_VSC) } as u16;
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: if up { KEYEVENTF_KEYUP } else { 0 }, time: 0, dwExtraInfo: 0 },
        },
    }
}

fn send(inputs: &[INPUT]) {
    unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32) };
}

/// Wait until the user lets go of the hotkey (modifiers + `extra` key). If they are still held
/// after `timeout`, release them synthetically so our Ctrl+C is not seen as e.g. Ctrl+Alt+C.
/// Which of the hotkey's keys are physically down right now (for the debug log).
pub fn held_keys(extra: Option<VIRTUAL_KEY>) -> Vec<VIRTUAL_KEY> {
    MODIFIERS.iter().copied().chain(extra).filter(|vk| is_down(*vk)).collect()
}

pub fn wait_keys_released(extra: Option<VIRTUAL_KEY>, timeout: Duration) {
    // The hotkey swallowed the letter, so the target app saw Alt/Win go down with no other key.
    // Releasing it would then open the app's menu bar (or the Start menu) and eat our Ctrl+C.
    // Tapping an unassigned key while they are still held prevents that ("menu mask key").
    if [VK_MENU, VK_LWIN, VK_RWIN].iter().any(|vk| is_down(*vk)) {
        send(&[key(VK_UNASSIGNED, false), key(VK_UNASSIGNED, true)]);
    }
    let held = || MODIFIERS.iter().copied().chain(extra).filter(|vk| is_down(*vk)).collect::<Vec<_>>();
    let start = Instant::now();
    while start.elapsed() < timeout {
        if held().is_empty() {
            return;
        }
        sleep(Duration::from_millis(10));
    }
    let still = held();
    let mut inputs = Vec::new();
    if still.contains(&VK_MENU) {
        inputs.push(key(VK_UNASSIGNED, false));
        inputs.push(key(VK_UNASSIGNED, true));
    }
    inputs.extend(still.into_iter().map(|vk| key(vk, true)));
    send(&inputs);
    sleep(Duration::from_millis(20));
}

/// Press Ctrl+<letter> (virtual-key codes, so it works with any keyboard layout, e.g. Hebrew).
pub fn send_ctrl(letter: u8) {
    let vk = letter.to_ascii_uppercase() as VIRTUAL_KEY;
    send(&[key(VK_CONTROL, false), key(vk, false), key(vk, true), key(VK_CONTROL, true)]);
}

pub fn clipboard_seq() -> u32 {
    unsafe { GetClipboardSequenceNumber() }
}

/// True if the clipboard changed (someone copied) within `timeout`. Apps often empty the
/// clipboard first and add formats afterwards, so after the first change we also wait until
/// the sequence number has been stable for a short while.
pub fn wait_clipboard_change(before: u32, timeout: Duration) -> bool {
    let start = Instant::now();
    while clipboard_seq() == before {
        if start.elapsed() >= timeout {
            return false;
        }
        sleep(Duration::from_millis(15));
    }
    let settle = Instant::now();
    let (mut last, mut stable_since) = (clipboard_seq(), Instant::now());
    while settle.elapsed() < Duration::from_millis(400) && stable_since.elapsed() < Duration::from_millis(60) {
        sleep(Duration::from_millis(10));
        let now = clipboard_seq();
        if now != last {
            last = now;
            stable_since = Instant::now();
        }
    }
    true
}

/// Show a window at the bottom-right of the primary work area, top-most, WITHOUT taking focus
/// (the user's paste target must keep focus).
pub fn show_toast_window(hwnd: isize, width: i32, height: i32) {
    let hwnd = hwnd as *mut c_void;
    unsafe {
        let ex = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, ex | (WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST) as isize);
        let mut area = RECT { left: 0, top: 0, right: 1920, bottom: 1080 };
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut area as *mut RECT as *mut c_void, 0);
        let margin = 16;
        SetWindowPos(hwnd, HWND_TOPMOST, area.right - width - margin, area.bottom - height - margin, width, height,
                     SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }
}

pub fn hide_window(hwnd: isize) {
    unsafe { ShowWindow(hwnd as *mut c_void, SW_HIDE) };
}
