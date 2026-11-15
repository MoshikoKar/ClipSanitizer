const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const $ = (id) => document.getElementById(id);

let state = null;
let lastResult = null;
let lastCounts = {};

// ---------------------------------------------------------------- rendering

function renderState(s) {
  state = s;
  $("hint-key").textContent = s.hotkey;
  $("hint").classList.toggle("paused", s.paused);
  $("hint").firstChild.textContent = s.paused ? "Hotkey paused (tray menu) - " : "Select text anywhere and press ";
  $("hotkey").value = s.hotkey;
  $("paste-after").checked = s.paste_after;
  $("show-toast").checked = s.show_toast;
  $("autostart").checked = s.autostart;
  $("check-updates").checked = s.check_updates;
  $("update-channel").value = s.update_channel === "beta" ? "beta" : "stable";
  $("mode").value = s.mode === "strict" ? "strict" : "standard";
  $("patterns-file").value = s.patterns_file;
  $("patterns-file").placeholder = s.patterns_path;
  $("load-msg").textContent = s.load_message;
  renderPatterns();
}

function renderPatterns() {
  if (!state) return;
  const q = $("filter").value.trim().toLowerCase();
  const list = $("pattern-list");
  list.replaceChildren();
  for (const p of state.patterns) {
    if (q && !p.name.toLowerCase().includes(q)) continue;
    const li = document.createElement("li");
    li.className = p.enabled ? "" : "off";
    li.title = `${p.comment || ""}\npriority ${p.priority}${p.hash ? " · hashed" : ""}${p.builtin ? " · built-in" : " · from patterns file"}\n${p.regex}`;
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = p.enabled;
    box.setAttribute("aria-label", `Enable ${p.name}`);
    box.addEventListener("change", async () => {
      p.enabled = box.checked;
      li.className = p.enabled ? "" : "off";
      await invoke("set_pattern_enabled", { name: p.name, enabled: p.enabled });
    });
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = p.name;
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = p.builtin ? "" : "custom";
    const hits = document.createElement("span");
    hits.className = "hits";
    hits.textContent = lastCounts[p.name] || "";
    li.append(box, name, badge, hits);
    list.append(li);
  }
}

function renderResult(r) {
  lastResult = r;
  lastCounts = Object.fromEntries(r.counts);
  const out = $("output");
  out.replaceChildren();
  for (const seg of r.segments) {
    if (seg.hit) {
      const m = document.createElement("mark");
      m.textContent = seg.text;
      m.title = seg.hit;
      out.append(m);
    } else {
      out.append(document.createTextNode(seg.text));
    }
  }
  $("copy").disabled = !r.text;
  const top = r.counts.slice(0, 5).map(([n, c]) => `${n} ${c}`).join(" · ");
  $("summary").textContent = r.total
    ? `${r.total} replacement${r.total === 1 ? "" : "s"}${top ? " - " + top : ""}`
    : "Nothing sensitive found";
  if (r.warnings.length) $("summary").textContent += ` | ${r.warnings.join("; ")}`;
  renderPatterns();
}

function settingsMsg(text, kind = "") {
  const el = $("settings-msg");
  el.textContent = text;
  el.className = "msg " + kind;
}

// ---------------------------------------------------------------- actions

async function sanitize() {
  const text = $("input").value;
  if (!text.trim()) {
    $("summary").textContent = "Paste or type some text first";
    return;
  }
  renderResult(await invoke("sanitize_text", { text }));
}

async function copyOutput() {
  if (!lastResult) return;
  try {
    await invoke("copy_text", { text: lastResult.text });
    $("summary").textContent = "Copied - ready to paste";
  } catch (e) {
    $("summary").textContent = String(e);
  }
}

$("sanitize").addEventListener("click", sanitize);
$("copy").addEventListener("click", copyOutput);
$("clear").addEventListener("click", () => {
  $("input").value = "";
  $("output").replaceChildren();
  $("summary").textContent = "";
  $("copy").disabled = true;
  lastResult = null;
  lastCounts = {};
  renderPatterns();
  $("input").focus();
});
$("paste").addEventListener("click", async () => {
  try {
    $("input").value = await invoke("paste_text");
    await sanitize();
  } catch (e) {
    $("summary").textContent = String(e);
  }
});
$("filter").addEventListener("input", renderPatterns);
document.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.key === "Enter") { e.preventDefault(); sanitize(); }
});

// settings drawer
$("settings-btn").addEventListener("click", () => {
  const panel = $("settings");
  panel.hidden = !panel.hidden;
  $("settings-btn").setAttribute("aria-expanded", String(!panel.hidden));
  settingsMsg("");
});

// hotkey recorder: uses physical key codes, so it works with any keyboard layout
$("hotkey").addEventListener("keydown", (e) => {
  e.preventDefault();
  if (["Control", "Alt", "Shift", "Meta"].includes(e.key)) return;
  const mods = [e.ctrlKey && "Ctrl", e.altKey && "Alt", e.shiftKey && "Shift", e.metaKey && "Super"].filter(Boolean);
  let key = e.code.replace(/^Key/, "").replace(/^Digit/, "");
  if (!mods.length) {
    settingsMsg("Use at least one modifier (Ctrl / Alt / Shift / Win)", "error");
    return;
  }
  $("hotkey").value = [...mods, key].join("+");
  settingsMsg("Press Save settings to apply");
});

$("save-settings").addEventListener("click", async () => {
  try {
    const s = await invoke("save_settings", {
      input: {
        hotkey: $("hotkey").value,
        paste_after: $("paste-after").checked,
        show_toast: $("show-toast").checked,
        patterns_file: $("patterns-file").value,
        autostart: $("autostart").checked,
        check_updates: $("check-updates").checked,
        update_channel: $("update-channel").value,
        mode: $("mode").value,
      },
    });
    renderState(s);
    settingsMsg("Saved", "ok");
  } catch (e) {
    settingsMsg(String(e), "error");
  }
});
$("open-patterns").addEventListener("click", () => invoke("open_patterns_file").catch((e) => settingsMsg(String(e), "error")));
$("reload").addEventListener("click", async () => {
  renderState(await invoke("reload_patterns"));
  settingsMsg(state.load_message, state.load_message.includes("not loaded") ? "error" : "ok");
});

// ---------------------------------------------------------------- events from the hotkey / tray

listen("sanitized", (e) => renderResult(e.payload));
listen("state-changed", async () => renderState(await invoke("get_state")));

// The page can load before the app has finished starting; retry until its state is available.
async function loadState(attempt = 0) {
  try {
    renderState(await invoke("get_state"));
  } catch (e) {
    if (attempt < 40) setTimeout(() => loadState(attempt + 1), 250);
    else $("load-msg").textContent = "Could not load app state: " + e;
  }
}
loadState();
