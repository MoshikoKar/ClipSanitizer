const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

listen("toast", (e) => {
  const { kind, title, body } = e.payload;
  const el = document.getElementById("toast");
  el.className = "toast " + kind;
  document.getElementById("title").textContent = title;
  document.getElementById("body").textContent = body;
  // restart the entry animation
  el.style.animation = "none";
  void el.offsetWidth;
  el.style.animation = "";
});

document.getElementById("toast").addEventListener("click", () => invoke("show_main_window"));
