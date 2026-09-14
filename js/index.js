////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// index.js — dedicated script for index.html (the hub/landing page).
// This page has no TOTP or provisioning logic of its own — just the
// dark/light theme toggle, shared with easy.html and biometry.html.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  var toggle = document.getElementById("themeToggle");
  var sun = toggle ? toggle.querySelector(".icon-sun") : null;
  var moon = toggle ? toggle.querySelector(".icon-moon") : null;
  if (theme === "dark") {
    if (sun) { sun.hidden = false; }
    if (moon) { moon.hidden = true; }
    if (toggle) { toggle.setAttribute("aria-label", "Switch to light mode"); }
  } else {
    if (sun) { sun.hidden = true; }
    if (moon) { moon.hidden = false; }
    if (toggle) { toggle.setAttribute("aria-label", "Switch to dark mode"); }
  }
  try { localStorage.setItem("zerotp-theme", theme); } catch (err) { /* ignore */ }
}

(function initTheme() {
  var saved = null;
  try { saved = localStorage.getItem("zerotp-theme"); } catch (err) { /* ignore */ }
  applyTheme(saved === "light" ? "light" : "dark");
})();

document.getElementById("themeToggle").addEventListener("click", function () {
  var current = document.documentElement.getAttribute("data-theme");
  applyTheme(current === "dark" ? "light" : "dark");
});
