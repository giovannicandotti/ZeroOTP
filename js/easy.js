////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// easy.js — dedicated script for easy.html
//
// Guided flow, decided automatically on load:
//   - no saved credential       -> show the QR provisioning methods.
//   - exactly one credential    -> load it automatically, no click needed.
//   - multiple credentials      -> Chrome's own native account picker
//                                  appears; whichever is chosen gets loaded.
// As soon as a QR code is decoded during provisioning, its issuer/secret
// are sent to Chrome Password Manager automatically.
//
// There is no Secret input field anywhere on this page — the secret lives
// only in the in-memory `currentSecret` variable below. Cookie and
// LocalStorage storage backends do not exist in this file: Chrome Password
// Manager is the only supported storage mechanism here (see index.html for
// the full-featured page with all storage backends).
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// In-memory only — never rendered into a visible input on this page.
var currentIssuer = "";
var currentSecret = "";
var totpTimer = null;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Theme toggle — dark by default (also the default set directly on <html>
// in easy.html, so there's no flash before this script runs). Preference
// is remembered per browser via localStorage.
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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Chrome Password Manager context / capability check
// (same rules as index.html's checkChromePasswordManagerContext()).
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function checkChromePasswordManagerContext(showAlert) {
  function fail(msg) {
    if (showAlert) { alert(msg); } else { console.warn(msg); }
    return false;
  }
  if (location.protocol === "file:") {
    return fail("Chrome Password Manager cannot associate a password credential with a local file:// page. Serve this file through HTTPS (or localhost) first.");
  }
  if (!window.isSecureContext) {
    return fail("Chrome Password Manager requires a secure context: HTTPS (or localhost).");
  }
  if (window.top !== window.self) {
    return fail("Chrome Password Manager access must run in the top-level page, not inside an iframe.");
  }
  if (!("credentials" in navigator) || !("PasswordCredential" in window)) {
    return fail("PasswordCredential is not available in this browser context.");
  }
  return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// View switching
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function showView(name) {
  document.getElementById("checkingNotice").hidden = true;
  document.getElementById("bioPromptView").hidden = (name !== "bioPrompt");
  document.getElementById("provisioningView").hidden = (name !== "provisioning");
  document.getElementById("authenticatorView").hidden = false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Startup — two independent storage backends to check, in order:
//   1. Chrome Password Manager (mediation "optional"): zero credentials ->
//      null, no UI; one -> loads automatically, no UI; multiple -> Chrome's
//      own native account chooser appears on its own.
//   2. If nothing there, check locally (no prompt) whether a biometric
//      vault exists. Unlocking a passkey always needs an explicit user
//      gesture, so this only shows a button — it never auto-prompts.
//   3. If neither, show provisioning.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
async function initEasyPage() {
  var pmAvailable = checkChromePasswordManagerContext(false);

  if (pmAvailable) {
    try {
      var credential = await navigator.credentials.get({ password: true, mediation: "optional" });
      if (credential && credential.type === "password" && typeof credential.password === "string") {
        loadCredentialIntoPage(credential, "password-manager");
        return;
      }
    } catch (err) {
      console.warn("Credential check failed:", err);
    }
  }

  try {
    if (window.BioVault && BioVault.status().enrolled) {
      showView("bioPrompt");
      return;
    }
  } catch (err) {
    console.warn("Biometric vault check failed:", err);
  }

  showView("provisioning");
}

function loadCredentialIntoPage(credential, method) {
  currentIssuer = credential.id || credential.name || "";
  currentSecret = credential.password;
  document.getElementById("issuer").value = currentIssuer;
  showView("running");
  startTotpLoop();
  showActiveMethodTag(method);
}

function showActiveMethodTag(method) {
  var tag = document.getElementById("activeMethodTag");
  if (!tag) { return; }
  var icon = method === "biometric" ? "img/icons/biometry.svg" : "img/icons/password-manager.svg";
  var label = method === "biometric" ? "Unlocked with a passkey" : "Saved in Chrome Password Manager";
  tag.innerHTML = '<img src="' + icon + '" alt="">' + '<span>' + label + '</span>';
  tag.hidden = false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Biometric unlock — explicit button on the bioPromptView.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
document.getElementById("btnBioUnlock").addEventListener("click", async function () {
  var status = document.getElementById("bioPromptStatus");
  try {
    if (status) { status.textContent = "Waiting for biometric verification\u2026"; }
    var v = await BioVault.unlock();
    currentIssuer = v.issuer;
    currentSecret = v.secret;
    document.getElementById("issuer").value = currentIssuer;
    showView("running");
    startTotpLoop();
    showActiveMethodTag("biometric");
  } catch (err) {
    if (status) { status.textContent = "Unlock failed: " + err.message; }
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Provisioning — acquire "issuer" + "secret" from a QR code image.
//  Same four input methods as index.html (unmodified logic), adapted to
//  populate the internal secret variable instead of a visible field, and
//  to trigger an automatic Chrome Password Manager save once decoded.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Case 1 - DROP - CURRENT PAGE
function allowDrop(ev) {
  ev.preventDefault();
}
function drag(ev) {
  ev.dataTransfer.setData("text", ev.target.id);
}
function drop(ev) {
  ev.preventDefault();
  var data = ev.dataTransfer.getData("text/uri-list");
  document.getElementById('div1').src = data;
  var dataText = ev.dataTransfer.getData("text");
  ev.target.appendChild(document.getElementById(dataText));

  getSecret(document.getElementById('div1').src);
}

// Case 2 - PASTE QR image encoded version of 2nd factor activation
function fromTextOnly() {
  getSecret(document.getElementById("textOnly").value);
}
function copyToClipboardImg() {
  document.getElementById("textOnly").value = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAyoAAAMqAQMAAABXByeEAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAGUExURQAAAP///6XZn90AAAAJcEhZcwAADsMAAA7DAcdvqGQAAAR5SURBVHja7d1BbiI7EABQj1iwzBE4CkdLjsZRcgSWLFD8f5o2rjKd/2ek4BlpXm3iNLZfL0vlMpSNeK0f4/BQ6/L3pdZTKbVel2H9fLqv9T1NfCs/FxgMBoPBYDDfz+xqjPeBuT9Ne/+75lzKsX9ayo+2w1sfLnHGYDAYDAaDmcmso89hY/bj6iYf++rj+vTw+f9tTWMuZdwcg8FgMBgM5rcxZS3zhCUhdh3fp1fDYDAYDAaD+dOYh3jvwpJAXdv5V8+0yuarYTAYDAaDwcxm8oYpGbrHsncZS0N9TV32Pvzi2RoGg8FgMJi/hXmIcBoVhiGdScNLSmd+tVEZg8FgMBgM5huZ+kVcUvvMUpXZtawplGLa9DFrynHCYDAYDAaDmcEs0a483SKcRoXVqYZ0bXP7xNLKSenVUmAwGAwGg8HMZQ7r1MsqfmxMTBfA9+OhV1ieGnIwGAwGg8Fgns2kLp1r2vOQ8qKWQLVDr5JufYeJbdjKSRWDwWAwGAxmEhMOsNrDNO9WGspL0quFrOkhMBgMBoPBYKYyy59zSqDCFazwBXzLR62aFF6tZU3hqndJa5bAYDAYDAaDmcC0HKf2dGej6Tg3Krc49U3C6Vg4/4qvhsFgMBgMBvN0Jizph16ZaXnRLj09p0Ov0J38OrxaxWAwGAwGg9lIWOoXNZtd2jvEBpNfDYPBYDAYDGYSU/o9p92a9oTIuVQ+tkoJ1C02enPO970wGAwGg8FgnsukXa7rPacfvTH4nhe1OPZcaon8aRPbaVRLoDAYDAaDwWCmMNf0NTVL5G7gFve9l7n50OutM+FqVXt9DAaDwWAwmClMOvTKCVQTa3+JUENqay59TV32fh2SrhcMBoPBYDCYacx91BOostHO0+K0mUCNNaTcAlQwGAwGg8Fg5jC7tLr22k6LhypRyqXyxMPjmnS5HIPBYDAYDOapTBrdIncn13XDcOh1TWxIoOo6LF2sGAwGg8FgMJOZJa59yS1ev2hULr2cVB/3/kgv8YLBYDAYDAazTDmXHLnPpg1zQ05jLmnvQyr59B0xGAwGg8FgJjAlirmDOJRiQjdwTQnUmF79Z56GwWAwGAwG81ymrnHqh0zt5xFqv8ydI6xJR1Ch5SYHBoPBYDAYzGymNRMvcXnMpepYGkoTywbTe3MwGAwGg8FgJjAtjuvD9+EHtUOXTjjpuqYq0UY9KESqQGEwGAwGg8E8kalbEfauvZ2n9Kypjt9nM2ZatzVtLgaDwWAwGMwUZiPCj3WH86/QqDxWfDLzNjQ3YzAYDAaDwcxjwklXHX8eIV0u/0mmrm95yBMxGAwGg8Fg5jBtyW489AqXy5fV53V462g+9g3b3iXh8V8MBoPBYDCY38PcIiRQdV3y0juaWy61HycuuVRdk66+BoPBYDAYDOYrZozWQXyLRWwXou69Oema1BWDwWAwGAxmMhPivdds8iFTyprCsKw1m3udJ/XmFAwGg8FgMJiZzEMEZrwmdV6PoLZvfe97/nUp/xsYDAaDwWAw38qU8g/tYJfYC5+9YAAAAABJRU5ErkJggg==";
  fromTextOnly();
}

// Case 3 - DROP image FROM OTHER BROWSER INSTANCE
function dropFromBrowser(ev) {
  ev.preventDefault();
  var data = ev.dataTransfer.getData("text/uri-list");
  document.getElementById('div3').src = data;
  getSecret(decodeURIComponent(data));
}

// Case 4 - DROP FILE from desktop
function dodrop(event) {
  var dt = event.dataTransfer;
  var files = dt.files;
  for (var i = 0; i < files.length; i++) {
    document.getElementById("output").textContent += (" File " + ": " + files[i].name + " [" + files[i].size + " bytes]\n");
    previewFile(files[i]);
  }
}
function previewFile(file) {
  var reader = new FileReader();
  reader.readAsDataURL(file);
  reader.onloadend = function () {
    getSecret(reader.result);
  };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Extract issuer/secret from a decoded QR image, display the issuer,
//  start the TOTP loop, and offer an explicit choice of how to protect it
//  (Password Manager or Biometrics) — now that there are two real options,
//  this is no longer silently auto-saved to one fixed backend.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
var getSecret = async function (pickedImageUrl) {
  var saveStatus = document.getElementById("saveStatus");
  if (saveStatus) { saveStatus.textContent = ""; }
  document.getElementById("issuer").value = "";
  currentIssuer = "";
  currentSecret = "";

  var BrowserQRCodeReader = ZXingBrowser.BrowserQRCodeReader;
  var codeReader = new BrowserQRCodeReader();
  var piu = await codeReader.decodeFromImageUrl(pickedImageUrl);
  var result = decodeURIComponent(decodeURIComponent(piu.text));

  // extract secret by text of QR code
  var myQrValue = result.split("?");
  // otpauth://totp/ <-- 15
  var myIssuerValue = myQrValue[0].slice(15, myQrValue[0].length);

  var myPars = myQrValue[1].split("&");
  var mySecret = myPars[0].split("=");
  var mySecretValue = mySecret[1];

  currentIssuer = myIssuerValue;
  currentSecret = mySecretValue;
  document.getElementById("issuer").value = currentIssuer;

  startTotpLoop();
  var choice = document.getElementById("protectChoice");
  if (choice) { choice.hidden = false; }
};

document.getElementById("btnProtectPm").addEventListener("click", function () {
  saveToPasswordManager();
});
document.getElementById("btnProtectBio").addEventListener("click", function () {
  saveToBiometric();
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// CHROME PASSWORD MANAGER — save on explicit user choice.
// Secret is stored as the browser password value; issuer as the username.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
async function saveToPasswordManager() {
  var saveStatus = document.getElementById("saveStatus");

  if (!checkChromePasswordManagerContext(false)) {
    if (saveStatus) { saveStatus.textContent = "Password Manager unavailable in this context — the code above still works, but it can't be saved here."; }
    return;
  }
  if (!currentIssuer || !currentSecret) { return; }

  var pmUsername = document.getElementById("chromePmUsername");
  var pmPassword = document.getElementById("chromePmPassword");
  var pmForm = document.getElementById("chromePmForm");
  pmUsername.value = currentIssuer;
  pmPassword.value = currentSecret;

  try {
    var credential = new PasswordCredential(pmForm);
    await navigator.credentials.store(credential);

    console.log("PasswordCredential store request completed", {
      origin: location.origin,
      id: credential.id,
      passwordLength: credential.password.length
    });

    // store() resolving is not the same as the password being saved:
    // Chrome still needs the user to accept its own native "Save/Update
    // password?" bubble near the address bar. A blocking alert() here
    // would grab focus away from that bubble, so use a non-blocking
    // status line instead (same lesson learned on index.html).
    if (saveStatus) {
      saveStatus.textContent = "Look for Chrome's Save/Update password prompt near the address bar and accept it.";
    }
    showActiveMethodTag("password-manager");
  } catch (err) {
    console.error("Chrome Password Manager SAVE failed:", err);
    if (saveStatus) {
      saveStatus.textContent = "Could not save (" + (err && err.name ? err.name : "error") + "). The code above still works.";
    }
  } finally {
    // Don't leave the plaintext secret sitting in the hidden form.
    pmUsername.value = "";
    pmPassword.value = "";
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// BIOMETRIC — save on explicit user choice, via BioVault (js/biometric.js).
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
async function saveToBiometric() {
  var saveStatus = document.getElementById("saveStatus");
  if (!currentIssuer || !currentSecret) { return; }
  if (!confirm("Protect this TOTP code with a passkey?\n\nYou'll be asked to verify " +
               "twice: once to create the passkey, once to derive the key.\n\n" +
               "WARNING: if you lose this passkey the secret is UNRECOVERABLE. " +
               "Keep the original QR code.")) { return; }
  try {
    if (saveStatus) { saveStatus.textContent = "Waiting for biometric verification\u2026"; }
    var r = await BioVault.enroll(currentIssuer, currentSecret);
    if (saveStatus) {
      saveStatus.textContent = (r.mode === "prf")
        ? "Sealed. The key is derived from the passkey itself."
        : "Sealed in fallback mode (no PRF support on this authenticator) \u2014 see js/biometric.js.";
    }
    showActiveMethodTag("biometric");
  } catch (err) {
    if (saveStatus) { saveStatus.textContent = "Could not save: " + err.message; }
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TOTP display — reads the in-memory secret only, never a DOM field.
// Also drives the countdown ring: its stroke-dashoffset is derived from
// the same "seconds remaining" value used for the text, so the ring is a
// second representation of one real fact, not a decoration.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
var _ringCircumference = null;
function ringCircumference() {
  if (_ringCircumference === null) {
    var ring = document.getElementById("ringProgress");
    var r = ring ? parseFloat(ring.getAttribute("r")) : 52;
    _ringCircumference = 2 * Math.PI * r;
  }
  return _ringCircumference;
}

function updateTotp() {
  var ring = document.getElementById("ringProgress");
  var circumference = ringCircumference();

  if (currentSecret) {
    var secret = currentSecret.replace(/\W/g, "");
    var totp = totp_get_otp(secret);
    var s = new Date().getSeconds();
    s = 30 - (s % 30);

    // Group into two triplets for readability ("123456" -> "123 456"),
    // the way most authenticator apps display a 6-digit code.
    var grouped = (totp.length === 6) ? (totp.slice(0, 3) + " " + totp.slice(3)) : totp;

    document.getElementById("myTotp").value = grouped;
    document.getElementById("myTotpSeconds").textContent = "changing in " + s + " seconds";
    if (ring) {
      ring.style.strokeDasharray = circumference;
      ring.style.strokeDashoffset = circumference * (1 - s / 30);
    }
  } else {
    document.getElementById("myTotp").value = "";
    document.getElementById("myTotpSeconds").textContent = "";
    if (ring) {
      ring.style.strokeDasharray = circumference;
      ring.style.strokeDashoffset = circumference;
    }
  }
}
function startTotpLoop() {
  if (totpTimer) { return; } // already running
  updateTotp();
  totpTimer = setInterval(updateTotp, 1000);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Bootstrap. easy.js is loaded at the end of <body>, so the DOM already
// exists by the time this line runs.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
initEasyPage();

