////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// biometry.js — dedicated script for biometry.html
//
// This page is Chrome-only by design: the biometric vault relies on a
// passkey held in Chrome Password Manager, and has only been built and
// tested against Chrome's implementation. If the browser isn't detected
// as Chrome, checkChromeOrStop() shows a blocking message and returns
// before anything else on this page is wired up — no provisioning, no
// BioVault calls, nothing.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

var currentIssuer = "";
var currentSecret = "";
var totpTimer = null;
var _ringCircumference = null;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Chrome detection. Best-effort by nature (user agents can be spoofed) —
// this is a UX gate for an unsupported-browser message, not a security
// boundary. Excludes Edge, Opera, and Brave, which all also match a loose
// "Chrome/" user-agent test despite not being Chrome.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function isChrome() {
  var ua = navigator.userAgent || "";
  var looksChromium = /Chrome\//.test(ua);
  var isEdge = /Edg\//.test(ua);
  var isOpera = /OPR\//.test(ua);
  var isBrave = !!(navigator.brave && typeof navigator.brave.isBrave === "function");
  var isGoogleVendor = navigator.vendor === "Google Inc.";
  return looksChromium && isGoogleVendor && !isEdge && !isOpera && !isBrave;
}

function checkChromeOrStop() {
  if (isChrome()) { return true; }
  document.getElementById("chromeGate").hidden = false;
  document.getElementById("mainContent").hidden = true;
  return false;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Provisioning — same four QR intake methods used on the other pages.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function allowDrop(ev) { ev.preventDefault(); }
function drag(ev) { ev.dataTransfer.setData("text", ev.target.id); }
function drop(ev) {
  ev.preventDefault();
  var data = ev.dataTransfer.getData("text/uri-list");
  document.getElementById('div1').src = data;
  var dataText = ev.dataTransfer.getData("text");
  ev.target.appendChild(document.getElementById(dataText));
  getSecret(document.getElementById('div1').src);
}

function fromTextOnly() {
  getSecret(document.getElementById("textOnly").value);
}
function copyToClipboardImg() {
  document.getElementById("textOnly").value = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAyoAAAMqAQMAAABXByeEAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAGUExURQAAAP///6XZn90AAAAJcEhZcwAADsMAAA7DAcdvqGQAAAR5SURBVHja7d1BbiI7EABQj1iwzBE4CkdLjsZRcgSWLFD8f5o2rjKd/2ek4BlpXm3iNLZfL0vlMpSNeK0f4/BQ6/L3pdZTKbVel2H9fLqv9T1NfCs/FxgMBoPBYDDfz+xqjPeBuT9Ne/+75lzKsX9ayo+2w1sfLnHGYDAYDAaDmcmso89hY/bj6iYf++rj+vTw+f9tTWMuZdwcg8FgMBgM5rcxZS3zhCUhdh3fp1fDYDAYDAaD+dOYh3jvwpJAXdv5V8+0yuarYTAYDAaDwcxm8oYpGbrHsncZS0N9TV32Pvzi2RoGg8FgMJi/hXmIcBoVhiGdScNLSmd+tVEZg8FgMBgM5huZ+kVcUvvMUpXZtawplGLa9DFrynHCYDAYDAaDmcEs0a483SKcRoXVqYZ0bXP7xNLKSenVUmAwGAwGg8HMZQ7r1MsqfmxMTBfA9+OhV1ieGnIwGAwGg8Fgns2kLp1r2vOQ8qKWQLVDr5JufYeJbdjKSRWDwWAwGAxmEhMOsNrDNO9WGspL0quFrOkhMBgMBoPBYKYyy59zSqDCFazwBXzLR62aFF6tZU3hqndJa5bAYDAYDAaDmcC0HKf2dGej6Tg3Krc49U3C6Vg4/4qvhsFgMBgMBvN0Jizph16ZaXnRLj09p0Ov0J38OrxaxWAwGAwGg9lIWOoXNZtd2jvEBpNfDYPBYDAYDGYSU/o9p92a9oTIuVQ+tkoJ1C02enPO970wGAwGg8FgnsukXa7rPacfvTH4nhe1OPZcaon8aRPbaVRLoDAYDAaDwWCmMNf0NTVL5G7gFve9l7n50OutM+FqVXt9DAaDwWAwmClMOvTKCVQTa3+JUENqay59TV32fh2SrhcMBoPBYDCYacx91BOostHO0+K0mUCNNaTcAlQwGAwGg8Fg5jC7tLr22k6LhypRyqXyxMPjmnS5HIPBYDAYDOapTBrdIncn13XDcOh1TWxIoOo6LF2sGAwGg8FgMJOZJa59yS1ev2hULr2cVB/3/kgv8YLBYDAYDAazTDmXHLnPpg1zQ05jLmnvQyr59B0xGAwGg8FgJjAlirmDOJRiQjdwTQnUmF79Z56GwWAwGAwG81ymrnHqh0zt5xFqv8ydI6xJR1Ch5SYHBoPBYDAYzGymNRMvcXnMpepYGkoTywbTe3MwGAwGg8FgJjAtjuvD9+EHtUOXTjjpuqYq0UY9KESqQGEwGAwGg8E8kalbEfauvZ2n9Kypjt9nM2ZatzVtLgaDwWAwGMwUZiPCj3WH86/QqDxWfDLzNjQ3YzAYDAaDwcxjwklXHX8eIV0u/0mmrm95yBMxGAwGg8Fg5jBtyW489AqXy5fV53V462g+9g3b3iXh8V8MBoPBYDCY38PcIiRQdV3y0juaWy61HycuuVRdk66+BoPBYDAYDOYrZozWQXyLRWwXou69Oema1BWDwWAwGAxmMhPivdds8iFTyprCsKw1m3udJ/XmFAwGg8FgMJiZzEMEZrwmdV6PoLZvfe97/nUp/xsYDAaDwWAw38qU8g/tYJfYC5+9YAAAAABJRU5ErkJggg==";
  fromTextOnly();
}

function dropFromBrowser(ev) {
  ev.preventDefault();
  var data = ev.dataTransfer.getData("text/uri-list");
  document.getElementById('div3').src = data;
  getSecret(decodeURIComponent(data));
}

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

var getSecret = async function (pickedImageUrl) {
  document.getElementById("qrIssuer").value = "";
  document.getElementById("qrSecret").value = "";

  var BrowserQRCodeReader = ZXingBrowser.BrowserQRCodeReader;
  var codeReader = new BrowserQRCodeReader();
  var piu = await codeReader.decodeFromImageUrl(pickedImageUrl);
  var result = decodeURIComponent(decodeURIComponent(piu.text));

  var myQrValue = result.split("?");
  // otpauth://totp/ <-- 15 chars
  var myIssuerValue = myQrValue[0].slice(15, myQrValue[0].length);
  var myPars = myQrValue[1].split("&");
  var mySecret = myPars[0].split("=");
  var mySecretValue = mySecret[1];

  document.getElementById("qrIssuer").value = myIssuerValue;
  document.getElementById("qrSecret").value = mySecretValue;

  currentIssuer = myIssuerValue;
  currentSecret = mySecretValue;
  document.getElementById("issuerDisplay").textContent = currentIssuer;
  startTotpLoop();
};

// Keep the visible Issuer/Secret fields in sync with the in-memory values
// (e.g. if the user hand-edits them before saving).
document.addEventListener("input", function (ev) {
  if (ev.target && ev.target.id === "qrIssuer") {
    currentIssuer = ev.target.value;
    document.getElementById("issuerDisplay").textContent = currentIssuer;
  }
  if (ev.target && ev.target.id === "qrSecret") {
    currentSecret = ev.target.value;
    startTotpLoop();
  }
});

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// TOTP display — same ring/grouping treatment as easy.html.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
    if (ring) { ring.style.strokeDasharray = circumference; ring.style.strokeDashoffset = circumference; }
  }
}
function startTotpLoop() {
  if (totpTimer) { return; }
  updateTotp();
  totpTimer = setInterval(updateTotp, 1000);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Biometric vault wiring — thin UI layer over BioVault (js/biometric.js).
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
function bioSay(msg, isError) {
  var el = document.getElementById("bioStatus");
  el.style.color = isError ? "#D6402C" : "var(--muted)";
  el.innerHTML = msg;
}

async function bioProbe() {
  var c = await BioVault.capabilities();
  var s = BioVault.status();
  var lines = [];
  lines.push("WebAuthn: " + (c.webauthn ? "yes" : "NO"));
  lines.push("Secure context: " + (c.secureContext ? "yes" : "NO \u2014 must serve over https:// or localhost"));
  lines.push("Platform authenticator (Touch ID / Windows Hello): " + (c.platformAuthenticator ? "yes" : "NO"));
  lines.push("PRF extension likely: " + (c.prfLikely ? "yes" : "unknown / no"));
  if (s.enrolled) {
    lines.push("<b>Vault: ENROLLED, mode = " + s.mode +
               (s.mode === "gate" ? " (weaker \u2014 gate only, see js/biometric.js)" : " (hardware-bound key)") +
               "</b>");
  } else {
    lines.push("<b>Vault: not enrolled</b>");
  }
  if (c.reason) { lines.push("<i>" + c.reason + "</i>"); }
  bioSay(lines.join("<br>"), !c.webauthn || !c.secureContext);
}

async function bioSave() {
  if (!currentSecret) {
    bioSay("Nothing to save \u2014 provision a code above first.", true);
    return;
  }
  if (!confirm("Protect this TOTP secret with a passkey?\n\n" +
               "You will be asked to verify twice: once to create the passkey, " +
               "once to derive the key.\n\n" +
               "WARNING: if you lose this passkey the secret is UNRECOVERABLE. " +
               "Keep the original QR code.")) { return; }
  try {
    bioSay("Waiting for biometric verification\u2026");
    var r = await BioVault.enroll(currentIssuer, currentSecret);
    if (r.mode === "prf") {
      bioSay("Sealed. The key is derived from the passkey itself \u2014 nothing " +
             "on this device can decrypt it without your biometrics.");
    } else {
      bioSay("Sealed in fallback \u201Cgate\u201D mode: this authenticator doesn't " +
             "support PRF, so the biometric check is enforced by this page's " +
             "logic rather than by cryptography. See js/biometric.js.", true);
    }
  } catch (e) {
    bioSay("Enrolment failed: " + e.message, true);
  }
}

async function bioGet() {
  await performUnlock(bioSay);
}

// Shared by the main "Get (unlock)" button and the bioPromptView's own
// "Unlock with passkey" button — same logic, different status target.
async function performUnlock(sayFn) {
  try {
    sayFn("Waiting for biometric verification\u2026");
    var v = await BioVault.unlock();
    currentIssuer = v.issuer;
    currentSecret = v.secret;
    document.getElementById("qrIssuer").value = currentIssuer;
    document.getElementById("qrSecret").value = currentSecret;
    document.getElementById("issuerDisplay").textContent = currentIssuer;
    startTotpLoop();
    sayFn("Unlocked.");
    hideProvisioningAndControls();
  } catch (e) {
    sayFn("Unlock failed: " + e.message, true);
  }
}

function bioPromptSay(msg, isError) {
  var el = document.getElementById("bioPromptStatus");
  if (el) { el.style.color = isError ? "#D6402C" : ""; el.textContent = msg; }
}

// Once a secret has been loaded, there's nothing left to provision and no
// reason to keep the intro / enrol / unlock / delete controls in view —
// collapse down to just the running code, with a small link to bring the
// vault controls back if needed (e.g. to delete the vault or check
// support again).
function hideProvisioningAndControls() {
  var provisioning = document.getElementById("provisioningView");
  var controls = document.getElementById("bioControlsSection");
  var hero = document.getElementById("bioHeroSection");
  var prompt = document.getElementById("bioPromptView");
  var reveal = document.getElementById("manageVaultLink");
  if (provisioning) { provisioning.hidden = true; }
  if (controls) { controls.hidden = true; }
  if (hero) { hero.hidden = true; }
  if (prompt) { prompt.hidden = true; }
  if (reveal) { reveal.hidden = false; }
}

// The two starting states, decided on load (see init()):
//   - a vault already exists -> show only the "unlock" prompt
//   - nothing enrolled yet   -> show the full page (hero, provisioning, controls)
function showBioPrompt() {
  document.getElementById("bioHeroSection").hidden = true;
  document.getElementById("provisioningView").hidden = true;
  document.getElementById("bioControlsSection").hidden = true;
  document.getElementById("bioPromptView").hidden = false;
}
function showFullPage() {
  document.getElementById("bioHeroSection").hidden = false;
  document.getElementById("provisioningView").hidden = false;
  document.getElementById("bioControlsSection").hidden = false;
  document.getElementById("bioPromptView").hidden = true;
}

async function bioClean() {
  if (!confirm("Really delete the biometric vault?\nNo way to undo.")) { return; }
  await BioVault.reset();
  bioSay("Vault deleted. Remove the passkey itself from Chrome's own " +
         "passkey settings (chrome://settings/passkeys) if you no longer want it there.");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Bootstrap.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
(function init() {
  if (!checkChromeOrStop()) { return; }
  document.getElementById("mainContent").hidden = false;

  document.getElementById("btnBioSave").addEventListener("click", bioSave);
  document.getElementById("btnBioGet").addEventListener("click", bioGet);
  document.getElementById("btnBioClean").addEventListener("click", bioClean);
  document.getElementById("btnBioProbe").addEventListener("click", bioProbe);
  document.getElementById("btnBioPromptUnlock").addEventListener("click", function () {
    performUnlock(bioPromptSay);
  });
  document.getElementById("btnBioPromptFallback").addEventListener("click", showFullPage);
  document.getElementById("btnManageVault").addEventListener("click", function () {
    document.getElementById("bioControlsSection").hidden = false;
    document.getElementById("bioHeroSection").hidden = false;
    document.getElementById("manageVaultLink").hidden = true;
  });

  // Decide the starting view: a vault already enrolled shows only the
  // unlock prompt; nothing enrolled shows the full page. This is a plain
  // local status check (BioVault.status()) — no biometric prompt fires
  // just from loading the page.
  try {
    if (window.BioVault && BioVault.status().enrolled) {
      showBioPrompt();
    } else {
      showFullPage();
    }
  } catch (err) {
    console.warn("Vault status check failed:", err);
    showFullPage();
  }

  bioProbe();
})();
