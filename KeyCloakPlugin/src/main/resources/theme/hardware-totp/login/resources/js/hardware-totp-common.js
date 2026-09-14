////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// hardware-totp-common.js
//
// Funzioni condivise tra la pagina di enrollment e quella di login:
// - encoding base64url
// - HKDF-SHA256 (per derivare la chiave AES da PRF)
// - AES-256-GCM encrypt/decrypt
// - calcolo TOTP (RFC 6238, HMAC-SHA1) via Web Crypto — nessuna libreria
//   esterna necessaria, a differenza della versione standalone ZeroOTP.
//
// NESSUN FALLBACK: se PRF non e' disponibile, le funzioni qui sotto NON
// producono una modalita' alternativa piu' debole. E' responsabilita' del
// chiamante (hardware-totp-register.js) interrompere l'enrollment.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const HTOTP_HKDF_INFO = "zerotp-keycloak-hardware-totp-v1";
const HTOTP_STORAGE_PREFIX = "htotp-vault:"; // + rpId, per isolare per realm/host

function htotpB64uEncode(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function htotpB64uDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function htotpRandomBytes(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return arr;
}

async function htotpDeriveAesKey(prfOutput, hkdfSalt) {
  const ikm = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: hkdfSalt, info: new TextEncoder().encode(HTOTP_HKDF_INFO) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function htotpEncrypt(key, plaintextObj) {
  const iv = htotpRandomBytes(12);
  const data = new TextEncoder().encode(JSON.stringify(plaintextObj));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { iv: htotpB64uEncode(iv), ct: htotpB64uEncode(ct) };
}
async function htotpDecrypt(key, record) {
  const iv = htotpB64uDecode(record.iv);
  const ct = htotpB64uDecode(record.ct);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

// ---- Base32 decode (per il segreto TOTP, RFC 4648) ----
function htotpBase32Decode(input) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  input = input.replace(/=+$/, "").toUpperCase();
  let bits = "";
  for (const c of input) {
    const val = alphabet.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

// ---- TOTP (RFC 6238) via Web Crypto HMAC-SHA1 ----
async function htotpComputeCode(base32Secret, digits, period) {
  digits = digits || 6;
  period = period || 30;
  const keyBytes = htotpBase32Decode(base32Secret);
  const counter = Math.floor(Date.now() / 1000 / period);

  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  // JS non ha interi a 64 bit nativi: scriviamo i 32 bit alti come 0
  // (validi fino all'anno ~2106 per un periodo di 30s), i 32 bassi col contatore.
  view.setUint32(0, 0, false);
  view.setUint32(4, counter, false);

  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBuf));

  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode = ((hmac[offset] & 0x7f) << 24) |
                   ((hmac[offset + 1] & 0xff) << 16) |
                   ((hmac[offset + 2] & 0xff) << 8) |
                   (hmac[offset + 3] & 0xff);
  const code = (binCode % Math.pow(10, digits)).toString().padStart(digits, "0");
  return code;
}

// ---- Estrazione flag BE/BS + AAGUID da authenticatorData grezzo ----
// Layout (WebAuthn spec, non CBOR - binario fisso):
//   rpIdHash(32) | flags(1) | signCount(4) | [aaguid(16) | credIdLen(2) | credId(credIdLen) | ...]
function htotpParseAuthenticatorData(authDataBuf) {
  const bytes = new Uint8Array(authDataBuf);
  const flags = bytes[32];
  const backupEligible = !!(flags & 0x08); // bit BE
  const backupState = !!(flags & 0x10);    // bit BS
  const attestedDataIncluded = !!(flags & 0x40); // bit AT

  let aaguid = null;
  if (attestedDataIncluded && bytes.length >= 32 + 1 + 4 + 16) {
    const aaguidBytes = bytes.slice(37, 53);
    aaguid = Array.from(aaguidBytes).map(b => b.toString(16).padStart(2, "0")).join("");
  }
  return { backupEligible, backupState, aaguid };
}

function htotpSubmitForm(formId, fields) {
  const form = document.getElementById(formId);
  Object.keys(fields).forEach(function (key) {
    const el = document.getElementById(key);
    if (el) { el.value = (fields[key] === null || fields[key] === undefined) ? "" : String(fields[key]); }
  });
  form.submit();
}

// ---- Session binding proof -------------------------------------------------
// Keeps the RFC 6238 TOTP unchanged, but binds its use to the Keycloak
// authentication session that issued serverChallenge.
// proof = HMAC-SHA256(TOTP-secret, "zerotp-session-v1\0" || challenge || "\0" || code)
async function htotpComputeSessionProof(base32Secret, challengeB64u, code) {
  const keyBytes = htotpBase32Decode(base32Secret);
  const label = new TextEncoder().encode("zerotp-session-v1\0");
  const challenge = new TextEncoder().encode(challengeB64u);
  const separator = new Uint8Array([0]);
  const codeBytes = new TextEncoder().encode(code);

  const data = new Uint8Array(label.length + challenge.length + separator.length + codeBytes.length);
  let offset = 0;
  data.set(label, offset); offset += label.length;
  data.set(challenge, offset); offset += challenge.length;
  data.set(separator, offset); offset += separator.length;
  data.set(codeBytes, offset);

  const cryptoKey = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", cryptoKey, data);
  return htotpB64uEncode(mac);
}
