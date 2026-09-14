/*
 * auth2 - biometric.js
 * -------------------------------------------------------------------------
 * Biometric-gated local vault for the TOTP secret, with NO master password.
 *
 * PRIMARY MODE ("prf"):
 *   Uses the WebAuthn PRF extension (CTAP2 hmac-secret). The authenticator
 *   holds a credential-bound secret in hardware (Secure Enclave / TPM /
 *   security key) and computes HMAC(credSecret, salt) only after a successful
 *   user-verification ceremony. The 32-byte output is deterministic, so it
 *   can be used as key material - but it does not exist anywhere until the
 *   user presents biometrics. Nothing derivable from disk alone.
 *
 *   prfOutput --HKDF-SHA256--> AES-256-GCM key --> encrypt/decrypt vault
 *
 * FALLBACK MODE ("gate"):
 *   Used only when PRF is unavailable. A non-extractable AES-GCM CryptoKey
 *   is kept in IndexedDB and a WebAuthn assertion is required before use.
 *   *** This is an application-logic gate, NOT a cryptographic binding. ***
 *   See SECURITY NOTE at the bottom of this file. Clearly labelled in the UI.
 *
 * Style note: this new file uses const/let and async/await because the
 * WebAuthn and WebCrypto APIs are promise-based. Existing files are untouched.
 */
/*global window, document, navigator, crypto, localStorage, indexedDB, TextEncoder, TextDecoder, PublicKeyCredential*/

(function (global) {
  "use strict";

  // ---------------------------------------------------------------- config
  const LS_RECORD   = "bioVaultRecord";   // encrypted vault + metadata
  const HKDF_INFO   = "auth2-totp-vault-v1";
  const IDB_NAME    = "auth2vault";
  const IDB_STORE   = "keys";
  const IDB_KEY_ID  = "wrapKey";
  const RP_NAME     = "ZeroOTP";           // shown to the user during passkey creation
  const USER_LABEL  = "auth2-vault";

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ------------------------------------------------------- base64url utils
  function b64uEncode(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64uDecode(str) {
    const pad = str.replace(/-/g, "+").replace(/_/g, "/");
    const padded = pad + "=".repeat((4 - (pad.length % 4)) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
    return out;
  }

  function randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  // ------------------------------------------------------------ record I/O
  function loadRecord() {
    const raw = localStorage.getItem(LS_RECORD);
    if (!raw) { return null; }
    try { return JSON.parse(raw); } catch (e) { return null; }
  }

  function saveRecord(rec) {
    localStorage.setItem(LS_RECORD, JSON.stringify(rec));
  }

  function clearRecord() {
    localStorage.removeItem(LS_RECORD);
  }

  // --------------------------------------------------------- capabilities
  /**
   * Probe what this device can actually do.
   * Returns { webauthn, platformAuthenticator, prfLikely, secureContext, reason }
   */
  async function capabilities() {
    const out = {
      webauthn: false,
      platformAuthenticator: false,
      prfLikely: false,
      secureContext: !!global.isSecureContext,
      reason: ""
    };

    if (!global.PublicKeyCredential) {
      out.reason = "WebAuthn is not available in this browser.";
      return out;
    }
    out.webauthn = true;

    if (!out.secureContext) {
      out.reason = "WebAuthn requires a secure context (https:// or http://localhost). " +
                   "file:// will not work.";
      return out;
    }

    try {
      out.platformAuthenticator =
        await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (e) {
      out.platformAuthenticator = false;
    }

    // getClientCapabilities() is the modern probe; not everywhere yet.
    if (typeof PublicKeyCredential.getClientCapabilities === "function") {
      try {
        const caps = await PublicKeyCredential.getClientCapabilities();
        if (typeof caps["extension:prf"] === "boolean") {
          out.prfLikely = caps["extension:prf"];
        } else {
          out.prfLikely = out.platformAuthenticator; // unknown -> optimistic
        }
      } catch (e) {
        out.prfLikely = out.platformAuthenticator;
      }
    } else {
      // No capability API: we can only find out by trying.
      out.prfLikely = out.platformAuthenticator;
    }

    if (!out.platformAuthenticator) {
      out.reason = "No user-verifying platform authenticator (Touch ID / Windows Hello / " +
                   "Android biometrics) detected. A roaming FIDO2 key may still work.";
    }
    return out;
  }

  // ------------------------------------------------------ WebAuthn helpers
  /**
   * Create a discoverable platform credential and request PRF.
   * Returns { credId (Uint8Array), prfEnabled (bool) }.
   */
  async function createCredential(prfSalt) {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: randomBytes(32),
        rp: { name: RP_NAME, id: global.location.hostname },
        user: {
          id: randomBytes(32),
          name: USER_LABEL,
          displayName: RP_NAME
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },   // ES256
          { type: "public-key", alg: -257 }  // RS256
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required"
        },
        timeout: 60000,
        attestation: "none",
        extensions: { prf: { eval: { first: prfSalt } } }
      }
    });

    if (!cred) { throw new Error("Credential creation returned nothing."); }

    const ext = cred.getClientExtensionResults();
    const prfEnabled = !!(ext && ext.prf && ext.prf.enabled);

    return { credId: new Uint8Array(cred.rawId), prfEnabled: prfEnabled };
  }

  /**
   * Assert an existing credential and evaluate PRF.
   * Returns { prfFirst (ArrayBuffer|null) } - biometrics prompted here.
   */
  async function assertWithPrf(credId, prfSalt) {
    const options = {
      publicKey: {
        challenge: randomBytes(32),
        userVerification: "required",
        timeout: 60000,
        extensions: { prf: { eval: { first: prfSalt } } }
      }
    };
    if (credId) {
      options.publicKey.allowCredentials = [
        { type: "public-key", id: credId }
      ];
    }

    const assertion = await navigator.credentials.get(options);
    if (!assertion) { throw new Error("Authentication was cancelled."); }

    const ext = assertion.getClientExtensionResults();
    const first = ext && ext.prf && ext.prf.results ? ext.prf.results.first : null;

    return { prfFirst: first || null, rawId: new Uint8Array(assertion.rawId) };
  }

  // ------------------------------------------------------- key derivation
  /**
   * PRF output (32 bytes) -> AES-256-GCM key, via HKDF-SHA256.
   * The derived key is non-extractable and never persisted.
   */
  async function deriveAesKey(prfOutput, hkdfSalt) {
    const ikm = await crypto.subtle.importKey(
      "raw", prfOutput, "HKDF", false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: hkdfSalt,
        info: enc.encode(HKDF_INFO)
      },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,                       // non-extractable
      ["encrypt", "decrypt"]
    );
  }

  // ------------------------------------------------------- AEAD primitives
  async function aeadEncrypt(key, plaintextObj, aad) {
    const iv = randomBytes(12);
    const pt = enc.encode(JSON.stringify(plaintextObj));
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad },
      key, pt
    );
    return { iv: b64uEncode(iv), ct: b64uEncode(ct) };
  }

  async function aeadDecrypt(key, ivB64u, ctB64u, aad) {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64uDecode(ivB64u), additionalData: aad },
      key, b64uDecode(ctB64u)
    );
    return JSON.parse(dec.decode(pt));
  }

  // ------------------------------------------- IndexedDB (fallback mode)
  function idbOpen() {
    return new Promise(function (resolve, reject) {
      const req = indexedDB.open(IDB_NAME, 1);
      req.onupgradeneeded = function () {
        req.result.createObjectStore(IDB_STORE);
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }

  function idbPut(id, value) {
    return idbOpen().then(function (db) {
      return new Promise(function (resolve, reject) {
        const tx = db.transaction(IDB_STORE, "readwrite");
        tx.objectStore(IDB_STORE).put(value, id);
        tx.oncomplete = function () { db.close(); resolve(true); };
        tx.onerror = function () { db.close(); reject(tx.error); };
      });
    });
  }

  function idbGet(id) {
    return idbOpen().then(function (db) {
      return new Promise(function (resolve, reject) {
        const tx = db.transaction(IDB_STORE, "readonly");
        const rq = tx.objectStore(IDB_STORE).get(id);
        rq.onsuccess = function () { db.close(); resolve(rq.result || null); };
        rq.onerror = function () { db.close(); reject(rq.error); };
      });
    });
  }

  function idbDelete(id) {
    return idbOpen().then(function (db) {
      return new Promise(function (resolve, reject) {
        const tx = db.transaction(IDB_STORE, "readwrite");
        tx.objectStore(IDB_STORE).delete(id);
        tx.oncomplete = function () { db.close(); resolve(true); };
        tx.onerror = function () { db.close(); reject(tx.error); };
      });
    });
  }

  // ================================================================ PUBLIC
  /**
   * Enrol biometrics and seal { issuer, secret } into localStorage.
   * Prompts twice on first run: once to create the credential, once to
   * evaluate the PRF (not all authenticators return PRF output at create
   * time, so we always take the assertion path for consistency).
   */
  async function enroll(issuer, secret) {
    if (!secret) { throw new Error("No TOTP secret to protect."); }

    const caps = await capabilities();
    if (!caps.webauthn)      { throw new Error(caps.reason || "WebAuthn unavailable."); }
    if (!caps.secureContext) { throw new Error(caps.reason); }

    const prfSalt  = randomBytes(32);
    const hkdfSalt = randomBytes(32);

    const created = await createCredential(prfSalt);
    const credId  = created.credId;
    const aad     = credId; // bind ciphertext to this credential

    let mode = "prf";
    let key  = null;

    // Always assert once: PRF results are frequently absent at create() time.
    let prfOutput = null;
    try {
      const asserted = await assertWithPrf(credId, prfSalt);
      prfOutput = asserted.prfFirst;
    } catch (e) {
      throw new Error("Biometric verification failed or was cancelled: " + e.message);
    }

    if (prfOutput && prfOutput.byteLength >= 32) {
      key = await deriveAesKey(prfOutput, hkdfSalt);
    } else {
      // ---- fallback: gate-only mode ----
      mode = "gate";
      key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
      );
      await idbPut(IDB_KEY_ID, key);
    }

    const sealed = await aeadEncrypt(key, { issuer: issuer || "", secret: secret }, aad);

    saveRecord({
      v: 1,
      mode: mode,
      credId: b64uEncode(credId),
      prfSalt: b64uEncode(prfSalt),
      hkdfSalt: b64uEncode(hkdfSalt),
      iv: sealed.iv,
      ct: sealed.ct,
      createdAt: new Date().toISOString()
    });

    return { mode: mode };
  }

  /**
   * Prompt biometrics and return { issuer, secret }.
   */
  async function unlock() {
    const rec = loadRecord();
    if (!rec) { throw new Error("No biometric vault found on this device."); }

    const credId = b64uDecode(rec.credId);
    const aad    = credId;
    let key;

    if (rec.mode === "prf") {
      const asserted = await assertWithPrf(credId, b64uDecode(rec.prfSalt));
      if (!asserted.prfFirst) {
        throw new Error(
          "The authenticator did not return a PRF value. The vault cannot be " +
          "opened on this browser/OS combination. Try the browser used at enrolment."
        );
      }
      key = await deriveAesKey(asserted.prfFirst, b64uDecode(rec.hkdfSalt));
    } else {
      // gate mode: assertion is a policy check, then use the stored key
      await assertWithPrf(credId, b64uDecode(rec.prfSalt));
      key = await idbGet(IDB_KEY_ID);
      if (!key) { throw new Error("Wrapping key missing from IndexedDB."); }
    }

    try {
      return await aeadDecrypt(key, rec.iv, rec.ct, aad);
    } catch (e) {
      throw new Error("Decryption failed - vault corrupted or wrong credential.");
    }
  }

  /**
   * Destroy the vault. The passkey itself must be removed via OS settings.
   */
  async function reset() {
    const rec = loadRecord();
    clearRecord();
    if (rec && rec.mode === "gate") {
      try { await idbDelete(IDB_KEY_ID); } catch (e) { /* best effort */ }
    }
    return true;
  }

  function status() {
    const rec = loadRecord();
    if (!rec) { return { enrolled: false }; }
    return {
      enrolled: true,
      mode: rec.mode,
      createdAt: rec.createdAt,
      credId: rec.credId.slice(0, 12) + "..."
    };
  }

  global.BioVault = {
    capabilities: capabilities,
    enroll: enroll,
    unlock: unlock,
    reset: reset,
    status: status
  };

}(window));

/* -----------------------------------------------------------------------
 * SECURITY NOTE - what each mode actually guarantees
 *
 * mode "prf"   The AES key is a deterministic function of a secret sealed
 *              inside the authenticator. It does not exist in the browser,
 *              on disk, or anywhere else until a user-verification ceremony
 *              succeeds. An attacker with a full copy of localStorage and the
 *              disk gains nothing. This is a genuine cryptographic binding.
 *
 * mode "gate"  The AES key lives in IndexedDB as a non-extractable CryptoKey.
 *              Script cannot export it, so it cannot be exfiltrated as key
 *              material - but any code running on this origin can still call
 *              decrypt() WITHOUT the biometric ceremony. The prompt is
 *              enforced by this file's logic, not by cryptography. It also is
 *              not hardware-backed: the browser stores the raw key in its own
 *              profile on disk. Treat as "better than plaintext", not as
 *              equivalent to PRF.
 *
 * BOTH MODES   userVerification:"required" guarantees *a* user-verification
 *              step, but WebAuthn does not let a relying party demand the
 *              biometric modality specifically. The OS may satisfy UV with a
 *              device PIN or password. There is no API to distinguish them.
 *
 * RECOVERY     A PRF key is bound to one credential. Lose the passkey (device
 *              wiped, iCloud Keychain entry deleted) and the ciphertext is
 *              unrecoverable by design. Always keep the original QR code or
 *              the Master Password path as a backup route.
 * --------------------------------------------------------------------- */
