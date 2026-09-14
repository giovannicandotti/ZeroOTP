(function () {
  const statusEl = document.getElementById("htotp-status");
  const retryBtn = document.getElementById("htotp-retry-btn");
  const data = window.HTOTP_LOGIN_DATA;

  function fail(msg) {
    statusEl.textContent = msg;
    retryBtn.style.display = "inline-block";
    htotpSubmitForm("kc-htotp-login-form", { outcome: "failure", errorMessage: msg });
  }

  async function attemptUnlock() {
    retryBtn.style.display = "none";

    if (!window.PublicKeyCredential || !navigator.credentials) {
      fail("WebAuthn non disponibile in questo browser.");
      return;
    }

    const raw = localStorage.getItem(HTOTP_STORAGE_PREFIX + data.rpId);
    if (!raw) {
      fail("Nessuna chiave locale trovata su questo dispositivo/browser per questo TOTP hardware. " +
           "Usa il dispositivo su cui hai completato l'enrollment, oppure accedi con la password.");
      return;
    }

    let vaultRecord;
    try {
      vaultRecord = JSON.parse(raw);
    } catch (e) {
      fail("Dati locali corrotti. Ripeti l'enrollment.");
      return;
    }

    try {
      statusEl.textContent = "Verifica biometrica in corso\u2026";

      const prfSalt = htotpB64uDecode(vaultRecord.prfSalt);
      const credId = htotpB64uDecode(vaultRecord.credentialId);
      const serverChallenge = htotpB64uDecode(data.serverChallenge);

      // The WebAuthn ceremony now uses the challenge issued by Keycloak,
      // instead of a client-generated random value.
      const asserted = await navigator.credentials.get({
        publicKey: {
          challenge: serverChallenge,
          allowCredentials: [{ type: "public-key", id: credId }],
          userVerification: "required",
          extensions: { prf: { eval: { first: prfSalt } } },
          timeout: 120000
        }
      });

      const prfResults = asserted.getClientExtensionResults ? asserted.getClientExtensionResults().prf : null;
      const prfOutput = prfResults && prfResults.results ? prfResults.results.first : null;

      if (!prfOutput) {
        fail("Verifica PRF non riuscita. Riprova, oppure accedi con la password.");
        return;
      }

      const hkdfSalt = htotpB64uDecode(vaultRecord.hkdfSalt);
      const key = await htotpDeriveAesKey(prfOutput, hkdfSalt);
      const plain = await htotpDecrypt(key, vaultRecord);

      const code = await htotpComputeCode(plain.secret, 6, 30);
      const sessionProof = await htotpComputeSessionProof(plain.secret, data.serverChallenge, code);

      statusEl.textContent = "Verifica completata.";
      htotpSubmitForm("kc-htotp-login-form", {
        outcome: "success",
        totpCode: code,
        sessionProof: sessionProof,
        assertionCredentialId: htotpB64uEncode(asserted.rawId),
        assertionClientDataJSON: htotpB64uEncode(asserted.response.clientDataJSON),
        assertionAuthenticatorData: htotpB64uEncode(asserted.response.authenticatorData),
        assertionSignature: htotpB64uEncode(asserted.response.signature)
      });
    } catch (e) {
      fail("Sblocco fallito: " + e.message);
    }
  }

  retryBtn.addEventListener("click", attemptUnlock);

  if (!data.isRetry) {
    attemptUnlock();
  } else {
    statusEl.textContent = "Premi \"Riprova con passkey\" per tentare di nuovo, oppure torna indietro e usa la password.";
    retryBtn.style.display = "inline-block";
  }
})();
