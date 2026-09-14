(async function () {
  const statusEl = document.getElementById("htotp-status");
  const data = window.HTOTP_ENROLL_DATA;

  function fail(msg) {
    statusEl.textContent = msg;
    htotpSubmitForm("kc-htotp-register-form", { outcome: "failure", errorMessage: msg });
  }

  if (!window.PublicKeyCredential || !navigator.credentials) {
    fail("WebAuthn is not available in this browser.");
    return;
  }
  if (!window.isSecureContext) {
    fail("Secure HTTPS context required.");
    return;
  }

  try {
    statusEl.textContent = "Creating passkey...";

    const prfSalt = htotpRandomBytes(32);
    const userId = htotpRandomBytes(32);
    const createChallenge = htotpB64uDecode(data.createChallenge);
    const assertionChallenge = htotpB64uDecode(data.assertionChallenge);

    const created = await navigator.credentials.create({
      publicKey: {
        challenge: createChallenge,
        rp: { name: "ZeroOTP Hardware TOTP", id: data.rpId },
        user: { id: userId, name: data.username, displayName: data.username },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 } // ES256: interoperable with current WebKit getPublicKey()
        ],
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required"
        },
        hints: ["client-device", "security-key"],
        attestation: "direct",
        extensions: { prf: { eval: { first: prfSalt } } },
        timeout: 120000
      }
    });

    if (!created) {
      fail("Passkey creation cancelled.");
      return;
    }

    if (!created.response.getPublicKey || !created.response.getPublicKeyAlgorithm) {
      fail("This browser cannot export the WebAuthn public key required for server-side assertion verification.");
      return;
    }

    const publicKeyDer = created.response.getPublicKey();
    const publicKeyAlgorithm = created.response.getPublicKeyAlgorithm();
    if (!publicKeyDer || publicKeyAlgorithm !== -7) {
      fail("The WebAuthn credential uses an unsupported public-key algorithm.");
      return;
    }

    const authenticatorData = created.response.getAuthenticatorData
      ? created.response.getAuthenticatorData()
      : null;
    const meta = authenticatorData
      ? htotpParseAuthenticatorData(authenticatorData)
      : { backupEligible: null, backupState: null, aaguid: null };

    statusEl.textContent = "Verifying PRF and WebAuthn assertion...";

    // One assertion performs both operations: it returns the WebAuthn signature
    // that Keycloak will verify and the PRF output used to seal the local TOTP secret.
    const asserted = await navigator.credentials.get({
      publicKey: {
        challenge: assertionChallenge,
        rpId: data.rpId,
        allowCredentials: [{ type: "public-key", id: created.rawId }],
        userVerification: "required",
        extensions: { prf: { eval: { first: prfSalt } } },
        timeout: 120000
      }
    });

    if (!asserted || !asserted.response) {
      fail("WebAuthn enrollment assertion failed.");
      return;
    }

    const prfResults = asserted.getClientExtensionResults ? asserted.getClientExtensionResults().prf : null;
    const prfOutput = prfResults && prfResults.results ? prfResults.results.first : null;
    if (!prfOutput || prfOutput.byteLength < 32) {
      fail("This authenticator does not provide the required WebAuthn PRF output.");
      return;
    }

    const hkdfSalt = htotpRandomBytes(32);
    const key = await htotpDeriveAesKey(prfOutput, hkdfSalt);
    const record = await htotpEncrypt(key, { secret: data.secret, issuer: data.issuer });

    const vaultRecord = {
      credentialId: htotpB64uEncode(created.rawId),
      prfSalt: htotpB64uEncode(prfSalt),
      hkdfSalt: htotpB64uEncode(hkdfSalt),
      iv: record.iv,
      ct: record.ct
    };
    localStorage.setItem(HTOTP_STORAGE_PREFIX + data.rpId, JSON.stringify(vaultRecord));

    statusEl.textContent = "Configuration completed.";
    htotpSubmitForm("kc-htotp-register-form", {
      outcome: "success",
      credentialId: vaultRecord.credentialId,
      publicKeyDer: htotpB64uEncode(publicKeyDer),
      publicKeyAlgorithm: publicKeyAlgorithm,
      assertionCredentialId: htotpB64uEncode(asserted.rawId),
      assertionClientDataJSON: htotpB64uEncode(asserted.response.clientDataJSON),
      assertionAuthenticatorData: htotpB64uEncode(asserted.response.authenticatorData),
      assertionSignature: htotpB64uEncode(asserted.response.signature),
      aaguid: meta.aaguid,
      attestationFormat: htotpB64uEncode(created.response.attestationObject),
      backupEligible: meta.backupEligible,
      backupState: meta.backupState
    });
  } catch (e) {
    fail("Enrollment failed: " + e.message);
  }
})();
