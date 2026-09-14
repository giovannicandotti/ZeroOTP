package com.zerotp.keycloak.credential;

import com.zerotp.keycloak.util.Base32Util;
import com.zerotp.keycloak.util.WebAuthnAssertionVerifier;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.HmacOTP;

import java.util.List;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

/**
 * Provider per la credenziale custom "hardware-prf-totp".
 *
 * La verifica del codice riusa {@link HmacOTP}, la stessa classe usata
 * internamente dal provider OTP nativo di Keycloak per l'algoritmo
 * RFC 6238 — non reinventiamo l'HMAC-based OTP qui.
 *
 * NOTA SUL FLAG BE (backup eligible): questo provider registra il flag
 * riportato al momento dell'enrollment per visibilita' in console admin,
 * ma NON lo usa per bloccare l'enrollment. E' un dato noto per essere
 * inaffidabile su alcune piattaforme (es. Apple puo' riportare BE=1/BS=1
 * anche per credenziali che sono di fatto device-bound). Il device-binding
 * "richiesto" avviene lato client tramite gli authenticatorSelection/hints
 * usati in fase di creazione (vedi risorse JS), non tramite un controllo
 * server-side su questo flag.
 */
public class HardwareTotpCredentialProvider implements CredentialProvider<HardwareTotpCredentialModel>, CredentialInputValidator {

    private static final Logger logger = Logger.getLogger(HardwareTotpCredentialProvider.class);

    protected KeycloakSession session;

    public HardwareTotpCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return HardwareTotpCredentialModel.CREDENTIAL_TYPE;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, HardwareTotpCredentialModel credentialModel) {
        // credentialModel E' GIA' un CredentialModel (estende la classe base),
        // non serve nessuna conversione/wrapping — a differenza della prima
        // versione, che usava un DTO separato non compatibile con i generics.
        return user.credentialManager().createStoredCredential(credentialModel);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    @Override
    public HardwareTotpCredentialModel getCredentialFromModel(CredentialModel model) {
        return HardwareTotpCredentialModel.createFromCredentialModel(model);
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {
        return CredentialTypeMetadata.builder()
                .type(getType())
                .category(CredentialTypeMetadata.Category.TWO_FACTOR)
                .displayName("hardware-prf-totp-display-name")
                .helpText("hardware-prf-totp-help-text")
                .createAction("hardware-prf-totp-register")
                .removeable(true)
                .build(session);
    }

    // ------------------------------------------------------------------
    // CredentialInputValidator
    // ------------------------------------------------------------------

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return HardwareTotpCredentialModel.CREDENTIAL_TYPE.equals(credentialType);
    }

    /**
     * Usato dal flow engine per decidere se questa alternativa e' applicabile
     * all'utente corrente: se false, l'authenticator viene SALTATO e Keycloak
     * prova l'alternativa successiva (Password Form). Questo e' esattamente
     * il meccanismo richiesto: "il TOTP non funzionera' per l'utente che non
     * lo ha ancora configurato" — nessuna logica custom aggiuntiva necessaria.
     */
    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) return false;
        return user.credentialManager()
                .getStoredCredentialsByTypeStream(HardwareTotpCredentialModel.CREDENTIAL_TYPE)
                .findAny()
                .isPresent();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) return false;

        List<HardwareTotpCredentialModel> credentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(HardwareTotpCredentialModel.CREDENTIAL_TYPE)
                .map(HardwareTotpCredentialModel::createFromCredentialModel)
                .collect(Collectors.toList());

        if (credentials.isEmpty()) {
            return false;
        }

        String submittedCode = input.getChallengeResponse();
        if (submittedCode == null || submittedCode.isBlank()) {
            return false;
        }

        for (HardwareTotpCredentialModel credential : credentials) {
            // lookAroundWindow=1: accetta lo step precedente/successivo per
            // tollerare piccoli drift di orologio, come fa il provider OTP nativo.
            HmacOTP validator = new HmacOTP(credential.getDigits(), credential.getAlgorithm(), 1);
            byte[] secretBytes = Base32Util.decode(credential.getSecretKey());
            int counter = (int) (System.currentTimeMillis() / 1000L / credential.getPeriod());
            if (validator.validateHOTP(submittedCode, secretBytes, counter) != -1) {
                return true;
            }
        }
        return false;
    }


    /**
     * Validates both the standard RFC 6238 TOTP and the per-session proof.
     * A six-digit TOTP captured from one authentication session is therefore
     * not sufficient to authenticate in another session.
     */
    public boolean isValidBound(RealmModel realm, UserModel user, String submittedCode,
                                String serverChallenge, String submittedProof,
                                String assertionCredentialId, String assertionClientDataJSON,
                                String assertionAuthenticatorData, String assertionSignature) {
        if (submittedCode == null || submittedCode.isBlank() ||
                serverChallenge == null || serverChallenge.isBlank() ||
                submittedProof == null || submittedProof.isBlank() ||
                assertionCredentialId == null || assertionCredentialId.isBlank()) {
            return false;
        }

        List<HardwareTotpCredentialModel> credentials = user.credentialManager()
                .getStoredCredentialsByTypeStream(HardwareTotpCredentialModel.CREDENTIAL_TYPE)
                .map(HardwareTotpCredentialModel::createFromCredentialModel)
                .collect(Collectors.toList());

        for (HardwareTotpCredentialModel credential : credentials) {
            // v1.2+ credentials must contain the WebAuthn verification material.
            if (credential.getPublicKeyDer() == null || credential.getPublicKeyAlgorithm() == null ||
                    credential.getRpId() == null || credential.getEnrollmentOrigin() == null) {
                continue;
            }

            if (!WebAuthnAssertionVerifier.verify(
                    credential.getCredentialIdWebAuthn(),
                    serverChallenge,
                    credential.getEnrollmentOrigin(),
                    credential.getRpId(),
                    credential.getPublicKeyDer(),
                    credential.getPublicKeyAlgorithm(),
                    assertionCredentialId,
                    assertionClientDataJSON,
                    assertionAuthenticatorData,
                    assertionSignature)) {
                continue;
            }

            HmacOTP validator = new HmacOTP(credential.getDigits(), credential.getAlgorithm(), 1);
            byte[] secretBytes = Base32Util.decode(credential.getSecretKey());
            int counter = (int) (System.currentTimeMillis() / 1000L / credential.getPeriod());
            if (validator.validateHOTP(submittedCode, secretBytes, counter) == -1) {
                continue;
            }

            byte[] expectedProof = computeSessionProof(secretBytes, serverChallenge, submittedCode);
            byte[] receivedProof;
            try {
                receivedProof = Base64.getUrlDecoder().decode(padBase64Url(submittedProof));
            } catch (IllegalArgumentException e) {
                return false;
            }

            if (MessageDigest.isEqual(expectedProof, receivedProof)) {
                return true;
            }
        }
        return false;
    }

    private byte[] computeSessionProof(byte[] secretBytes, String challenge, String code) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secretBytes, "HmacSHA256"));
            mac.update("zerotp-session-v1\0".getBytes(StandardCharsets.UTF_8));
            mac.update(challenge.getBytes(StandardCharsets.UTF_8));
            mac.update((byte) 0);
            mac.update(code.getBytes(StandardCharsets.UTF_8));
            return mac.doFinal();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to calculate ZeroOTP session proof", e);
        }
    }

    private String padBase64Url(String value) {
        int mod = value.length() % 4;
        if (mod == 0) return value;
        return value + "=".repeat(4 - mod);
    }

    // Helper usato dall'Authenticator per verificare rapidamente se esiste
    // almeno una credenziale hardware-prf-totp per l'utente.
    public boolean hasCredential(RealmModel realm, UserModel user) {
        return isConfiguredFor(realm, user, HardwareTotpCredentialModel.CREDENTIAL_TYPE);
    }

    @Override
    public void close() {
        // no-op
    }
}
