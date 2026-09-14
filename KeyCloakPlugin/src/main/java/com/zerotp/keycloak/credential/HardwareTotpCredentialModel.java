package com.zerotp.keycloak.credential;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.keycloak.credential.CredentialModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;

/**
 * Dati custom associati alla credenziale "hardware-prf-totp".
 *
 * IMPORTANTE: questa classe DEVE estendere CredentialModel — e' un vincolo
 * dei generics di CredentialProvider<T extends CredentialModel> nella SPI
 * Keycloak, non una scelta stilistica. Un DTO indipendente con conversioni
 * statiche (la versione precedente di questo file) non soddisfa quel
 * vincolo e non compila — confermato dall'errore reale ottenuto in build.
 *
 * Il segreto TOTP (secretKey) vive in DUE punti, come da architettura
 * concordata:
 *   1. Qui (parte "secretData" del CredentialModel) — usato per la verifica.
 *   2. Nel browser dell'utente, cifrato con una chiave derivata da PRF —
 *      Keycloak non vede mai quella copia, ne' la chiave di cifratura.
 *
 * I campi aaguid/be/bs sono metadati del passkey usato per l'enrollment,
 * conservati per visibilita'/audit in console admin — NON usati per
 * bloccare l'enrollment (vedi nota nel Provider sul flag BE inaffidabile
 * su alcune piattaforme).
 *
 * enrollmentOrigin: l'origine (schema+host+porta) da cui e' avvenuto
 * l'enrollment — utile in debug per scoprire esattamente il tipo di
 * problema gia' incontrato in test (es. enrollment su "localhost", login
 * tentato da "127.0.0.1": stesso servizio, ma localStorage isolato per
 * origine esatta, quindi la chiave locale non si trova mai). Viene anche
 * riportato nello userLabel, cosi' e' visibile direttamente nella lista
 * Credentials della console admin e nell'Account Console dell'utente,
 * senza bisogno di ispezionare il JSON grezzo.
 */
public class HardwareTotpCredentialModel extends CredentialModel {

    public static final String CREDENTIAL_TYPE = "hardware-prf-totp";

    private String secretKey;      // base32, RFC 6238
    private int digits = 6;
    private int period = 30;
    private String algorithm = "HmacSHA1";

    // Metadati del passkey usato per proteggere la copia lato client.
    private String credentialIdWebAuthn;   // WebAuthn credential ID (base64url)
    private String aaguid;
    private Boolean backupEligible;        // flag BE al momento dell'enrollment
    private Boolean backupState;           // flag BS al momento dell'enrollment
    private String attestationFormat;
    private String enrollmentOrigin;
    private String rpId;
    private String publicKeyDer;          // SubjectPublicKeyInfo DER, base64url
    private Integer publicKeyAlgorithm;  // COSE algorithm id, e.g. -7 ES256

    public static HardwareTotpCredentialModel create(String secretKey, String credentialIdWebAuthn,
                                                       String aaguid, Boolean backupEligible,
                                                       Boolean backupState, String attestationFormat,
                                                       String enrollmentOrigin, String rpId,
                                                       String publicKeyDer, Integer publicKeyAlgorithm) {
        HardwareTotpCredentialModel model = new HardwareTotpCredentialModel();
        model.secretKey = secretKey;
        model.credentialIdWebAuthn = credentialIdWebAuthn;
        model.aaguid = aaguid;
        model.backupEligible = backupEligible;
        model.backupState = backupState;
        model.attestationFormat = attestationFormat;
        model.enrollmentOrigin = enrollmentOrigin;
        model.rpId = rpId;
        model.publicKeyDer = publicKeyDer;
        model.publicKeyAlgorithm = publicKeyAlgorithm;

        model.setType(CREDENTIAL_TYPE);
        model.setCreatedDate(System.currentTimeMillis());
        model.setUserLabel("Hardware TOTP (PRF)" + (enrollmentOrigin != null ? " \u2014 " + enrollmentOrigin : ""));
        model.fillCredentialModelFields();
        return model;
    }

    /** Ricostruisce i campi custom deserializzando da un CredentialModel gia' caricato da storage. */
    public static HardwareTotpCredentialModel createFromCredentialModel(CredentialModel baseModel) {
        HardwareTotpCredentialModel model = new HardwareTotpCredentialModel();
        model.setId(baseModel.getId());
        model.setType(baseModel.getType());
        model.setCreatedDate(baseModel.getCreatedDate());
        model.setUserLabel(baseModel.getUserLabel());
        model.setSecretData(baseModel.getSecretData());
        model.setCredentialData(baseModel.getCredentialData());

        try {
            SecretData secretData = JsonSerialization.readValue(baseModel.getSecretData(), SecretData.class);
            CredentialData credentialData = JsonSerialization.readValue(baseModel.getCredentialData(), CredentialData.class);

            model.secretKey = secretData.value;
            model.digits = credentialData.digits;
            model.period = credentialData.period;
            model.algorithm = credentialData.algorithm;
            model.credentialIdWebAuthn = credentialData.credentialId;
            model.aaguid = credentialData.aaguid;
            model.backupEligible = credentialData.backupEligible;
            model.backupState = credentialData.backupState;
            model.attestationFormat = credentialData.attestationFormat;
            model.enrollmentOrigin = credentialData.enrollmentOrigin;
            model.rpId = credentialData.rpId;
            model.publicKeyDer = credentialData.publicKeyDer;
            model.publicKeyAlgorithm = credentialData.publicKeyAlgorithm;
        } catch (IOException e) {
            throw new RuntimeException("Impossibile deserializzare HardwareTotpCredentialModel", e);
        }
        return model;
    }

    /** Serializza i campi custom nelle proprieta' secretData/credentialData ereditate. */
    private void fillCredentialModelFields() {
        try {
            setSecretData(JsonSerialization.writeValueAsString(new SecretData(secretKey)));
            setCredentialData(JsonSerialization.writeValueAsString(new CredentialData(
                    digits, period, algorithm, credentialIdWebAuthn, aaguid, backupEligible, backupState,
                    attestationFormat, enrollmentOrigin, rpId, publicKeyDer, publicKeyAlgorithm)));
        } catch (IOException e) {
            throw new RuntimeException("Impossibile serializzare HardwareTotpCredentialModel", e);
        }
    }

    // ---- getters ----
    public String getSecretKey() { return secretKey; }
    public int getDigits() { return digits; }
    public int getPeriod() { return period; }
    public String getAlgorithm() { return algorithm; }
    public String getCredentialIdWebAuthn() { return credentialIdWebAuthn; }
    public String getAaguid() { return aaguid; }
    public Boolean getBackupEligible() { return backupEligible; }
    public Boolean getBackupState() { return backupState; }
    public String getAttestationFormat() { return attestationFormat; }
    public String getEnrollmentOrigin() { return enrollmentOrigin; }
    public String getRpId() { return rpId; }
    public String getPublicKeyDer() { return publicKeyDer; }
    public Integer getPublicKeyAlgorithm() { return publicKeyAlgorithm; }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class SecretData {
        public String value;
        public SecretData() {}
        public SecretData(String value) { this.value = value; }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    static class CredentialData {
        public int digits;
        public int period;
        public String algorithm;
        public String credentialId;
        public String aaguid;
        public Boolean backupEligible;
        public Boolean backupState;
        public String attestationFormat;
        public String enrollmentOrigin;
        public String rpId;
        public String publicKeyDer;
        public Integer publicKeyAlgorithm;

        public CredentialData() {}
        public CredentialData(int digits, int period, String algorithm, String credentialId,
                               String aaguid, Boolean backupEligible, Boolean backupState,
                               String attestationFormat, String enrollmentOrigin, String rpId,
                               String publicKeyDer, Integer publicKeyAlgorithm) {
            this.digits = digits;
            this.period = period;
            this.algorithm = algorithm;
            this.credentialId = credentialId;
            this.aaguid = aaguid;
            this.backupEligible = backupEligible;
            this.backupState = backupState;
            this.attestationFormat = attestationFormat;
            this.enrollmentOrigin = enrollmentOrigin;
            this.rpId = rpId;
            this.publicKeyDer = publicKeyDer;
            this.publicKeyAlgorithm = publicKeyAlgorithm;
        }
    }
}
