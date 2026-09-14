package com.zerotp.keycloak.authenticator;

import com.zerotp.keycloak.credential.HardwareTotpCredentialModel;
import com.zerotp.keycloak.credential.HardwareTotpCredentialProvider;
import com.zerotp.keycloak.credential.HardwareTotpCredentialProviderFactory;
import com.zerotp.keycloak.util.Base32Util;
import com.zerotp.keycloak.util.WebAuthnAssertionVerifier;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialProvider;

import java.security.SecureRandom;
import java.util.Base64;

/** Enrollment for the ZeroOTP hardware-prf-totp credential. */
public class HardwareTotpEnrollRequiredAction implements RequiredActionProvider {

    private static final Logger logger = Logger.getLogger(HardwareTotpEnrollRequiredAction.class);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String AUTH_NOTE_SECRET = "HARDWARE_TOTP_PENDING_SECRET";
    private static final String AUTH_NOTE_ORIGIN = "HARDWARE_TOTP_PENDING_ORIGIN";
    private static final String AUTH_NOTE_RPID = "HARDWARE_TOTP_PENDING_RPID";
    private static final String AUTH_NOTE_CREATE_CHALLENGE = "HARDWARE_TOTP_CREATE_CHALLENGE";
    private static final String AUTH_NOTE_ASSERT_CHALLENGE = "HARDWARE_TOTP_ENROLL_ASSERT_CHALLENGE";

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        // Explicit self-service/admin enrollment only.
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        String secret = generateBase32Secret();
        String rpId = context.getUriInfo().getBaseUri().getHost();
        String origin = buildOrigin(context);
        String createChallenge = newChallenge();
        String assertionChallenge = newChallenge();

        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_SECRET, secret);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_ORIGIN, origin);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_RPID, rpId);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_CREATE_CHALLENGE, createChallenge);
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_ASSERT_CHALLENGE, assertionChallenge);

        Response challenge = context.form()
                .setAttribute("secret", secret)
                .setAttribute("issuer", context.getRealm().getName())
                .setAttribute("username", context.getUser().getUsername())
                .setAttribute("rpId", rpId)
                .setAttribute("createChallenge", createChallenge)
                .setAttribute("assertionChallenge", assertionChallenge)
                .createForm("hardware-totp-register.ftl");
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String outcome = formData.getFirst("outcome");

        if (!"success".equals(outcome)) {
            String errorMessage = formData.getFirst("errorMessage");
            logger.warnf("Enrollment hardware-prf-totp failed for user %s: %s",
                    context.getUser().getUsername(), errorMessage);
            requiredActionChallengeWithError(context, errorMessage);
            return;
        }

        String secret = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_SECRET);
        String origin = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_ORIGIN);
        String rpId = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_RPID);
        String assertionChallenge = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_ASSERT_CHALLENGE);
        if (secret == null || origin == null || rpId == null || assertionChallenge == null) {
            requiredActionChallengeWithError(context, "Enrollment session expired. Retry enrollment.");
            return;
        }

        String credentialId = formData.getFirst("credentialId");
        String publicKeyDer = formData.getFirst("publicKeyDer");
        Integer publicKeyAlgorithm = parseInteger(formData.getFirst("publicKeyAlgorithm"));
        String assertionCredentialId = formData.getFirst("assertionCredentialId");
        String assertionClientDataJSON = formData.getFirst("assertionClientDataJSON");
        String assertionAuthenticatorData = formData.getFirst("assertionAuthenticatorData");
        String assertionSignature = formData.getFirst("assertionSignature");

        if (publicKeyAlgorithm == null || publicKeyAlgorithm != -7) {
            requiredActionChallengeWithError(context, "Unsupported WebAuthn public-key algorithm.");
            return;
        }

        boolean assertionValid = WebAuthnAssertionVerifier.verify(
                credentialId,
                assertionChallenge,
                origin,
                rpId,
                publicKeyDer,
                publicKeyAlgorithm,
                assertionCredentialId,
                assertionClientDataJSON,
                assertionAuthenticatorData,
                assertionSignature);
        if (!assertionValid) {
            logger.warnf("Enrollment WebAuthn assertion verification failed for user %s",
                    context.getUser().getUsername());
            requiredActionChallengeWithError(context, "WebAuthn enrollment verification failed.");
            return;
        }

        String aaguid = formData.getFirst("aaguid");
        String attestationFormat = formData.getFirst("attestationFormat");
        Boolean backupEligible = parseBoolOrNull(formData.getFirst("backupEligible"));
        Boolean backupState = parseBoolOrNull(formData.getFirst("backupState"));

        HardwareTotpCredentialModel model = HardwareTotpCredentialModel.create(
                secret, credentialId, aaguid, backupEligible, backupState, attestationFormat,
                origin, rpId, publicKeyDer, publicKeyAlgorithm);

        HardwareTotpCredentialProvider provider = (HardwareTotpCredentialProvider)
                context.getSession().getProvider(CredentialProvider.class,
                        HardwareTotpCredentialProviderFactory.PROVIDER_ID);
        provider.createCredential(context.getRealm(), context.getUser(), model);

        clearEnrollmentNotes(context);
        context.success();
    }

    private void clearEnrollmentNotes(RequiredActionContext context) {
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_SECRET);
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_ORIGIN);
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_RPID);
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_CREATE_CHALLENGE);
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_ASSERT_CHALLENGE);
    }

    private String buildOrigin(RequiredActionContext context) {
        var base = context.getUriInfo().getBaseUri();
        StringBuilder sb = new StringBuilder();
        sb.append(base.getScheme()).append("://").append(base.getHost());
        if (base.getPort() != -1) sb.append(":").append(base.getPort());
        return sb.toString();
    }

    private void requiredActionChallengeWithError(RequiredActionContext context, String errorMessage) {
        Response challenge = context.form()
                .setError(errorMessage != null ? errorMessage : "Enrollment failed.")
                .createForm("hardware-totp-register-error.ftl");
        context.challenge(challenge);
    }

    private Boolean parseBoolOrNull(String s) {
        return s == null || s.isBlank() ? null : Boolean.parseBoolean(s);
    }

    private Integer parseInteger(String s) {
        try {
            return s == null || s.isBlank() ? null : Integer.valueOf(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private String generateBase32Secret() {
        byte[] buffer = new byte[20];
        RANDOM.nextBytes(buffer);
        return Base32Util.encode(buffer);
    }

    private String newChallenge() {
        byte[] value = new byte[32];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    @Override
    public void close() {
        // no-op
    }
}
