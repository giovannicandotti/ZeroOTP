package com.zerotp.keycloak.authenticator;

import com.zerotp.keycloak.credential.HardwareTotpCredentialModel;
import com.zerotp.keycloak.credential.HardwareTotpCredentialProvider;
import com.zerotp.keycloak.credential.HardwareTotpCredentialProviderFactory;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import java.util.Base64;

import java.security.SecureRandom;

/**
 * Hardware PRF protected TOTP authenticator.
 *
 * v1.1 adds server-issued, per-authentication-session challenge binding.
 * The browser still computes a standard RFC 6238 TOTP, but it must also
 * return HMAC-SHA256(TOTP-secret, protocol-label || challenge || TOTP).
 * This makes a captured six-digit code unusable in a different Keycloak
 * authentication session while preserving RFC 6238 compatibility.
 */
public class HardwareTotpAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(HardwareTotpAuthenticator.class);
    private static final String AUTH_NOTE_CHALLENGE = "HARDWARE_TOTP_LOGIN_CHALLENGE";
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();

        if (user == null || !configuredFor(context.getSession(), realm, user)) {
            context.attempted();
            return;
        }

        context.challenge(loginForm(context, false, null));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String outcome = formData.getFirst("outcome");

        if (!"success".equals(outcome)) {
            String errorMessage = formData.getFirst("errorMessage");
            logger.warnf("Hardware PRF TOTP unlock failed for user %s: %s",
                    context.getUser() != null ? context.getUser().getUsername() : "?", errorMessage);
            context.challenge(loginForm(context, true,
                    errorMessage != null ? errorMessage : "Sblocco fallito."));
            return;
        }

        String code = formData.getFirst("totpCode");
        String sessionProof = formData.getFirst("sessionProof");
        String assertionCredentialId = formData.getFirst("assertionCredentialId");
        String assertionClientDataJSON = formData.getFirst("assertionClientDataJSON");
        String assertionAuthenticatorData = formData.getFirst("assertionAuthenticatorData");
        String assertionSignature = formData.getFirst("assertionSignature");
        String challenge = context.getAuthenticationSession().getAuthNote(AUTH_NOTE_CHALLENGE);

        if (code == null || code.isBlank() || sessionProof == null || sessionProof.isBlank() || challenge == null ||
                assertionCredentialId == null || assertionCredentialId.isBlank() ||
                assertionClientDataJSON == null || assertionClientDataJSON.isBlank() ||
                assertionAuthenticatorData == null || assertionAuthenticatorData.isBlank() ||
                assertionSignature == null || assertionSignature.isBlank()) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    loginForm(context, true, "Risposta crittografica incompleta o sessione scaduta."));
            return;
        }

        HardwareTotpCredentialProvider provider = (HardwareTotpCredentialProvider)
                context.getSession().getProvider(CredentialProvider.class,
                        HardwareTotpCredentialProviderFactory.PROVIDER_ID);

        boolean valid = provider.isValidBound(
                context.getRealm(), context.getUser(), code, challenge, sessionProof,
                assertionCredentialId, assertionClientDataJSON, assertionAuthenticatorData, assertionSignature);

        // Challenge is single-use irrespective of success/failure.
        context.getAuthenticationSession().removeAuthNote(AUTH_NOTE_CHALLENGE);

        if (valid) {
            context.success();
        } else {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    loginForm(context, true, "WebAuthn assertion, TOTP, or session binding is invalid."));
        }
    }

    private Response loginForm(AuthenticationFlowContext context, boolean isRetry, String errorMessage) {
        String challenge = newChallenge();
        context.getAuthenticationSession().setAuthNote(AUTH_NOTE_CHALLENGE, challenge);

        var form = context.form()
                .setAttribute("rpId", context.getUriInfo().getBaseUri().getHost())
                .setAttribute("serverChallenge", challenge)
                .setAttribute("isRetry", isRetry);
        if (errorMessage != null) {
            form.setError(errorMessage);
        }
        return form.createForm("hardware-totp-login.ftl");
    }

    private String newChallenge() {
        byte[] value = new byte[32];
        RANDOM.nextBytes(value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        HardwareTotpCredentialProvider provider = (HardwareTotpCredentialProvider) session.getProvider(
                CredentialProvider.class, HardwareTotpCredentialProviderFactory.PROVIDER_ID);
        return provider != null && provider.hasCredential(realm, user);
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }
}
