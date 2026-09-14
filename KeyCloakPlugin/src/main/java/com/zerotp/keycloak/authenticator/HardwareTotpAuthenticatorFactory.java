package com.zerotp.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class HardwareTotpAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "hardware-prf-totp-authenticator";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public Authenticator create(KeycloakSession session) {
        return new HardwareTotpAuthenticator();
    }

    @Override
    public void init(Config.Scope config) { }

    @Override
    public void postInit(KeycloakSessionFactory factory) { }

    @Override
    public void close() { }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Hardware TOTP (passkey + PRF)";
    }

    @Override
    public String getReferenceCategory() {
        return "hardware-totp";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public String getHelpText() {
        return "Autentica con un TOTP il cui segreto e' cifrato localmente da una chiave " +
               "derivata via WebAuthn PRF, sbloccata obbligatoriamente con biometria/PIN a " +
               "ogni utilizzo. Disponibile come alternativa alla password SOLO per gli utenti " +
               "che hanno completato l'enrollment (Required Action hardware-prf-totp-register).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
