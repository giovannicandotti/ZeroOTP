package com.zerotp.keycloak.authenticator;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class HardwareTotpEnrollRequiredActionFactory implements RequiredActionFactory {

    public static final String PROVIDER_ID = "hardware-prf-totp-register";

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new HardwareTotpEnrollRequiredAction();
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
    public String getDisplayText() {
        return "Configura TOTP hardware (passkey + PRF)";
    }
}
