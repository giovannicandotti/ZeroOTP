package com.zerotp.keycloak.credential;

import org.keycloak.Config;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class HardwareTotpCredentialProviderFactory implements CredentialProviderFactory<HardwareTotpCredentialProvider> {

    public static final String PROVIDER_ID = "hardware-prf-totp";

    @Override
    public HardwareTotpCredentialProvider create(KeycloakSession session) {
        return new HardwareTotpCredentialProvider(session);
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
}
