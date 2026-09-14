package com.zerotp.keycloak.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/** Minimal server-side verifier for the WebAuthn assertion already produced by navigator.credentials.get(). */
public final class WebAuthnAssertionVerifier {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int FLAG_UP = 0x01;
    private static final int FLAG_UV = 0x04;

    private WebAuthnAssertionVerifier() {}

    public static boolean verify(
            String expectedCredentialId,
            String expectedChallenge,
            String expectedOrigin,
            String expectedRpId,
            String publicKeyDerB64u,
            int coseAlgorithm,
            String credentialIdB64u,
            String clientDataJsonB64u,
            String authenticatorDataB64u,
            String signatureB64u) {
        try {
            if (isBlank(expectedCredentialId) || isBlank(expectedChallenge) || isBlank(expectedOrigin) ||
                    isBlank(expectedRpId) || isBlank(publicKeyDerB64u) || isBlank(credentialIdB64u) ||
                    isBlank(clientDataJsonB64u) || isBlank(authenticatorDataB64u) || isBlank(signatureB64u)) {
                return false;
            }

            byte[] expectedCredentialIdBytes = decodeB64u(expectedCredentialId);
            byte[] receivedCredentialIdBytes = decodeB64u(credentialIdB64u);
            if (!MessageDigest.isEqual(expectedCredentialIdBytes, receivedCredentialIdBytes)) {
                return false;
            }

            byte[] clientDataJson = decodeB64u(clientDataJsonB64u);
            JsonNode clientData = JSON.readTree(clientDataJson);
            if (!"webauthn.get".equals(text(clientData, "type"))) return false;
            if (!expectedChallenge.equals(text(clientData, "challenge"))) return false;
            if (!expectedOrigin.equals(text(clientData, "origin"))) return false;
            JsonNode crossOrigin = clientData.get("crossOrigin");
            if (crossOrigin != null && crossOrigin.asBoolean(false)) return false;

            byte[] authenticatorData = decodeB64u(authenticatorDataB64u);
            if (authenticatorData.length < 37) return false;

            byte[] expectedRpIdHash = MessageDigest.getInstance("SHA-256")
                    .digest(expectedRpId.getBytes(StandardCharsets.UTF_8));
            byte[] receivedRpIdHash = Arrays.copyOfRange(authenticatorData, 0, 32);
            if (!MessageDigest.isEqual(expectedRpIdHash, receivedRpIdHash)) return false;

            int flags = authenticatorData[32] & 0xff;
            if ((flags & FLAG_UP) == 0 || (flags & FLAG_UV) == 0) return false;

            byte[] clientDataHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);
            byte[] signedData = ByteBuffer.allocate(authenticatorData.length + clientDataHash.length)
                    .put(authenticatorData)
                    .put(clientDataHash)
                    .array();

            PublicKey publicKey = decodePublicKey(publicKeyDerB64u, coseAlgorithm);
            Signature verifier = Signature.getInstance(signatureAlgorithm(coseAlgorithm));
            verifier.initVerify(publicKey);
            verifier.update(signedData);
            return verifier.verify(decodeB64u(signatureB64u));
        } catch (Exception e) {
            return false;
        }
    }

    private static PublicKey decodePublicKey(String publicKeyDerB64u, int coseAlgorithm) throws Exception {
        String keyFactoryAlgorithm;
        if (coseAlgorithm == -7) {
            keyFactoryAlgorithm = "EC";
        } else if (coseAlgorithm == -257) {
            keyFactoryAlgorithm = "RSA";
        } else {
            throw new IllegalArgumentException("Unsupported COSE algorithm: " + coseAlgorithm);
        }
        return KeyFactory.getInstance(keyFactoryAlgorithm)
                .generatePublic(new X509EncodedKeySpec(decodeB64u(publicKeyDerB64u)));
    }

    private static String signatureAlgorithm(int coseAlgorithm) {
        if (coseAlgorithm == -7) return "SHA256withECDSA";
        if (coseAlgorithm == -257) return "SHA256withRSA";
        throw new IllegalArgumentException("Unsupported COSE algorithm: " + coseAlgorithm);
    }

    private static String text(JsonNode node, String name) {
        JsonNode value = node.get(name);
        return value == null || !value.isTextual() ? null : value.asText();
    }

    private static byte[] decodeB64u(String value) {
        int mod = value.length() % 4;
        String padded = mod == 0 ? value : value + "=".repeat(4 - mod);
        return Base64.getUrlDecoder().decode(padded);
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
