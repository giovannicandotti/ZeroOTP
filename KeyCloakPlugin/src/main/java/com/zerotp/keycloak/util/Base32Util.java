package com.zerotp.keycloak.util;

/**
 * Base32 (RFC 4648), implementazione minimale e senza dipendenze.
 *
 * Motivo per cui esiste una copia locale invece di usare una classe interna
 * di Keycloak: il percorso/esistenza di una eventuale utility Base32 interna
 * varia tra versioni Keycloak (confermato: org.keycloak.util.Base32 non
 * esiste nella versione in uso al momento del primo build reale di questo
 * plugin). Base32 e' uno standard fisso — non ha senso agganciarsi a un
 * dettaglio implementativo interno che puo' spostarsi.
 */
public final class Base32Util {

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private Base32Util() { }

    public static String encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int bits = 0;
        int value = 0;
        for (byte b : data) {
            value = (value << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                sb.append(ALPHABET.charAt((value >>> (bits - 5)) & 0x1F));
                bits -= 5;
            }
        }
        if (bits > 0) {
            sb.append(ALPHABET.charAt((value << (5 - bits)) & 0x1F));
        }
        return sb.toString();
    }

    public static byte[] decode(String input) {
        String clean = input.trim().replace("=", "").toUpperCase();
        int bits = 0;
        int value = 0;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (char c : clean.toCharArray()) {
            int idx = ALPHABET.indexOf(c);
            if (idx < 0) continue; // ignora caratteri non validi invece di lanciare
            value = (value << 5) | idx;
            bits += 5;
            if (bits >= 8) {
                out.write((value >>> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }
}
