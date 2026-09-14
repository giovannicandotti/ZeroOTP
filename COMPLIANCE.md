# ZeroOTP — NIST and Microsoft Security Classification

**Scope:** current repository, including the standalone browser application and `KeyCloakPlugin/` v1.1.0.  
**Last reviewed:** September 2026.

This document distinguishes **protocol security properties** from **vendor policy-engine recognition**. Those are not the same question.

---

## 1. NIST baseline

The primary reference is **NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management**, published July 2025.

NIST defines phishing resistance as the ability of an authentication protocol to prevent disclosure of authentication secrets and valid authenticator outputs to an impostor verifier without relying on the claimant to recognize the attack.

NIST further states that:

- phishing resistance requires cryptographic authentication;
- manual transfer of OTP authenticator outputs is not phishing-resistant because it does not bind the output to the specific session;
- recognized approaches include **verifier name binding** and **channel binding**;
- WebAuthn/FIDO2 is explicitly cited as an example of verifier-name binding;
- verifier challenges/nonces are a standard mechanism for replay resistance.

Primary source: <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/>

---

## 2. Standalone ZeroOTP classification

The standalone root application contains several storage/protection modes but ultimately produces an RFC 6238 TOTP that the user can transfer to a verifier.

| Standalone mode | Relevant property | NIST-oriented assessment |
|---|---|---|
| Cookie + master password | Encrypted local storage; TOTP is still transferable | OTP semantics; not phishing-resistant |
| LocalStorage + master password | Same as Cookie with different storage | OTP semantics; not phishing-resistant |
| Browser/password-manager storage | Storage protection changes; TOTP protocol does not | OTP semantics; not phishing-resistant |
| WebAuthn PRF biometric vault | Strong credential/RP-bound unlock of the local secret; user verification can be required | Stronger secret protection, but the final standalone TOTP is still transferable; therefore do **not** classify the complete standalone TOTP authentication as phishing-resistant solely because PRF was used to unlock the secret |

A standalone PRF-protected TOTP can still be a strong **multi-factor OTP** construction when each use requires control of the WebAuthn credential plus an activation factor, but NIST's phishing-resistance property applies to the authentication protocol and final authenticator output, not just to the storage boundary.

### AAL statement

AAL2 may permit multi-factor OTP authenticators, subject to all applicable NIST requirements and deployment controls. That does not make OTP phishing-resistant. NIST requires verifiers at AAL2 to offer phishing-resistant options and requires phishing-resistant authentication for federal enterprise users; AAL3 requires phishing resistance and additional cryptographic/hardware properties.

This repository does not claim standalone ZeroOTP has been certified at an AAL.

---

## 3. Keycloak plugin v1.1.0 classification

The Keycloak plugin changes the authentication protocol. The server no longer accepts an RFC 6238 code alone.

For every login:

```text
Keycloak challenge (256-bit, per AuthenticationSession)
        |
        +--> WebAuthn get() + PRF -> unlock local TOTP secret
        |
        +--> HMAC-SHA-256(TOTP-secret, label || challenge || TOTP)
                                  |
                                  v
                         sessionProof
```

Keycloak validates both the TOTP and `sessionProof`, then consumes the challenge.

### NIST-oriented interpretation

| Property | Plugin v1.1.0 |
|---|---|
| RFC 6238 compatibility | Yes; TOTP remains unchanged internally |
| TOTP sufficient by itself | No |
| Verifier-generated nonce/challenge | Yes, 256-bit |
| Challenge scoped to current authentication session | Yes |
| Cryptographic response to challenge | Yes, HMAC-SHA-256 |
| Proof bound to submitted TOTP | Yes |
| Challenge single-use at application layer | Yes |
| WebAuthn RP/verifier binding before local secret release | Yes |
| Manual transfer of accepted proof | No |
| Cross-session replay of captured TOTP + proof | Prevented by distinct challenge, assuming key secrecy and correct implementation |
| Phishing-resistant protocol property | **Architecturally supportable**, because the accepted cryptographic output is verifier/session-bound rather than a manually transferable OTP alone |
| AAL3 | **Not claimed** |

The most precise description is:

> **A multi-factor, session-bound cryptographic authentication protocol that uses RFC 6238 TOTP as an internal compatibility component, WebAuthn PRF for verifier-bound secret release, and HMAC-SHA-256 over a verifier-generated challenge for authentication-session binding.**

This avoids the misleading expression “phishing-resistant TOTP.” The phishing-resistant property belongs to the **composite protocol**, not to RFC 6238 itself.

---

## 4. Why PRF and session binding are separate controls

### PRF

The WebAuthn Level 3 PRF extension evaluates a credential-associated pseudo-random function and returns a 32-byte result. ZeroOTP derives the local AES key from that output with HKDF-SHA-256. This makes the local vault dependent on successful use of the credential and on the WebAuthn RP security model.

Primary source: <https://www.w3.org/TR/webauthn-3/#prf-extension>

### Session proof

PRF alone does not change the fact that a conventional TOTP can be relayed. The Keycloak plugin therefore authenticates a fresh server challenge under the TOTP secret:

```text
HMAC-SHA-256(K, protocol-label || serverChallenge || TOTP)
```

The verifier challenge is the session-specific element; HMAC is the cryptographic integrity/authentication mechanism; the WebAuthn ceremony provides the verifier-name-bound gate through which `K` can be recovered on the endpoint.

---

## 5. Cryptographic components

| Component | Use in ZeroOTP | Reference |
|---|---|---|
| RFC 6238 / HOTP | Standards-compatible TOTP component | <https://www.rfc-editor.org/rfc/rfc6238> |
| WebAuthn PRF | Credential-associated keying material; RP-bound evaluation path | <https://www.w3.org/TR/webauthn-3/#prf-extension> |
| FIDO CTAP `hmac-secret` | Underlying authenticator capability on which WebAuthn PRF can be modeled | <https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html> |
| HKDF-SHA-256 | Derives AES key from PRF output | <https://www.rfc-editor.org/rfc/rfc5869> |
| AES-GCM | Authenticated encryption of browser-side TOTP material | <https://csrc.nist.gov/pubs/sp/800/38/d/final> |
| HMAC-SHA-256 | Session proof over verifier challenge + TOTP | <https://csrc.nist.gov/projects/message-authentication-codes> |
| SecureRandom challenge | 256-bit per-authentication-session freshness | NIST random-value requirements: <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/> |

---

## 6. Microsoft Entra classification — product recognition vs protocol analysis

Microsoft Entra Conditional Access authentication strengths are based on recognized authentication methods and combinations. Microsoft currently defines three built-in strengths:

1. Multifactor authentication strength
2. Passwordless MFA strength
3. Phishing-resistant MFA strength

Microsoft lists methods such as FIDO2/passkeys, Windows Hello/platform credentials, and multifactor certificate-based authentication in the built-in phishing-resistant strength.

Reference: <https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths>

### Standalone ZeroOTP

A standalone ZeroOTP TOTP is not a native Entra authentication method. If its output is consumed as OATH/TOTP, the closest Microsoft category is software/hardware OATH-style OTP, which Microsoft treats as MFA but not as one of its phishing-resistant methods.

### Keycloak plugin

The Keycloak v1.1.0 plugin can have phishing-resistant protocol properties under the NIST technical definition, but **Microsoft Entra does not automatically inspect or certify the internal cryptographic properties of a custom Keycloak SPI**.

If Keycloak is federated to Entra, Microsoft policy evaluation depends on the federation integration and the authentication context/claims Entra recognizes. In the built-in authentication-strength table, generic **federated multifactor** satisfies the baseline MFA strength but is not listed under the built-in Passwordless or Phishing-resistant MFA strengths.

Therefore:

| Question | Standalone ZeroOTP | Keycloak v1.1.0 |
|---|---|---|
| Technically phishing-resistant under the described NIST protocol property? | No, when the final value is a transferable TOTP | Yes, supportable for the composite session-bound protocol, subject to implementation/threat-model assumptions |
| Automatically recognized by Entra as built-in `Phishing-resistant MFA strength`? | No | No |
| Could participate in federated MFA semantics? | Integration-dependent | Yes, integration-dependent, but generic federated MFA maps to baseline MFA strength in Microsoft's built-in table |

Do not equate “has phishing-resistant cryptographic properties” with “is selectable as Microsoft's built-in Phishing-resistant MFA authentication strength.”

---

## 7. References

### NIST

- SP 800-63B-4: <https://pages.nist.gov/800-63-4/sp800-63b.html>
- Authenticator requirements and phishing resistance: <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/>
- AAL requirements: <https://pages.nist.gov/800-63-4/sp800-63b/aal/>
- Publication record: <https://csrc.nist.gov/pubs/sp/800/63/b/4/final>

### WebAuthn / FIDO / IETF / cryptography

- WebAuthn Level 3: <https://www.w3.org/TR/webauthn-3/>
- FIDO CTAP 2.2: <https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html>
- RFC 6238 TOTP: <https://www.rfc-editor.org/rfc/rfc6238>
- RFC 5869 HKDF: <https://www.rfc-editor.org/rfc/rfc5869>
- NIST HMAC: <https://csrc.nist.gov/projects/message-authentication-codes>
- NIST SP 800-38D AES-GCM: <https://csrc.nist.gov/pubs/sp/800/38/d/final>

### Microsoft

- Authentication overview: <https://learn.microsoft.com/en-us/entra/identity/authentication/overview-authentication>
- Authentication strengths: <https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths>
- Passkeys/FIDO2: <https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-passkeys-fido2>
- NIST AAL2 mapping for Entra: <https://learn.microsoft.com/en-us/entra/standards/nist-authenticator-assurance-level-2>
