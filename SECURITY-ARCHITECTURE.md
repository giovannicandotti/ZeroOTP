# ZeroOTP Security Architecture and Assurance Analysis

## Standalone ZeroOTP and the Keycloak Session-Bound Authentication Profile

**Document status:** Technical architecture and security analysis  
**Repository scope:** `ZeroOTP/` root application and `ZeroOTP/KeyCloakPlugin/` v1.1.0  
**Reference date:** September 2026  
**Audience:** Identity architects, cryptographers, IAM engineers, security reviewers, Keycloak engineers, risk/compliance specialists, and technical assessors familiar with WebAuthn, OTP, federation, and NIST SP 800-63.

---

# Executive Summary

ZeroOTP is a browser-centric authentication technology built around an unusual but deliberate compatibility objective: retain RFC 6238 Time-Based One-Time Password (TOTP) semantics while materially strengthening how the TOTP secret is stored, activated, and — in the Keycloak implementation — how the resulting authentication event is cryptographically bound to the verifier session.

The repository contains two related implementations, not two independent products. The **root ZeroOTP browser application** demonstrates several mechanisms for storing or protecting a TOTP secret, including a WebAuthn Pseudo-Random Function (PRF) mode. The **Keycloak plugin** derives from the PRF mode and adds server-side authentication state plus a cryptographic session proof. That additional proof changes the security classification of the complete authentication exchange.

The standalone PRF mode uses a WebAuthn credential as the controlled source of pseudo-random keying material. Through the WebAuthn Level 3 `prf` extension, a credential-associated PRF is evaluated at an application-provided input. ZeroOTP takes the resulting 32-byte value, applies HKDF-SHA-256, and derives an AES-GCM key. That key encrypts the browser-side TOTP secret. The key itself is not intentionally persisted. Reconstructing it requires another successful WebAuthn operation involving the credential and its configured user-verification policy.

This is a strong mechanism for **protecting the TOTP secret at rest and gating its release**, but it does not by itself make a conventional TOTP authentication phishing-resistant. NIST SP 800-63B-4 treats phishing resistance as a property of the authentication protocol. A six-digit OTP that can be manually transferred to another verifier is not cryptographically bound to the authentication session in which it is entered. NIST explicitly states that authenticators involving manual entry of authenticator output, including OTP authenticators, are not phishing-resistant for exactly this reason.

The **Keycloak v1.1.0 plugin changes that protocol property**. Each ZeroOTP login causes Keycloak to generate a fresh 256-bit random challenge and store it in the current Keycloak `AuthenticationSession`. The browser uses this verifier-generated challenge in its WebAuthn `get()` ceremony while requesting PRF evaluation. After successful user verification and PRF evaluation, the local TOTP secret is decrypted and the normal RFC 6238 code is generated. The browser then computes a second output:

```text
sessionProof = HMAC-SHA-256(
    K,
    "zerotp-session-v1\0" || serverChallenge || "\0" || totpCode
)
```

where `K` is the TOTP shared secret. Keycloak accepts the login only if both the RFC 6238 code and the HMAC proof are valid for the challenge stored in the same authentication session. The challenge is consumed after the attempt.

This design has three important consequences. First, capture of the six-digit TOTP alone is no longer sufficient. Second, capture of a valid `TOTP + sessionProof` pair from one Keycloak authentication session does not yield a valid pair for another authentication session because the HMAC input contains a different verifier challenge. Third, the local ability to recover `K` is reached through an RP-bound WebAuthn credential operation with user verification required.

Using NIST SP 800-63B-4 terminology, the v1.1.0 Keycloak profile is best analyzed as a **multi-factor cryptographic challenge-response protocol using a symmetric authentication key**, with WebAuthn contributing verifier-name binding and the HMAC challenge response contributing explicit authentication-session binding and replay resistance. RFC 6238 remains present as an internal compatibility component, but it is no longer the complete authenticator output accepted by the verifier.

Accordingly, this document supports the following carefully scoped conclusion:

> **The ZeroOTP Keycloak v1.1.0 composite protocol is designed to meet the NIST phishing-resistance property by preventing a captured OTP, or a cryptographic response captured from another authentication session, from being directly reusable against the genuine verifier. Its phishing-resistance argument relies on WebAuthn verifier-name binding plus a verifier-generated, session-specific challenge authenticated with HMAC-SHA-256.**

That statement is not a NIST certification, does not imply FIPS validation, and does not establish Authentication Assurance Level 3. AAL3 includes additional mandatory requirements, including public-key cryptography for the cryptographic authenticator at AAL3, non-exportable authentication keys, stronger authenticator validation requirements, and other controls. The current ZeroOTP verifier also stores the symmetric TOTP secret, which is a materially different compromise model from native WebAuthn public-key verification.

The Microsoft classification requires a separate distinction. Microsoft Entra Conditional Access `Authentication strengths` are **product-defined policy categories containing recognized authentication methods**. A custom Keycloak SPI does not become an Entra built-in `Phishing-resistant MFA strength` method merely because its protocol can be argued to satisfy the NIST technical definition of phishing resistance. Microsoft lists passkeys/FIDO2, Windows Hello/platform credentials, and multifactor certificate authentication among phishing-resistant methods. Generic federated MFA appears in the baseline MFA strength. Therefore this document treats **NIST protocol-property classification** and **Microsoft Entra policy recognition** as separate layers.

---

# 1. Scope and System Definition

## 1.1 Repository as a single technology tree

The repository should be understood as one technology with two profiles:

```text
ZeroOTP
|
+-- Standalone browser profile
|   +-- Password-manager storage
|   +-- Cookie / master-password storage
|   +-- LocalStorage / master-password storage
|   +-- WebAuthn PRF-protected vault
|
+-- Keycloak integration profile
    +-- WebAuthn PRF-protected vault
    +-- Keycloak credential model and Authentication SPI
    +-- verifier-generated per-session challenge
    +-- HMAC-SHA-256 session proof
```

The Keycloak profile reuses the fundamental ZeroOTP concept — protecting a TOTP secret through browser-side cryptography — but moves the design from a local secret-protection demonstration into an end-to-end authentication protocol with verifier participation.

## 1.2 What ZeroOTP is not

ZeroOTP is not a new replacement for RFC 6238. The TOTP value remains standards-compatible. The plugin does not redefine the TOTP moving factor, truncation, digit count, or time-step semantics in order to obtain phishing resistance.

ZeroOTP is also not native WebAuthn authentication in the strict sense that Keycloak's final credential verifier stores a public key and verifies a WebAuthn assertion signature as the sole authentication proof. WebAuthn is used to control access to PRF output and to provide the RP-bound credential ceremony. The Keycloak plugin's final session-bound proof is HMAC-SHA-256 under the symmetric TOTP key.

This distinction matters for both assurance analysis and compromise analysis.

## 1.3 Security goals

The principal security goals are:

1. avoid persistent plaintext storage of the browser-side TOTP secret;
2. require use of a WebAuthn credential, with user verification, to reconstruct local keying material;
3. preserve RFC 6238 interoperability internally;
4. prevent a six-digit TOTP captured during authentication from being sufficient to authenticate elsewhere;
5. prevent a cryptographic authentication response captured from one authentication session from being replayed into another;
6. use the WebAuthn RP security model to restrict the credential operation to the intended relying-party context;
7. maintain a protocol that can be integrated into Keycloak authentication flows without requiring a proprietary browser extension or native endpoint application.

## 1.4 Non-goals

The current implementation does not claim to:

- provide AAL3;
- eliminate the verifier-side symmetric secret;
- withstand arbitrary code execution in the legitimate RP origin;
- perform full enterprise attestation policy evaluation against FIDO Metadata Service;
- make all standalone ZeroOTP storage methods phishing-resistant;
- be automatically recognized by Microsoft Entra as a built-in phishing-resistant authentication method;
- constitute an independent laboratory cryptographic validation.

---

# 2. Terminology and NIST Model

## 2.1 Authentication factor

NIST SP 800-63 identifies three factor categories: something known, something possessed, and something inherent to the claimant. A multi-factor authenticator can combine possession of an authenticator with an activation factor such as a PIN or local biometric verification.

In the PRF profile, the WebAuthn credential represents possession/control of an authenticator environment. `userVerification: "required"` requests an additional local verification step implemented by the authenticator/platform, typically a PIN, biometric, or equivalent mechanism.

## 2.2 Authenticator secret and authentication key

NIST uses **authentication secret** as a broad term for secret values used in authentication. An **authentication key** can be private or symmetric and is used to generate an authenticator output.

In the ZeroOTP Keycloak protocol, the RFC 6238 seed `K` plays two roles:

- it is the TOTP seed used to generate and verify the time-based OTP;
- it is the symmetric HMAC key used to authenticate the verifier challenge and submitted TOTP.

That dual use is intentionally separated by a protocol label in the HMAC input. A future hardening revision could derive a distinct session-proof key from `K` with a dedicated KDF label, further reducing cross-protocol key-reuse concerns. The current design uses the same high-entropy symmetric secret directly as the HMAC key.

## 2.3 Authenticator output

NIST defines an authenticator output as the value generated by an authenticator such that the ability to generate valid outputs demonstrates control of the authenticator. Protocol messages may explicitly contain that output or may depend on it.

For conventional TOTP, the authenticator output is the short OTP code. For ZeroOTP Keycloak v1.1.0, the verifier accepts authentication only when it receives both:

```text
TOTP
sessionProof
```

The security analysis therefore treats the accepted composite response — not the six-digit code in isolation — as the effective protocol output.

## 2.4 Challenge-response protocol

NIST defines a challenge-response protocol as one in which the verifier sends a challenge and the claimant combines that challenge with a secret, for example by hashing it with a shared secret or applying a private-key operation, to generate a response.

The session-proof layer directly fits this model:

```text
Verifier -> random challenge C
Claimant/browser -> HMAC_K(label || C || TOTP)
Verifier -> recompute and compare
```

## 2.5 Phishing resistance

NIST SP 800-63B-4 defines phishing resistance as the ability of the authentication protocol to prevent disclosure of authentication secrets and valid authenticator outputs to an impostor verifier without relying on the claimant's vigilance.

NIST recognizes two broad methods: **channel binding** and **verifier name binding**. WebAuthn/FIDO2 is explicitly cited as an example of verifier-name binding because a credential is associated with the authenticated RP/domain context.

NIST also explicitly explains why manual OTP entry fails this test: manual entry does not bind the authenticator output to the specific session being authenticated, enabling an impostor verifier to relay the output.

## 2.6 Replay resistance

Replay resistance means that recording and replaying a previous authentication message should not enable a later successful authentication. NIST points to nonce/challenge mechanisms as standard replay-resistance controls.

ZeroOTP Keycloak adds a fresh 256-bit challenge to each authentication session and deletes it after an attempt. This provides explicit freshness beyond the RFC 6238 time window.

---

# 3. Standalone ZeroOTP Architecture

## 3.1 Browser-only execution model

The standalone application is composed of HTML, CSS, and JavaScript. TOTP computation occurs locally in the browser. There is no ZeroOTP backend required for the static demonstration.

The principal variants are `easy.html`, `full.html`, and `biometry.html`. `index.html` acts as an entry point and explanatory page.

## 3.2 TOTP core

The TOTP component follows RFC 6238 semantics and ultimately depends on HOTP as defined by RFC 4226. Conceptually:

```text
T = floor((CurrentUnixTime - T0) / X)
TOTP = Truncate(HMAC(K, T)) mod 10^digits
```

RFC 6238 requires prover and verifier to share the same secret or derive the same secret and use the same time-step parameters. The ZeroOTP browser acts as the prover-side OTP generator.

## 3.3 Password-protected local modes

Cookie and LocalStorage modes protect the stored secret with application-level encryption derived from a user-supplied master password. Their exact storage mechanism changes confidentiality-at-rest characteristics but does not alter the authenticator protocol observed by the downstream TOTP verifier.

Once the secret is recovered and a six-digit TOTP is shown or transferred, that TOTP has ordinary OTP semantics.

## 3.4 Password-manager mode

Storing TOTP material through a browser password-manager path delegates storage protection to the browser/provider. Again, this can materially change secret-at-rest risk but does not change the final RFC 6238 protocol. The downstream verifier cannot infer from the six-digit OTP whether the seed was stored in a password manager, encrypted cookie, secure enclave-backed application, or plaintext file.

## 3.5 WebAuthn PRF mode

The PRF mode is architecturally different because it does not rely on a typed application master password to reconstruct the encryption key. Instead, the browser invokes a WebAuthn credential and requests evaluation of its associated PRF.

The W3C PRF extension defines credential-associated pseudo-random functions that map arbitrary inputs to 32-byte outputs. The specification explicitly gives symmetric-key encryption of user data as a motivating use case: encrypted application data can remain inaccessible without the ability to obtain PRF output from the associated credential.

ZeroOTP applies exactly that pattern.

## 3.6 PRF key derivation pipeline

The logical pipeline is:

```text
credential-associated PRF
          |
          | input = prfSalt
          v
     32-byte output
          |
          v
     HKDF-SHA-256
     salt = hkdfSalt
     application info label
          |
          v
     AES-256-GCM key
          |
          v
 decrypt/encrypt TOTP vault
```

HKDF is specified in RFC 5869. It provides extract-and-expand semantics suitable for deriving strong application-specific keys from input keying material. AES-GCM is an authenticated-encryption mode specified by NIST SP 800-38D and provides confidentiality plus integrity/authenticity for the encrypted local record.

## 3.7 Why PRF is stronger than a local application password

A conventional master-password design has at least three recurring risks: low-entropy user choice, offline guessing against stolen ciphertext, and password reuse. A credential-associated PRF changes the source of keying material. The application does not ask the user to invent the high-entropy cryptographic material; the credential/authenticator participates in producing it.

The WebAuthn ceremony also supplies RP/origin constraints and can require local user verification. This materially raises the bar for offline attacks against the encrypted TOTP secret when compared with an application design whose only protection is a low-entropy password-derived key.

## 3.8 Why PRF alone does not make standalone TOTP phishing-resistant

This point is critical. Secret-at-rest protection and phishing resistance are distinct.

Suppose the user successfully invokes WebAuthn PRF, decrypts `K`, and the page displays `123456`. If a phishing workflow causes that code to be entered into an impostor site, the impostor can relay it to the real TOTP verifier before it expires. The fact that the seed was unlocked through a phishing-resistant credential ceremony does not cryptographically bind the resulting six-digit value to the final authentication session.

Therefore the standalone PRF profile should be described as **PRF-protected TOTP secret storage with strong credential-gated release**, not as an automatically phishing-resistant TOTP protocol.

---

# 4. Keycloak Integration Architecture

## 4.1 Keycloak SPI roles

The plugin introduces Keycloak components for:

- authentication-flow execution;
- required-action enrollment;
- custom credential storage/modeling;
- server-side TOTP verification;
- FreeMarker login and enrollment pages;
- browser JavaScript implementing WebAuthn PRF, vault decryption, TOTP calculation, and session-proof calculation.

The principal provider identifiers are:

```text
hardware-prf-totp-authenticator
hardware-prf-totp
hardware-prf-totp-register
```

## 4.2 Server-side credential data

Keycloak must retain enough information to validate TOTP and the HMAC proof. The server therefore has a verifier-side copy of the symmetric TOTP secret. The browser has an encrypted copy.

This symmetric-key verifier design differs from native WebAuthn public-key authentication. Compromise of the verifier's secret store can expose authentication keys capable of generating valid responses.

## 4.3 Browser-side vault

The browser record contains the WebAuthn credential identifier plus the values needed to reproduce PRF evaluation and AES key derivation, as well as AES-GCM ciphertext and IV. It does not intentionally persist the derived AES key or plaintext TOTP secret.

Local browser state is therefore part of the authentication environment. A passkey existing on another device does not automatically recreate the encrypted vault record.

## 4.4 Enrollment and authentication are different ceremonies

Enrollment establishes credential/vault state and sends credential metadata to Keycloak. Login reconstructs the encryption key, decrypts the vault, and produces the session-bound response.

The enrollment challenges in the current JavaScript are locally generated for the credential creation and PRF-capability confirmation path; the **authentication** ceremony uses the Keycloak-generated challenge introduced by v1.1.0. This document's phishing-resistance claim applies to the authentication protocol, not to an assertion that every enrollment message is server-verified as a native WebAuthn registration.

---

# 5. PRF: Cryptographic Role and Security Properties

## 5.1 What the PRF extension provides

WebAuthn Level 3 specifies the `prf` client extension so an RP can evaluate a pseudo-random function associated with a WebAuthn credential. The output is 32 bytes. The function is intended to behave like a randomly selected function associated with the credential and is separated from arbitrary underlying authenticator HMAC uses.

The W3C specification explicitly notes encrypted user data as a motivating scenario. The RP can use PRF output as symmetric keying material; without ability to obtain an assertion from the associated credential, the encrypted data cannot be decrypted merely from application storage.

## 5.2 Relationship to CTAP `hmac-secret`

The WebAuthn PRF extension is modeled on the FIDO CTAP `hmac-secret` extension while adding client-side separation and WebAuthn semantics. CTAP documents `hmac-secret` as a mechanism for a platform to retrieve a symmetric secret scoped to a credential for encryption/decryption purposes.

This is conceptually aligned with ZeroOTP's vault design.

## 5.3 User verification

The plugin requests:

```text
userVerification = required
```

The intent is that every credential use needed to reconstruct PRF output requires the authenticator/platform to perform user verification according to the selected authenticator's policy and capabilities.

From a NIST perspective, local PIN or biometric verification can act as an activation factor for a multi-factor authenticator. A biometric characteristic is not a standalone authenticator under NIST; it is used together with possession/control of a physical authenticator.

## 5.4 PRF output is not itself the server authentication proof

A common conceptual error is to treat successful PRF evaluation as if Keycloak had verified a WebAuthn signature. That is not what the current code does. The PRF output remains browser-side and is used to derive the local AES key. Keycloak's custom authenticator ultimately verifies the RFC 6238 code and HMAC session proof under the symmetric secret.

This distinction is essential for an accurate threat model.

## 5.5 PRF and verifier-name binding

NIST recognizes WebAuthn as a verifier-name-bound protocol. The credential is scoped to an RP identifier authenticated through the web origin model. Therefore an impostor domain cannot simply claim arbitrary access to the legitimate RP's WebAuthn credential.

ZeroOTP leverages this property at the point where the local authentication secret becomes recoverable.

---

# 6. Cryptographic Session Binding in v1.1.0

## 6.1 Design requirement

The design requirement is to preserve a standard RFC 6238 code while preventing that code from being an independently sufficient authenticator output.

A naive approach would alter TOTP itself by mixing the Keycloak session challenge into the RFC 6238 calculation. That would destroy interoperability with RFC 6238 verifiers. Instead, ZeroOTP keeps TOTP unchanged and adds a parallel cryptographic proof.

## 6.2 Challenge generation

The server creates 32 bytes from Java `SecureRandom`:

```text
C <- SecureRandom(256 bits)
```

It serializes `C` as Base64URL and records it under the current Keycloak `AuthenticationSession`.

A 256-bit random value substantially exceeds NIST's minimum challenge size requirements for cryptographic authenticators. Security nevertheless depends on the quality of the platform random generator and correct session-state isolation.

## 6.3 Challenge delivery and WebAuthn use

Keycloak injects the challenge into the FreeMarker page. The browser decodes it for use as the WebAuthn `challenge` field.

The WebAuthn assertion ceremony therefore incorporates a value generated by the genuine Keycloak verifier. This supplies transaction freshness to the credential operation instead of using a browser-generated value unknown to the server.

## 6.4 Construction of the proof

Let:

- `K` = decoded RFC 6238 symmetric secret;
- `C` = Base64URL representation of the Keycloak challenge as used by the HMAC implementation;
- `O` = exact TOTP string;
- `L` = ASCII/UTF-8 protocol label `zerotp-session-v1` followed by NUL.

Then:

```text
P = HMAC-SHA-256(K, L || C || 0x00 || O)
```

The browser sends `(O, P)`.

## 6.5 Protocol label and field separation

The label provides domain separation. The design does not simply MAC `challenge || TOTP` with no context; it identifies this MAC as belonging to the ZeroOTP session-binding protocol version.

The NUL separator between challenge and TOTP prevents straightforward concatenation ambiguity. A more formal serialization format — for example a length-prefixed binary structure or CBOR — could be considered in future protocol versions, but the current fields have constrained formats and an explicit separator.

## 6.6 Binding to the submitted OTP

Including `O` in the HMAC input means that the proof authenticates the exact TOTP submitted. An attacker cannot combine a captured proof with a different TOTP string and expect verification to succeed.

## 6.7 Server validation order

The verifier first checks the TOTP window. Only a candidate credential with a valid TOTP proceeds to proof comparison. It recomputes `P` with the server-side secret and session challenge and performs a constant-time-style digest comparison using `MessageDigest.isEqual()`.

This ordering is operationally efficient, though implementations must continue to consider side channels, account enumeration, and rate limiting at the flow level.

## 6.8 Single-use challenge

The authentication note is removed after the verification attempt. This is an important state transition: even if the browser resubmits the same form after a completed attempt, the original challenge is no longer present in the session.

On retry, the form-generation path creates a new challenge.

---

# 7. Phishing-Resistance Analysis under NIST SP 800-63B-4

## 7.1 NIST's test is about protocol behavior

The decisive NIST wording focuses on whether an impostor verifier can obtain authentication secrets or valid authenticator outputs. It is not enough that the authenticating device uses good cryptography internally.

This is why ordinary OTP remains non-phishing-resistant even when generated by high-assurance hardware: if the user manually transfers the OTP, the device does not control which verifier receives the output.

## 7.2 Conventional TOTP failure mode

A typical adversary-in-the-middle phishing sequence is:

```text
Victim -> impostor site: password
Victim -> authenticator: read TOTP 123456
Victim -> impostor site: 123456
Impostor -> genuine verifier: 123456
```

The verifier cannot distinguish whether the user typed the code into its own page or whether an attacker relayed it.

## 7.3 ZeroOTP v1.1.0 changes the accepted output

In the Keycloak plugin, the attacker needs more than `123456`. The accepted request requires:

```text
P_A = HMAC_K(L || C_A || 123456)
```

for the challenge `C_A` associated with the specific Keycloak authentication session.

A different genuine-verifier session contains `C_B`, so the expected proof changes.

## 7.4 Cross-session relay model

Consider a phisher that can cause the user to authenticate in one context while the attacker owns another pending Keycloak session.

If the attacker captures `(O, P_A)` from the user's genuine session A and injects it into attack session B, the genuine verifier computes:

```text
P_B = HMAC_K(L || C_B || O)
```

Because `C_A` and `C_B` are statistically independent 256-bit challenges, `P_A` and `P_B` differ with overwhelming probability.

This directly addresses the “output is not bound to the specific session” problem NIST identifies for manually entered OTP.

## 7.5 Verifier-name binding contribution

Session binding alone is not identical to phishing resistance if an impostor verifier can cause the authenticator to create a valid response for a genuine verifier identifier under attacker control. The WebAuthn layer contributes the verifier-name binding: the PRF-producing credential is tied to the legitimate RP identifier/origin rules.

The two controls compose:

```text
WebAuthn RP binding
    -> limits where credential/PRF operation is available

Keycloak challenge + HMAC
    -> limits where the recovered secret's authentication output is valid
```

## 7.6 Why this is not channel binding

The HMAC proof is not a cryptographic binding to a TLS exporter, transcript hash, or equivalent channel identifier. It is an **application-layer verifier-session challenge**. The appropriate NIST analogy is verifier-name binding plus challenge-response freshness, not TLS channel binding.

## 7.7 Classification language

The recommended language is:

> ZeroOTP Keycloak v1.1.0 implements a phishing-resistant, session-bound cryptographic authentication protocol in which RFC 6238 TOTP is retained as an internal compatibility component. WebAuthn provides verifier-name-bound access to PRF-derived keying material, while a verifier-generated challenge is authenticated with HMAC-SHA-256 to bind each accepted login to its Keycloak authentication session.

Avoid:

> “TOTP is phishing-resistant.”

That statement is false in general and conflicts with NIST terminology.

---

# 8. Authenticator-Type and AAL Analysis

## 8.1 Conventional multi-factor OTP

NIST's Multi-Factor OTP category describes an OTP authenticator activated by another factor and producing an OTP output. NIST explicitly marks OTP authentication as non-phishing-resistant.

Standalone ZeroOTP PRF mode can resemble a multi-factor OTP device from the user's perspective: possession/control of a WebAuthn credential plus local user verification are required before the TOTP secret is available. Yet the final output remains an OTP.

## 8.2 Keycloak v1.1.0 as cryptographic authentication

NIST describes multi-factor cryptographic authentication as proving possession/control of an authentication key through a cryptographic protocol after activation by another factor. NIST also defines challenge-response protocols that combine a verifier challenge with a shared secret.

The ZeroOTP Keycloak session proof uses a symmetric authentication key and challenge-response construction. On that basis, the complete exchange is more accurately assessed as cryptographic authentication than as plain OTP authentication.

This does not mean every NIST implementation requirement is automatically satisfied. Formal AAL conformance requires the complete system, lifecycle, rate limiting, binding, cryptographic validation, protected channels, authenticator characteristics, and operational controls to be evaluated.

## 8.3 AAL2

NIST AAL2 permits multi-factor cryptographic authenticators and multi-factor OTP, among other combinations, with approved cryptography and replay-resistance requirements. NIST also requires verifiers to offer phishing-resistant options at AAL2 and, for federal enterprise users, requires phishing-resistant authentication.

The plugin architecture is compatible with an **AAL2-oriented design target**, but this repository does not claim formal AAL2 certification. Cryptographic-module validation requirements may apply in regulated/federal deployments.

## 8.4 Why AAL3 is not claimed

AAL3 requires, among other controls:

- a cryptographic authenticator with a non-exportable private/authentication key;
- phishing resistance;
- replay resistance;
- authentication intent;
- public-key cryptography for the AAL3 cryptographic authenticator to protect authentication secrets from verifier compromise;
- applicable FIPS 140 validation requirements.

ZeroOTP's final Keycloak verifier uses a symmetric secret also stored at the verifier. That is fundamentally different from the AAL3 public-key requirement. Therefore an AAL3 claim would be inappropriate without a substantial redesign and complete conformance assessment.

---

# 9. Cryptographic Primitive Review

## 9.1 RFC 6238 / HMAC-SHA-1

The current browser implementation computes RFC 6238 using HMAC-SHA-1. RFC 6238 explicitly allows SHA-1, SHA-256, or SHA-512 variants, with HMAC-SHA-1 inherited from HOTP compatibility.

The security concern with six-digit TOTP is not collision resistance in the same way as a general-purpose SHA-1 signature use. The output is intentionally truncated to a small code space and therefore requires server-side throttling and short validity periods. The session proof adds a full HMAC-SHA-256 value but does not eliminate the need to rate-limit TOTP attempts.

## 9.2 HMAC-SHA-256 session proof

HMAC is a standard message-authentication construction. The 256-bit output is not truncated in the session proof. Security relies on the secrecy and entropy of `K` and on correct HMAC-SHA-256 implementation.

Using the same `K` for TOTP and session proof is simple and interoperable but creates a key-reuse relationship. Domain-separated input reduces protocol confusion, but a stronger future design could derive:

```text
K_session = HKDF(K, salt/label dedicated to ZeroOTP session proof)
```

and use `K_session` for HMAC. This would cryptographically separate the RFC 6238 function key from the session-proof key without changing stored secret material.

## 9.3 HKDF-SHA-256

HKDF is used to transform PRF output into an AES key under an application-specific context. The KDF's role is key separation and normalization, not password stretching. Since PRF output is intended to be high-entropy cryptographic material, expensive password hashing is not required for this path.

## 9.4 AES-GCM

AES-GCM provides authenticated encryption. The implementation generates a fresh 12-byte IV for encryption, matching the standard operational pattern for GCM. IV uniqueness under a fixed AES key remains an essential requirement.

The ciphertext's integrity tag prevents silent modification of the vault record from producing controlled plaintext without detection.

## 9.5 Random challenges and salts

The Java server challenge is generated with `SecureRandom`. Browser salts and IVs are generated with Web Crypto random values. These random values serve different roles:

- `serverChallenge`: authentication freshness/session binding;
- `prfSalt`: PRF input/namespace value for the credential;
- `hkdfSalt`: key-derivation salt;
- AES-GCM IV: nonce for authenticated encryption.

They should not be conflated or reused arbitrarily.

---

# 10. Threat Model

## 10.1 Remote phishing site

**Adversary:** controls a domain visually imitating the genuine Keycloak login page.

**Standalone TOTP:** vulnerable to real-time OTP relay if the user transfers the code.

**Keycloak v1.1.0:** the attacker's domain cannot simply invoke the legitimate RP's WebAuthn credential; and a TOTP/session-proof pair obtained for a different Keycloak authentication session does not verify under the attacker's pending genuine session.

## 10.2 Adversary-in-the-middle reverse proxy

A sophisticated phishing proxy can maintain live connections to both victim and verifier. The session-proof mechanism is specifically valuable here because the response depends on the verifier session challenge. The attacker cannot substitute its own verifier session challenge without having the victim's browser create a proof for that exact challenge in the legitimate RP-bound context.

A complete browser compromise or same-origin code injection changes this analysis; see below.

## 10.3 OTP-only credential theft

Logs, screen captures, DOM scraping, or accidental disclosure of a six-digit code do not by themselves satisfy the plugin's verifier because `sessionProof` is also required.

## 10.4 Captured HTTP form from previous session

Replaying the entire previous form fails when the stored challenge is absent or different. The challenge is removed after the attempt.

## 10.5 Verifier database compromise

This is a significant residual risk. The server stores `K`. An attacker who extracts `K` can generate both TOTP and session proofs for arbitrary server challenges if they can interact with the authentication flow. Native WebAuthn public-key verification offers stronger verifier-compromise resistance because the verifier need not store the private authentication secret.

ZeroOTP should therefore protect verifier-side secrets with strong access controls, encryption, secret-management architecture, and potentially HSM-backed protection where deployment requirements justify it.

## 10.6 Malicious JavaScript in the legitimate origin

If an attacker achieves XSS or supply-chain compromise and runs arbitrary JavaScript under the legitimate RP origin, WebAuthn origin checks do not distinguish legitimate application JavaScript from malicious same-origin JavaScript. Such code may be able to initiate credential operations, observe application plaintext after decryption, or manipulate form submission depending on browser/authenticator interaction and user approval.

CSP, dependency control, template escaping, supply-chain security, and ordinary web-application hardening remain essential.

## 10.7 Local browser profile theft

The local vault is encrypted. Theft of localStorage alone does not reveal the TOTP secret without the PRF-derived key. The strength of this protection depends on the WebAuthn credential implementation and PRF behavior.

## 10.8 Synced passkey considerations

A PRF-capable passkey may be device-bound or syncable depending on platform/provider behavior. NIST permits syncable authenticators at up to AAL2 subject to its Appendix B conditions but not at AAL3 because their private keys are exportable by design.

The plugin also requires the local encrypted vault record. Even if a related passkey is available on another device, the browser still needs the corresponding vault data and compatible PRF behavior to reconstruct the secret.

---

# 11. Enrollment, Binding, and Lifecycle

## 11.1 Credential binding

Enrollment occurs after the user reaches the Keycloak required action through an authenticated context. The plugin creates the TOTP credential and local WebAuthn/PRF vault.

A production deployment should ensure that enrollment itself is authorized by a sufficiently strong existing authentication method, especially because binding a new authenticator is a high-value operation.

## 11.2 Device/browser migration

The encrypted vault is local browser state. Migration is not equivalent to simply synchronizing a passkey. Operational procedures should explicitly define how a user enrolls an additional endpoint and how old credentials/vaults are invalidated.

## 11.3 Revocation

Deleting the Keycloak `hardware-prf-totp` credential should make the server stop accepting that ZeroOTP configuration. Local browser data may remain but becomes useless for the deleted server credential unless separately re-provisioned.

## 11.4 Recovery

Recovery must not silently downgrade phishing resistance. If password-based recovery is allowed, the assurance of the account is bounded by the recovery path. NIST emphasizes secure authenticator binding and recovery because attackers frequently target lifecycle processes rather than primary cryptography.

---

# 12. Operational Security Requirements

## 12.1 Protected channel

Production use requires HTTPS. WebAuthn itself requires a secure context except for browser exceptions such as `localhost` development. Keycloak should be deployed with standard reverse-proxy and hostname configuration so the RP identifier remains stable and unambiguous.

## 12.2 Rate limiting

A six-digit TOTP has a small output space. The session proof prevents a guessed TOTP from being sufficient unless the attacker also possesses `K`, but online flow-abuse controls are still necessary. Keycloak brute-force protection and appropriate per-account throttling should be enabled.

## 12.3 Logging

Logs should never contain the TOTP secret, PRF output, derived AES key, or plaintext vault. Logging the six-digit OTP or full session proof is unnecessary and should be avoided. Authentication-event logs should identify method, result, credential identifier metadata where appropriate, session correlation IDs, and security-relevant failures without exposing secrets.

## 12.4 Secret storage at the verifier

Because `K` is a long-term symmetric secret, its database representation deserves the same protection normally applied to OTP seeds: least-privilege access, encryption at rest, protected backup, limited administrative access, and, where warranted, HSM or dedicated secret-protection mechanisms.

## 12.5 Keycloak version alignment

The Maven project currently targets Keycloak 26.7.3. The Dockerfile uses `quay.io/keycloak/keycloak:latest`, which can drift beyond the compile-time API version. For reproducible production builds, pin the container image to the tested Keycloak release and update it deliberately.

This is an important operational improvement recommendation even though it is not part of the protocol itself.

---

# 13. Microsoft Entra Authentication Model

## 13.1 Microsoft authentication strengths

Microsoft Entra Conditional Access provides built-in authentication strengths that constrain which authentication method combinations can satisfy a policy. Microsoft currently documents three built-in strengths: Multifactor authentication, Passwordless MFA, and Phishing-resistant MFA.

Microsoft's built-in phishing-resistant set includes methods such as passkeys/FIDO2, Windows Hello/platform credentials, and multifactor certificate-based authentication. Microsoft also recommends these methods as phishing-resistant authentication technologies.

## 13.2 Mapping ZeroOTP to Microsoft terminology

The standalone ZeroOTP root application is not a Microsoft Entra authentication method. If it is used to generate a TOTP consumed by Entra or another system as an OATH code, Microsoft treats OATH/TOTP as MFA-capable but not as one of the phishing-resistant methods.

The Keycloak plugin likewise does not become a native Entra method. If Keycloak federates authentication to Entra, Entra evaluates what the federation communicates and what its policy engine recognizes. The internal fact that ZeroOTP uses WebAuthn PRF and a session-bound HMAC is not automatically visible to Conditional Access.

Microsoft's built-in authentication-strength table lists generic `Federated multifactor` under the baseline MFA strength, not under Passwordless MFA or Phishing-resistant MFA.

Therefore there are two legitimate classifications:

```text
NIST-style protocol property:
ZeroOTP Keycloak v1.1.0 -> phishing-resistant design argument is supportable.

Microsoft Entra built-in Authentication Strength recognition:
Custom ZeroOTP Keycloak method -> not automatically a built-in Phishing-resistant MFA method.
```

An enterprise integration that needs Entra to enforce a specific strength must use a Microsoft-supported method/claim/integration model and validate the resulting Conditional Access behavior rather than relying on conceptual equivalence.

---

# 14. Microsoft Comparison of the Two ZeroOTP Profiles

| Characteristic | Standalone ZeroOTP PRF profile | ZeroOTP Keycloak v1.1.0 |
|---|---|---|
| Final authentication value | Transferable RFC 6238 TOTP | RFC 6238 TOTP plus session-bound HMAC proof |
| PRF used | Yes | Yes |
| WebAuthn RP binding used to release local secret | Yes | Yes |
| Verifier-generated per-login challenge | No | Yes |
| Accepted output bound to verifier session | No | Yes |
| NIST phishing-resistant property | No for the complete TOTP authentication flow | Supportable for the composite protocol, subject to stated assumptions |
| Native Entra authentication method | No | No |
| Built-in Entra Phishing-resistant MFA strength | No | No automatic recognition |
| Closest Microsoft policy category when represented only as TOTP/federated MFA | OATH/MFA-style | Federation-dependent; generic federated MFA is baseline MFA strength |

The important governance point is that Microsoft's `Phishing-resistant MFA strength` is a **policy-product classification**, not a generic cryptographic certification label that third-party protocols can self-assign inside Entra.

---

# 15. Security Comparison with Native WebAuthn

## 15.1 Similarities

Both native WebAuthn and ZeroOTP Keycloak rely on WebAuthn's RP/origin model at an important point in the authentication path. Both can require local user verification. Both use a verifier freshness challenge in the login ceremony.

## 15.2 Differences

Native WebAuthn normally verifies a public-key signature over authenticator data and client data containing the challenge and origin. The RP stores a public key, not the private key.

ZeroOTP Keycloak uses WebAuthn primarily to obtain credential-associated PRF output, then uses a shared TOTP secret for both RFC 6238 and HMAC session proof. Keycloak therefore stores a secret capable of generating valid authentication outputs.

## 15.3 Security consequence of verifier compromise

This is the most important architectural difference. If a native WebAuthn credential database is stolen without the authenticator private keys, the attacker cannot ordinarily forge assertions. If the ZeroOTP verifier-side `K` values are stolen, the attacker can compute TOTP values and HMAC proofs.

Thus phishing resistance does not imply verifier-compromise resistance.

## 15.4 Compatibility advantage

The advantage is that ZeroOTP preserves TOTP semantics and can integrate with an authentication system whose credential model is built around shared OTP secrets, while adding a stronger session-bound browser protocol around that compatibility core.

---

# 16. Security Claims: Recommended and Prohibited Wording

## 16.1 Recommended

- “ZeroOTP standalone PRF mode uses WebAuthn PRF to protect the browser-side TOTP secret and require credential-bound user verification before secret release.”
- “The standalone TOTP output remains transferable and should not be described as phishing-resistant solely because PRF protects the secret.”
- “ZeroOTP Keycloak v1.1.0 adds a 256-bit verifier-generated challenge and HMAC-SHA-256 session proof; the six-digit TOTP is not sufficient by itself.”
- “The Keycloak composite protocol is designed to provide phishing resistance through WebAuthn verifier-name binding and cryptographic authentication-session binding.”
- “The design is AAL2-oriented but is not a formal NIST certification.”
- “AAL3 is not claimed.”

## 16.2 Avoid

- “TOTP is phishing-resistant.”
- “PRF automatically makes OTP phishing-resistant.”
- “ZeroOTP is NIST certified.”
- “ZeroOTP is automatically Microsoft Phishing-resistant MFA strength.”
- “Device-bound is guaranteed solely from BE/BS values.”
- “The verifier cannot impersonate users if its database is compromised.”

---

# 17. Recommended Future Hardening

## 17.1 Derive a dedicated session-proof key

Instead of using `K` directly for both TOTP and session HMAC, derive a separate key:

```text
K_session = HKDF-SHA-256(
    IKM = K,
    salt = protocol-specific value,
    info = "zerotp-session-proof-v2"
)
```

Then:

```text
P = HMAC-SHA-256(K_session, serialized-session-data)
```

This gives stronger key separation.

## 17.2 Structured serialization

Replace concatenated fields with a canonical length-prefixed or CBOR structure containing protocol version, RP identifier, challenge, TOTP, and optionally user/session identifiers. This makes parsing and future evolution more explicit.

## 17.3 Bind additional context

Depending on privacy and architecture requirements, a future proof could bind selected stable context such as realm identifier and authentication-flow instance in addition to the challenge. The challenge already provides uniqueness; extra context mainly reduces cross-protocol/configuration confusion.

## 17.4 Pin Keycloak image versions

Align Docker image tags with the Maven API version instead of `latest` to reduce supply-chain and compatibility drift.

## 17.5 Full WebAuthn attestation policy where required

Organizations needing hardware provenance guarantees can validate attestation statements and metadata against a controlled trust policy. This is distinct from phishing resistance itself but can strengthen assurance about authenticator characteristics.

## 17.6 Server-side secret protection

Consider HSM-backed wrapping or equivalent dedicated secret-management controls for stored `K` values in deployments whose threat model includes database extraction or privileged operator compromise.

## 17.7 Security test suite

Automate negative tests for:

- replaying the same response in a second authentication session;
- reusing a consumed challenge;
- swapping TOTP values while retaining the proof;
- altering one byte of proof;
- expired TOTP windows;
- absent local vault;
- PRF unavailable/unsupported;
- wrong RP identifier;
- user-verification cancellation;
- duplicate browser submissions.

---

# 18. Assurance Argument

A concise assurance case for the Keycloak profile can be expressed as claims, evidence, and assumptions.

## Claim A — local secret cannot be recovered from stored browser ciphertext alone

**Evidence:** AES-GCM ciphertext is encrypted under a key derived from WebAuthn PRF output through HKDF. The PRF output is not stored in localStorage.

**Assumptions:** PRF behaves as specified; AES-GCM/HKDF are correctly implemented; attacker does not control the legitimate origin at the time of unlock; credential/provider does not expose equivalent keying material outside intended interfaces.

## Claim B — captured TOTP alone cannot authenticate

**Evidence:** Keycloak `action()` requires non-empty `totpCode`, `sessionProof`, and server-side session challenge. `isValidBound()` validates the TOTP and independently validates HMAC-SHA-256.

## Claim C — response from session A cannot be replayed in session B

**Evidence:** challenge is random per login and stored in `AuthenticationSession`; proof includes the challenge; server recomputes with the current session challenge; challenge is removed after attempt.

**Assumptions:** session isolation is correct; challenges are generated with adequate randomness; attacker does not possess `K`.

## Claim D — phishing origin cannot directly request equivalent credential operation for the genuine RP

**Evidence:** WebAuthn RP/origin model and credential scoping; NIST recognizes WebAuthn/FIDO2 as verifier-name bound.

**Assumptions:** browser WebAuthn implementation correctly enforces RP rules; no legitimate-origin compromise.

## Claim E — composite protocol can satisfy the NIST phishing-resistance property

**Argument:** ordinary transferable OTP is no longer the complete accepted authenticator output. The required cryptographic output depends on a genuine-verifier session challenge and the secret can only be recovered through an RP-bound WebAuthn credential operation. An impostor verifier therefore cannot obtain a generally reusable valid authenticator output merely by soliciting a six-digit code from the claimant.

This is a reasoned architecture claim, not third-party certification.

---

# 19. Glossary

**AAL — Authenticator Assurance Level**  
NIST assurance category describing confidence in authentication. SP 800-63B-4 defines AAL1, AAL2, and AAL3.

**Activation factor**  
A local factor such as a PIN or biometric characteristic used to activate a multi-factor authenticator. It is not necessarily sent to the verifier.

**Authentication key**  
A private or symmetric key used by an authenticator to generate authenticator output.

**Authentication protocol**  
The sequence of messages between claimant and verifier that demonstrates control of authenticators and may demonstrate communication with the intended verifier.

**AuthenticationSession**  
Keycloak server-side state object associated with an in-progress authentication flow. ZeroOTP stores the per-login challenge in this state.

**Authenticator output**  
A value generated by an authenticator whose valid production demonstrates possession/control. The ZeroOTP Keycloak verifier effectively requires TOTP plus a valid session proof.

**AES-GCM**  
Authenticated-encryption mode based on AES, used by ZeroOTP to encrypt the local TOTP vault.

**Challenge / nonce**  
Fresh verifier value incorporated into an authentication transaction to prevent replay and prove freshness.

**Channel binding**  
NIST-recognized phishing-resistance mechanism that cryptographically binds authentication output to a particular authenticated protected channel.

**CTAP**  
FIDO Client to Authenticator Protocol. The `hmac-secret` authenticator extension is related to the WebAuthn PRF extension.

**FIDO2**  
Technology family combining WebAuthn and CTAP for public-key authentication.

**HKDF**  
HMAC-based Extract-and-Expand Key Derivation Function defined by RFC 5869.

**HMAC**  
Keyed-hash message authentication code. ZeroOTP uses HMAC-SHA-256 for the session proof.

**HOTP**  
HMAC-Based One-Time Password defined in RFC 4226. TOTP uses HOTP with a time-derived moving factor.

**Multi-factor cryptographic authenticator**  
NIST category in which possession/control of an authentication key is demonstrated through a cryptographic protocol and the authenticator requires an additional activation factor.

**Multi-factor OTP authenticator**  
NIST category in which an OTP is generated after activation by a second factor. NIST states OTP authentication is not phishing-resistant when output is manually transferred.

**Phishing resistance**  
NIST property whereby the authentication protocol prevents disclosure of authentication secrets and valid authenticator outputs to an impostor verifier without relying on claimant vigilance.

**PRF — Pseudo-Random Function**  
In WebAuthn Level 3, a credential-associated function exposed through the `prf` extension, producing 32-byte outputs for RP-provided inputs. ZeroOTP uses PRF output as keying material.

**RP — Relying Party**  
The web service/application using WebAuthn. Credential scope is bound to the RP identifier according to WebAuthn rules.

**RFC 6238 / TOTP**  
Time-Based One-Time Password algorithm using a shared secret and time-derived moving factor.

**Session binding**  
The property that an authentication response is valid only for the verifier session for which it was created. ZeroOTP v1.1.0 implements this with HMAC over a per-session challenge and TOTP.

**sessionProof**  
The ZeroOTP HMAC-SHA-256 response that authenticates the Keycloak challenge and exact TOTP under the shared secret.

**Verifier**  
The entity that validates authenticator output. In the plugin architecture, Keycloak is the verifier.

**Verifier-name binding**  
NIST-recognized phishing-resistance mechanism that cryptographically binds authenticator output or secret selection/derivation to an authenticated verifier identifier. WebAuthn is NIST's canonical example.

**WebAuthn**  
W3C Web Authentication API for public-key credentials. ZeroOTP uses it to create/use a credential and evaluate PRF output.

---

# 20. References

## 20.1 NIST

1. **NIST SP 800-63B-4 — Digital Identity Guidelines: Authentication and Authenticator Management**  
   <https://pages.nist.gov/800-63-4/sp800-63b.html>

2. **Authenticator requirements, cryptographic authenticators, phishing resistance, replay resistance, random values**  
   <https://pages.nist.gov/800-63-4/sp800-63b/authenticators/>

3. **Authentication Assurance Levels**  
   <https://pages.nist.gov/800-63-4/sp800-63b/aal/>

4. **NIST publication record for SP 800-63B-4**  
   <https://csrc.nist.gov/pubs/sp/800/63/b/4/final>

5. **NIST SP 800-38D — Galois/Counter Mode (GCM)**  
   <https://csrc.nist.gov/pubs/sp/800/38/d/final>

6. **NIST Message Authentication Codes / HMAC guidance**  
   <https://csrc.nist.gov/projects/message-authentication-codes>

7. **NIST SP 800-131A Rev. 2 — Cryptographic Algorithm and Key-Length Transitions**  
   <https://csrc.nist.gov/pubs/sp/800/131/a/r2/final>

## 20.2 WebAuthn, FIDO, and IETF

8. **W3C Web Authentication Level 3 — PRF extension**  
   <https://www.w3.org/TR/webauthn-3/#prf-extension>

9. **FIDO CTAP 2.2 — hmac-secret**  
   <https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html>

10. **RFC 6238 — TOTP: Time-Based One-Time Password Algorithm**  
    <https://www.rfc-editor.org/rfc/rfc6238>

11. **RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm**  
    <https://www.rfc-editor.org/rfc/rfc4226>

12. **RFC 5869 — HKDF**  
    <https://www.rfc-editor.org/rfc/rfc5869>

## 20.3 Microsoft

13. **Microsoft Entra authentication overview**  
    <https://learn.microsoft.com/en-us/entra/identity/authentication/overview-authentication>

14. **Microsoft Entra Conditional Access authentication strengths**  
    <https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths>

15. **Passkeys (FIDO2) in Microsoft Entra ID**  
    <https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-passkeys-fido2>

16. **Microsoft mapping for NIST AAL2**  
    <https://learn.microsoft.com/en-us/entra/standards/nist-authenticator-assurance-level-2>

---

# 21. Conclusion

ZeroOTP demonstrates that preserving an RFC 6238 compatibility core does not require accepting the security properties of a bare, manually transferable OTP as the complete authentication protocol.

At the repository root, WebAuthn PRF materially strengthens the protection and activation of the local TOTP secret, but the standalone TOTP output remains an OTP and therefore should not be labeled phishing-resistant under NIST merely because its secret was unlocked through WebAuthn.

The Keycloak v1.1.0 profile introduces the missing protocol element: a verifier-created, per-authentication-session challenge authenticated under a cryptographic MAC. Keycloak refuses to authenticate on the basis of the six-digit TOTP alone. The same server challenge is also used in the WebAuthn/PRF credential ceremony. This produces a composite design in which the local secret release is verifier-name bound and the accepted server response is explicitly session bound.

The resulting security claim must remain precise. ZeroOTP does not make RFC 6238 itself phishing-resistant. Instead, it **encapsulates RFC 6238 inside a broader cryptographic authentication protocol** designed to satisfy the NIST phishing-resistance objective. The design's strongest differentiator is exactly the addition requested by NIST's phishing-resistance model: a cryptographic relationship between authenticator output and the verifier/session for which that output is valid.

For Microsoft Entra, the same protocol-property conclusion cannot be mechanically translated into a built-in Conditional Access authentication strength. Microsoft policy recognition is method-specific. A custom Keycloak provider remains a third-party/federated implementation unless Microsoft explicitly recognizes it through a supported integration path.

For security architecture purposes, this separation is the correct final position:

```text
Standalone ZeroOTP PRF:
    strong PRF-protected TOTP secret release
    + WebAuthn RP binding
    - final transferable OTP
    => not phishing-resistant as a complete TOTP authentication flow

ZeroOTP Keycloak v1.1.0:
    WebAuthn PRF verifier binding
    + required user verification
    + RFC 6238 compatibility
    + 256-bit verifier challenge
    + HMAC-SHA-256 session proof
    + single-use authentication-session state
    => phishing-resistant composite protocol is technically supportable,
       without claiming NIST certification or AAL3
```

---

# 22. Protocol State Machine and Failure Semantics

A security review benefits from treating the Keycloak profile as a state machine rather than as a sequence of loosely related browser actions. This makes it possible to reason about whether stale values, retries, or reordered messages can accidentally satisfy the verifier.

## 22.1 States

A simplified authentication state machine is:

```text
S0  User identified, ZeroOTP credential exists
 |
 | create fresh C
 v
S1  AuthenticationSession contains C
 |
 | render form with C
 v
S2  Browser holds C and local encrypted vault metadata
 |
 | WebAuthn get(challenge=C, PRF input)
 v
S3  Credential operation + user verification succeeded
 |
 | PRF output -> HKDF -> AES decrypt
 v
S4  Browser temporarily holds K
 |
 | compute O=TOTP(K,time)
 | compute P=HMAC(K,L||C||0||O)
 v
S5  Browser submits (O,P)
 |
 | server reads C from AuthenticationSession
 v
S6  server validates O and P
 |
 | consume C
 +-----------------------+
 |                       |
 valid                 invalid
 |                       |
 v                       v
S7 success             S8 failure/new challenge on retry
```

The critical invariant is:

> **There must be no transition to authenticated state unless the verifier still possesses the exact challenge that was used to produce the submitted proof.**

The current implementation satisfies this by retrieving the challenge from `AuthenticationSession` rather than trusting a challenge echoed from a hidden browser form field.

## 22.2 Why the challenge must remain server-side state

If the browser were allowed to submit both `challenge` and `proof`, with no server-side record of the challenge, the attacker could choose an arbitrary challenge and ask for a matching proof. That would provide freshness from the client's perspective but would not bind the proof to a verifier-controlled authentication transaction.

The current design instead treats the browser copy as an instruction/input and the server-side `AuthenticationSession` note as authoritative state.

## 22.3 Retry behavior

A failed unlock or validation attempt must not preserve a challenge indefinitely. The plugin either consumes the challenge after a validation attempt or creates a new challenge when a retry form is generated. This means that a user action performed after a failed transaction targets a new cryptographic context.

For operational testing, this behavior should be verified explicitly by observing that two consecutive login forms contain different `serverChallenge` values and that a proof generated for the first form does not validate against the second.

## 22.4 Cancellation and abandonment

If the user cancels WebAuthn, no valid proof is produced. The existing authentication session may remain until Keycloak expires or advances the flow, but no authentication success can occur without `(O,P)` validation. Production configurations should set ordinary Keycloak authentication-session lifetimes appropriately so abandoned challenges do not remain indefinitely.

## 22.5 Concurrent tabs

Concurrent browser tabs are an important edge case. Keycloak can create separate authentication sessions, each with a distinct challenge. A response computed in tab A should not be accepted in tab B. This is a direct negative test of the binding property and should be part of regression testing.

## 22.6 Time-window overlap

Because TOTP codes are time-based, the same `O` may be valid for more than one concurrent Keycloak session during the same time step. The session proof deliberately resolves this ambiguity:

```text
P_A = HMAC(K,L||C_A||0||O)
P_B = HMAC(K,L||C_B||0||O)
```

Even where `O_A == O_B`, the proofs are distinct because `C_A != C_B`.

This is precisely why session binding is stronger than relying on TOTP replay resistance alone.

---

# 23. Verification and Security Test Plan

The following test plan is intended for a technical review or pre-production validation. It focuses on security properties rather than only functional success.

## 23.1 Baseline enrollment tests

1. Enroll on a supported browser/authenticator with PRF available.
2. Confirm the local record contains ciphertext and metadata but not the plaintext TOTP secret.
3. Confirm enrollment fails when PRF output is unavailable.
4. Confirm enrollment requires `userVerification` according to the selected authenticator behavior.
5. Confirm the Keycloak credential is associated with the intended user and realm.

Expected result: no non-PRF fallback is silently selected.

## 23.2 Baseline authentication tests

1. Start a fresh login.
2. Confirm Keycloak emits a `serverChallenge`.
3. Complete WebAuthn verification.
4. Confirm a valid `totpCode` and non-empty `sessionProof` are posted.
5. Confirm Keycloak accepts the pair.
6. Confirm the authentication-session challenge is consumed.

## 23.3 OTP-only negative test

Capture a valid `totpCode` but omit `sessionProof`.

Expected result: authentication fails with incomplete cryptographic response/session state.

This demonstrates that the protocol no longer accepts the TOTP as an independent authenticator output.

## 23.4 Proof-only negative test

Submit a valid-looking `sessionProof` but omit or alter the TOTP.

Expected result: authentication fails. The proof authenticates the exact TOTP value included in its HMAC input.

## 23.5 Cross-session replay test

1. Open two independent Keycloak login sessions A and B for the same user.
2. Confirm `challenge_A != challenge_B`.
3. Complete ZeroOTP in session A and capture `(O_A,P_A)` before submission or in a controlled test harness.
4. Submit `(O_A,P_A)` to session B.

Expected result: session B fails even if `O_A` is still within the valid TOTP time step.

This is the principal test of the new phishing/relay control.

## 23.6 Same-session duplicate replay test

1. Complete authentication in session A.
2. Attempt to replay the exact same HTTP form against the same authentication endpoint/session.

Expected result: authentication must not succeed a second time because the challenge is consumed or the authentication session has advanced.

## 23.7 Altered proof test

Flip one bit of the Base64URL-decoded proof.

Expected result: `MessageDigest.isEqual()` comparison fails.

## 23.8 Altered challenge test

If a test harness can manipulate the browser-visible `serverChallenge` while the server retains the original challenge, generate a proof over the modified value.

Expected result: server verification fails because its authoritative challenge differs.

## 23.9 Wrong credential / wrong vault tests

- replace `credentialId` with another credential;
- replace the local ciphertext with another user's or another RP's vault record;
- alter `prfSalt` or `hkdfSalt`;
- attempt login after deleting localStorage.

Expected results should be failure without fallback to a weaker unlock method.

## 23.10 RP-origin phishing test

Host a visually identical page on a different domain and attempt to request the legitimate RP credential/PRF operation.

Expected result: browser WebAuthn RP/origin rules prevent the impostor origin from operating as the genuine RP.

This test validates the browser/platform behavior on which the verifier-name-binding argument depends.

## 23.11 TOTP clock-drift tests

Validate accepted and rejected time windows around step boundaries. The server currently uses a small window consistent with Keycloak's OTP validation behavior. Ensure that increased drift tolerance does not accidentally become a substitute for session freshness; the HMAC challenge remains the decisive session-binding element.

## 23.12 Brute-force and throttling tests

Drive repeated invalid TOTP/proof submissions and verify Keycloak's configured brute-force protections and account throttling. Cryptographic session binding is not a reason to omit online abuse controls.

## 23.13 Logging tests

Inspect application and reverse-proxy logs after successful and failed attempts. Verify that they do not expose:

```text
TOTP shared secret
PRF output
HKDF-derived AES key
plaintext vault
full sessionProof unless explicitly required for a controlled debug build
```

## 23.14 Browser compromise boundary test

A controlled same-origin test script can demonstrate the residual endpoint boundary: once legitimate application JavaScript has reconstructed the TOTP secret in memory, same-origin malicious code with equivalent execution privileges may be able to observe or manipulate application state. This test should be documented as a limitation, not treated as a protocol failure; it confirms why XSS prevention remains part of the trusted computing base.

---

# 24. NIST Requirement Traceability Matrix

The following matrix is not a certification checklist. It maps significant SP 800-63B-4 concepts to the implementation so reviewers can identify both supporting evidence and gaps.

| NIST concept | ZeroOTP Keycloak evidence | Assessment / remaining work |
|---|---|---|
| Authenticated protected channel | Production deployment is intended for HTTPS; WebAuthn requires secure context | Must be enforced in production deployment architecture |
| Multi-factor activation | WebAuthn requests `userVerification: required`; credential possession/control plus PIN/biometric according to authenticator | Actual factor characteristics depend on authenticator/platform implementation |
| Cryptographic authentication | HMAC-SHA-256 response under authentication key `K` | Present at protocol layer |
| Verifier challenge | 256-bit `SecureRandom` value generated by Keycloak | Strong implementation pattern; cryptographic-module requirements depend on deployment context |
| Challenge uniqueness/freshness | New challenge for login/retry; stored per `AuthenticationSession` | Regression-test concurrent and retry cases |
| Replay resistance | HMAC includes per-session challenge; challenge consumed | Stronger than TOTP time-step replay resistance alone |
| Phishing resistance | WebAuthn verifier-name binding + session-bound cryptographic proof | Architecture supports the property; no claim of external certification |
| Manual OTP transfer exclusion | Accepted login requires non-manual cryptographic proof in addition to TOTP | TOTP alone is insufficient |
| Rate limiting | Available through Keycloak controls; TOTP verifier semantics still require protection | Must be configured/tested operationally |
| Authenticator binding | Keycloak custom credential and required-action enrollment | Enrollment assurance depends on flow used to authorize registration |
| Authenticator lifecycle | Keycloak credential can be enrolled/deleted | Recovery, replacement, notification, and enterprise policy need deployment procedures |
| Random values | Java `SecureRandom`, browser Web Crypto random values | Review platform/FIPS requirements where applicable |
| Approved cryptography | AES-GCM, HMAC-SHA-256, HKDF-SHA-256 are standard approved-family constructions; TOTP implementation uses HMAC-SHA-1 per RFC compatibility | Federal conformance also depends on validated modules and precise NIST requirements |
| Authentication intent | User verification is required, but explicit user-intent properties depend on authenticator UX and platform | Must be assessed for deployment/AAL claim |
| Verifier-compromise protection | Symmetric `K` stored at verifier | Weaker than public-key WebAuthn; prevents AAL3 claim in current architecture |
| Non-exportable key for AAL3 | Not established for the symmetric application key; syncable credentials may be exportable | AAL3 not claimed |
| Public-key cryptography at AAL3 | Final custom verifier proof is symmetric HMAC | AAL3 not satisfied by this design |
| FIPS validation | Not established by repository | Required where applicable; outside current project evidence |

The matrix illustrates why **phishing resistance is a property that can be argued independently of AAL3**. A protocol can provide verifier/session binding while still failing other AAL3 requirements.

---

# 25. Final Architectural Position

The most important conceptual result of the v1.1.0 work is that ZeroOTP now has a clean boundary between three layers:

```text
Layer 1 — Credential/RP layer
WebAuthn credential + user verification + PRF
Purpose: authorize access to credential-associated keying material

Layer 2 — Local secret-protection layer
PRF output -> HKDF -> AES-GCM
Purpose: protect the browser-side TOTP secret at rest

Layer 3 — Verifier/session authentication layer
TOTP + HMAC-SHA-256(server challenge, TOTP)
Purpose: make the verifier accept only an output bound to the current
Keycloak authentication session
```

A security classification that looks only at Layer 2 will overstate the standalone application. A classification that looks only at the six-digit code in Layer 3 will understate the plugin. The correct object of analysis is the complete protocol.

This layered interpretation is also the best way to explain the technology to a highly technical reviewer: **PRF protects the ability to recover the secret; the HMAC challenge response protects the use of that secret in authentication.**
