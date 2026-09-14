<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("Configura TOTP hardware")}
    <#elseif section = "form">
        <div id="htotp-status" style="margin-bottom: 1em;">Preparazione della cerimonia passkey in corso&hellip;</div>
        <form id="kc-htotp-register-form" action="${url.loginAction}" method="post">
            <input type="hidden" id="outcome" name="outcome" value="">
            <input type="hidden" id="credentialId" name="credentialId" value="">
            <input type="hidden" id="publicKeyDer" name="publicKeyDer" value="">
            <input type="hidden" id="publicKeyAlgorithm" name="publicKeyAlgorithm" value="">
            <input type="hidden" id="assertionCredentialId" name="assertionCredentialId" value="">
            <input type="hidden" id="assertionClientDataJSON" name="assertionClientDataJSON" value="">
            <input type="hidden" id="assertionAuthenticatorData" name="assertionAuthenticatorData" value="">
            <input type="hidden" id="assertionSignature" name="assertionSignature" value="">
            <input type="hidden" id="aaguid" name="aaguid" value="">
            <input type="hidden" id="attestationFormat" name="attestationFormat" value="">
            <input type="hidden" id="backupEligible" name="backupEligible" value="">
            <input type="hidden" id="backupState" name="backupState" value="">
            <input type="hidden" id="errorMessage" name="errorMessage" value="">
        </form>
        <script>
            window.HTOTP_ENROLL_DATA = {
                secret: "${secret}",
                issuer: "${issuer}",
                username: "${username}",
                rpId: "${rpId}",
                createChallenge: "${createChallenge}",
                assertionChallenge: "${assertionChallenge}"
            };
        </script>
        <script src="${url.resourcesPath}/js/hardware-totp-common.js"></script>
        <script src="${url.resourcesPath}/js/hardware-totp-register.js"></script>
    </#if>
</@layout.registrationLayout>
