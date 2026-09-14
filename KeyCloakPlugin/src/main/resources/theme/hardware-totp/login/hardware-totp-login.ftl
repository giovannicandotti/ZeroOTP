<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("Accesso con TOTP hardware")}
    <#elseif section = "form">
        <div id="htotp-status" style="margin-bottom: 1em;">
            In attesa della verifica biometrica&hellip;
        </div>

        <button id="htotp-retry-btn" type="button" class="pf-c-button pf-m-primary" style="display:none;">
            Riprova con passkey
        </button>

        <form id="kc-htotp-login-form" action="${url.loginAction}" method="post">
            <input type="hidden" id="outcome" name="outcome" value="">
            <input type="hidden" id="totpCode" name="totpCode" value="">
            <input type="hidden" id="sessionProof" name="sessionProof" value="">
            <input type="hidden" id="assertionCredentialId" name="assertionCredentialId" value="">
            <input type="hidden" id="assertionClientDataJSON" name="assertionClientDataJSON" value="">
            <input type="hidden" id="assertionAuthenticatorData" name="assertionAuthenticatorData" value="">
            <input type="hidden" id="assertionSignature" name="assertionSignature" value="">
            <input type="hidden" id="errorMessage" name="errorMessage" value="">
        </form>

        <script>
            window.HTOTP_LOGIN_DATA = {
                rpId: "${rpId?js_string}",
                serverChallenge: "${serverChallenge?js_string}",
                isRetry: ${isRetry?c}
            };
        </script>
        <script src="${url.resourcesPath}/js/hardware-totp-common.js"></script>
        <script src="${url.resourcesPath}/js/hardware-totp-login.js"></script>
    </#if>
</@layout.registrationLayout>
