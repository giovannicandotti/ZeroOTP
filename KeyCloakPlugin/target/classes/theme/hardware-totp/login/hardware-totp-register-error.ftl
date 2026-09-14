<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("Configurazione non riuscita")}
    <#elseif section = "form">
        <p>
            Il dispositivo o il browser corrente non soddisfa i requisiti necessari
            (passkey con estensione PRF, hardware). Questo metodo non puo' essere
            attivato senza tale supporto &mdash; non esiste un livello di sicurezza
            ridotto per dispositivi non compatibili.
        </p>
        <p>
            <a href="${url.loginAction}">Riprova</a>
        </p>
    </#if>
</@layout.registrationLayout>
