# Dockerfile — immagine Keycloak con il plugin hardware-prf-totp integrato.
#
# Costruire il JAR PRIMA di questo step (vedi README.md):
#   mvn clean package
#   -> genera target/zerotp-hardware-totp-1.2.0.jar
#
# Poi:
#   docker build -t zerotp-keycloak:latest .

FROM quay.io/keycloak/keycloak:latest AS builder

# Copia il JAR del plugin nella cartella dei provider.
COPY target/zerotp-hardware-totp-1.2.0.jar /opt/keycloak/providers/

# 'kc.sh build' compila la configurazione (incluso il nostro provider)
# nell'immagine ottimizzata di Keycloak. Va rifatto ogni volta che il JAR
# del plugin cambia.
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:latest
COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
