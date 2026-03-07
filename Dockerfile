FROM maven:3.9-eclipse-temurin-17

WORKDIR /opt/util/msaManager

COPY scripts/start-manager-docker.sh /opt/util/msaManager/scripts/start-manager-docker.sh
RUN chmod +x /opt/util/msaManager/scripts/start-manager-docker.sh

# Fallback source copy (normally overridden by bind mount in docker-compose)
COPY EgovMsaManager /opt/util/msaManager/EgovMsaManager

EXPOSE 18030-18039
ENTRYPOINT ["bash", "-lc", "/opt/util/msaManager/scripts/start-manager-docker.sh"]
