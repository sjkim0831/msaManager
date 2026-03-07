FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /workspace/module/EgovMsaManager
COPY module/EgovMsaManager/pom.xml ./
RUN mvn -q -DskipTests dependency:go-offline
COPY module/EgovMsaManager/src ./src
RUN mvn -q -DskipTests package

FROM eclipse-temurin:17-jre
WORKDIR /opt/msaManager
COPY --from=build /workspace/module/EgovMsaManager/target/EgovMsaManager.jar /opt/msaManager/EgovMsaManager.jar
EXPOSE 18030
ENTRYPOINT ["sh", "-lc", "java -Dcarbosys.root=${CARBOSYS_ROOT:-/opt/carbosys} -Xms128m -Xmx256m -jar /opt/msaManager/EgovMsaManager.jar --server.port=18030"]
