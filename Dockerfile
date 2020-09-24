FROM openjdk:14-alpine
COPY build/libs/io.zenkoderz.io.labs.acceptor-*-all.jar acceptor.jar
EXPOSE 8080
CMD ["java", "-Dcom.sun.management.jmxremote", "-Xmx128m", "-jar", "acceptor.jar"]