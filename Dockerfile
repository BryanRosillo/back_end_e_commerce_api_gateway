FROM maven:3.8-openjdk-17-slim AS build
WORKDIR /app
COPY pom.xml ./
COPY src ./src

ARG MICROSERVICIO_SEGURIDAD_URI
ENV MICROSERVICIO_SEGURIDAD_URI=${MICROSERVICIO_SEGURIDAD_URI}

ARG MICROSERVICIO_PRODUCTOS_URI
ENV MICROSERVICIO_PRODUCTOS_URI=${MICROSERVICIO_PRODUCTOS_URI}

ARG MICROSERVICIO_PEDIDOS_URI
ENV MICROSERVICIO_PEDIDOS_URI=${MICROSERVICIO_PEDIDOS_URI}

ARG MICROSERVICIO_CHAT_URI
ENV MICROSERVICIO_CHAT_URI=${MICROSERVICIO_CHAT_URI}

ARG MICROSERVICIO_REGISTRO_URI
ENV MICROSERVICIO_REGISTRO_URI=${MICROSERVICIO_REGISTRO_URI}

RUN mvn clean package 

FROM openjdk:17-jdk-slim
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT [ "java", "-jar", "app.jar" ]