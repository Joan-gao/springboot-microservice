# 使用Java官方镜像作为基础镜像
FROM openjdk:22-jdk-slim

# 指定维护者信息
LABEL maintainer="xgao9917@gmail.com"

# 添加一个卷，指向 /tmp
WORKDIR /app

# 将你的jar包添加到容器中
COPY target/order-service-1.0-SNAPSHOT.jar /app/order-service-1.0-SNAPSHOT.jar

# 声明运行时容器提供服务端口
EXPOSE 8080

# 配置容器启动后执行的命令
ENTRYPOINT ["java", "-jar", "/app/order-service-1.0-SNAPSHOT.jar"]
