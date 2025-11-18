# 使用官方 Java 17 镜像
FROM openjdk:25-slim

# 设置工作目录
WORKDIR /app

# 复制所有文件到容器中
COPY . .

# 编译 Java 文件
RUN javac backend.java

# 暴露端口（Render 会自动映射）
EXPOSE 10000

# 启动应用
CMD ["java", "backend"]