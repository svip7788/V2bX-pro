# Build go
FROM golang:1.27-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN GOEXPERIMENT=jsonv2 go mod download
RUN GOEXPERIMENT=jsonv2 go build -v -o V2bX -tags "xray"

# Release
FROM  alpine
# 安装必要的工具包
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/V2bX/
COPY --from=builder /app/V2bX /usr/local/bin

ENTRYPOINT [ "V2bX", "server", "--config", "/etc/V2bX/config.json"]
