# ---- 构建阶段 ----
FROM golang:1.24-alpine AS builder

WORKDIR /src

# 先拉取依赖，充分利用镜像缓存
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/proxy .

# ---- 运行阶段 ----
FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 proxy

COPY --from=builder /out/proxy /usr/local/bin/proxy

USER proxy
EXPOSE 1080 8080

ENTRYPOINT ["/usr/local/bin/proxy"]
CMD ["-c", "/etc/proxy/config.yaml"]
