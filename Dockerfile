# ---- 构建阶段 ----
ARG GO_VERSION=1.24
FROM golang:${GO_VERSION}-alpine AS builder

# buildx 交叉编译时会自动注入这两个值
ARG TARGETOS=linux
ARG TARGETARCH=amd64
# 版本号写入二进制，可通过 --build-arg VERSION=xxx 覆盖
ARG VERSION=dev

WORKDIR /src

# 先拉取依赖，充分利用镜像层缓存
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/proxy .

# ---- 运行阶段 ----
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 proxy \
    && mkdir -p /etc/proxy \
    && chown proxy:proxy /etc/proxy

COPY --from=builder /out/proxy /usr/local/bin/proxy
# 内置默认配置，容器可直接启动；需要自定义时挂载覆盖即可
COPY config.yaml /etc/proxy/config.yaml

USER proxy
EXPOSE 1080 8080

ENTRYPOINT ["/usr/local/bin/proxy"]
CMD ["-c", "/etc/proxy/config.yaml"]
