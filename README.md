# proxy

一个用 Go 实现的 **HTTP + SOCKS5 正向代理服务器**。

两者都在**传输层**建立 TCP 隧道，对上层协议完全透明，因此除了网页访问外，
还可以直接代理 **MongoDB、MySQL、PostgreSQL、Redis、SSH** 等任意基于 TCP 的服务。

## 特性

- **SOCKS5（RFC 1928）**
  - `CONNECT` —— 纯 TCP 隧道，数据库代理的核心路径
  - `BIND` —— 支持 FTP 主动模式（默认关闭）
  - `UDP ASSOCIATE` —— UDP 数据报中继，带源地址校验，不会变成开放中继
  - 用户名/密码认证（RFC 1929），常量时间比较避免时序侧信道
  - 域名 / IPv4 / IPv6 三种地址类型
- **HTTP 代理**
  - 普通请求转发（绝对 URI），自动清理逐跳首部、补充 `X-Forwarded-For`
  - `CONNECT` 隧道（HTTPS 及任意 TCP 协议）
  - `Basic` 代理认证（`407 Proxy Authentication Required`）
  - 支持 HTTP keep-alive 连接复用
- **访问控制（ACL）**：按 IP/CIDR、域名（含子域通配）、端口范围放行或拒绝
- **连接管理**：连接超时、空闲超时、半关闭宽限期，避免连接悬挂
- **内置 SOCKS5 客户端拨号器**：可直接接入 MongoDB / MySQL 官方驱动
- **零外部运行时依赖**，标准库实现；支持 YAML 配置与命令行覆盖

## 快速开始

```bash
# 直接编译运行（SOCKS5 :1080 + HTTP :8080，默认配置）
go run .

# 编译
go build -o proxy .

# 指定配置文件
./proxy -c config.yaml

# 纯命令行启动，要求账号认证
./proxy -socks5 :1080 -http :8080 -user dbuser -pass dbpass

# 拉取预构建镜像（GHCR，linux/amd64 + linux/arm64）
docker pull ghcr.io/sixath/proxy:latest

# 用镜像内置默认配置启动（SOCKS5 :1080 + HTTP :8080）
docker run --rm -p 1080:1080 -p 8080:8080 ghcr.io/sixath/proxy:latest

# 挂载自定义配置
docker run --rm -p 1080:1080 -p 8080:8080 \
  -v $PWD/config.yaml:/etc/proxy/config.yaml ghcr.io/sixath/proxy:latest

# 本地构建
docker build -t proxy:latest .

# 多架构构建并推送到自己的仓库
docker buildx build --platform linux/amd64,linux/arm64 \
  -t <your-registry>/proxy:latest --push .
```

> 镜像内已内置 `config.yaml` 默认配置，不挂载也能直接跑。
> 容器内以非 root 用户（`uid 10001`）运行。

## 使用场景

> **关于 `internal/` 目录**：下面的 Go 示例直接引用了 `internal/socks5` 中的客户端
> 拨号器。Go 的 `internal` 机制只允许本模块内部引用，若要在**其它项目**中复用，
> 请把顶层 `internal` 目录改名为 `pkg`（同步调整 import 路径），
> 或将 `internal/socks5/client.go` 复制到你的项目中。

### 1. 浏览器 / 命令行走 HTTP 代理

```bash
curl -x http://127.0.0.1:8080 http://example.com
curl -x http://user:pass@127.0.0.1:8080 https://example.com

export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
```

### 2. 走 SOCKS5 代理

```bash
curl -x socks5://127.0.0.1:1080 http://example.com
curl -x socks5h://user:pass@127.0.0.1:1080 http://example.com
```

### 3. 通过 SOCKS5 代理 MongoDB

MongoDB 官方 Go 驱动可以通过自定义 Dialer 接入代理：

```go
import (
    "context"
    "net"

    "github.com/sixath/proxy/internal/socks5"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

// 适配器：把 mongo 需要的 Dialer 接口接到 SOCKS5 客户端上
type mongoDialer struct{ c *socks5.Client }

func (d mongoDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
    return d.c.DialContext(ctx, network, addr)
}

func connectMongo(ctx context.Context) (*mongo.Client, error) {
    socks := socks5.NewClient("127.0.0.1:1080",
        socks5.WithClientAuth("dbuser", "dbpass"),
    )
    return mongo.Connect(ctx, options.Client().
        ApplyURI("mongodb://mongo-host:27017").
        SetDialer(mongoDialer{c: socks}))
}
```

其它语言/工具的常见做法：

```bash
# socat 做本地端口转发，客户端连本地 27018 即可
socat TCP-LISTEN:27018,fork SOCKS5:127.0.0.1:mongo-host:27017,socksport=1080

# ncat
ncat --proxy 127.0.0.1:1080 --proxy-type socks5 --listen 27018 --keep-open
```

### 4. 通过 SOCKS5 代理 MySQL

```go
import (
    "database/sql"
    "net"

    "github.com/sixath/proxy/internal/socks5"
    "github.com/go-sql-driver/mysql"
)

func init() {
    socks := socks5.NewClient("127.0.0.1:1080",
        socks5.WithClientAuth("dbuser", "dbpass"),
    )
    mysql.RegisterDialer("tcp", func(addr string) (net.Conn, error) {
        return socks.Dial("tcp", addr)
    })
}

func connectMySQL() (*sql.DB, error) {
    return sql.Open("mysql", "root:pwd@tcp(mysql-host:3306)/appdb")
}
```

命令行工具可用 `socat` / `proxychains` / `ncat --proxy` 做同样的端口转发。

> **要点**：MongoDB 与 MySQL 都跑在 TCP 之上，SOCKS5 的 `CONNECT`
> 只负责搬运字节流、不解析报文内容，所以无需为每种数据库做适配。

## 配置

完整示例见 `config.yaml`，主要字段：

| 配置段 | 字段 | 说明 |
| --- | --- | --- |
| `log` | `level` / `format` / `output` | 日志级别、格式（text/json）、输出目标 |
| `socks5` | `enabled` / `listen` | 是否启用与监听地址，默认 `:1080` |
| `socks5` | `connect_timeout` / `idle_timeout` / `grace_timeout` | 连接、空闲、半关闭超时 |
| `socks5` | `udp` / `bind` | 是否启用 UDP 中继与 BIND 命令 |
| `socks5.auth` | `enabled` / `users` | 是否强制认证及账号列表 |
| `http` | `enabled` / `listen` | 是否启用与监听地址，默认 `:8080` |
| `http` | `forward_timeout` | 单个 HTTP 请求整体超时 |
| `http.auth` | `enabled` / `users` | 代理认证 |
| `acl` | `default` / `rules` | 默认动作与规则列表 |

### ACL 规则

规则按顺序匹配，**第一条命中的规则决定结果**；同一条规则内 `cidr`/`domain`/`port`
是「与」关系，留空的维度表示不限制。

```yaml
acl:
  default: allow
  rules:
    - action: deny
      cidr: ["127.0.0.0/8", "10.0.0.0/8"]
    - action: deny
      domain: ["internal.example.com"]   # 含子域
    - action: deny
      port: ["22", "8000-8080"]          # 支持端口范围
```

## 命令行参数

| 参数 | 说明 |
| --- | --- |
| `-c <path>` | 配置文件路径，文件不存在时使用默认配置 |
| `-socks5 <addr>` | 覆盖 SOCKS5 监听地址 |
| `-http <addr>` | 覆盖 HTTP 代理监听地址 |
| `-user` / `-pass` | 设置代理账号（同时生效于两个服务） |
| `-log-level` | 覆盖日志级别 |
| `-version` | 打印版本 |

命令行参数的优先级高于配置文件。

## 项目结构

```
.
├── main.go                     入口：装配配置、启动服务、优雅退出
├── config.yaml                 示例配置
├── internal/
│   ├── config/                 配置加载与校验
│   ├── logger/                 日志封装
│   ├── acl/                    访问控制规则
│   ├── relay/                  双向 TCP 转发（隧道核心）
│   ├── socks5/                 SOCKS5 服务端 + 客户端拨号器
│   └── httpproxy/              HTTP 代理服务端
├── .github/workflows/         CI：构建并推送多架构镜像到 GHCR
└── Dockerfile                 多阶段构建，产物为静态二进制 + alpine
```

## 开发

```bash
go build ./...
go vet ./...
go test ./...
go test -race ./...
```

## 安全建议

- 部署在公网时**务必开启认证**（`auth.enabled: true`），否则会成为开放代理。
- 建议配置 ACL 拒绝内网网段（`127.0.0.0/8`、`10.0.0.0/8` 等），避免被用作内网跳板。
- UDP 中继会校验数据报源地址，仅接受发起 `UDP ASSOCIATE` 的客户端地址。
