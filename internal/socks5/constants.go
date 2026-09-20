// Package socks5 实现 RFC 1928 定义的 SOCKS5 代理服务器。
//
// SOCKS5 工作在传输层，CONNECT 命令建立的是一条纯粹的 TCP 隧道，
// 因此它对上层应用协议完全透明——无论是 HTTP、MySQL、MongoDB、Redis
// 还是任何自定义 TCP 协议，都可以通过它进行代理。
package socks5

import "errors"

// Version5 是 SOCKS 协议版本号。
const Version5 = 0x05

// 认证方法（RFC 1928）。
const (
	MethodNoAuth       = 0x00 // 无需认证
	MethodGSSAPI       = 0x01 // GSSAPI（本实现不支持）
	MethodUserPass     = 0x02 // 用户名/密码认证（RFC 1929）
	MethodNoAcceptable = 0xFF // 没有可接受的认证方法
)

// 请求命令（RFC 1928）。
const (
	CmdConnect      = 0x01 // 建立 TCP 连接并透传数据
	CmdBind         = 0x02 // 监听入站连接（如 FTP 主动模式）
	CmdUDPAssociate = 0x03 // UDP 中继
)

// 地址类型（RFC 1928）。
const (
	AtypIPv4   = 0x01 // 4 字节 IPv4 地址
	AtypDomain = 0x03 // 1 字节长度 + 域名
	AtypIPv6   = 0x04 // 16 字节 IPv6 地址
)

// 响应码（RFC 1928）。
const (
	RepSuccess                 = 0x00 // 成功
	RepGeneralFailure          = 0x01 // 通用失败
	RepConnectionNotAllowed    = 0x02 // 被规则集拒绝
	RepNetworkUnreachable      = 0x03 // 网络不可达
	RepHostUnreachable         = 0x04 // 主机不可达
	RepConnectionRefused       = 0x05 // 连接被拒绝
	RepTTLExpired              = 0x06 // TTL 过期
	RepCommandNotSupported     = 0x07 // 命令不支持
	RepAddressTypeNotSupported = 0x08 // 地址类型不支持
)

// 协议层错误。
var (
	ErrUnsupportedVersion  = errors.New("socks5: 不支持的协议版本")
	ErrNoAcceptableMethods = errors.New("socks5: 没有可接受的认证方法")
	ErrAuthFailed          = errors.New("socks5: 身份认证失败")
	ErrCommandNotSupported = errors.New("socks5: 不支持的命令")
	ErrAddressNotSupported = errors.New("socks5: 不支持的地址类型")
	ErrMalformedRequest    = errors.New("socks5: 报文格式错误")
	ErrReservedNonZero     = errors.New("socks5: RSV 字段必须为 0")
	ErrFragmented          = errors.New("socks5: 不支持 UDP 分片")
)
