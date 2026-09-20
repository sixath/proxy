package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Client 是 SOCKS5 客户端拨号器。它把"经由 SOCKS5 代理建立连接"封装成
// 一个普通的 Dialer，从而可以无缝接入各种数据库驱动的自定义拨号接口，
// 例如：
//   - mongo-go-driver: options.Client().SetDialer(...)
//   - go-sql-driver/mysql: mysql.RegisterDialer("tcp", ...)
type Client struct {
	proxyAddr string
	user      string
	pass      string
	timeout   time.Duration

	// Dialer 用于连接 SOCKS5 代理服务器本身，便于测试或级联代理。
	Dialer interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
}

// ClientOption 用于定制 Client。
type ClientOption func(*Client)

// WithClientAuth 设置 SOCKS5 代理的用户名与密码。
func WithClientAuth(user, pass string) ClientOption {
	return func(c *Client) { c.user, c.pass = user, pass }
}

// WithClientTimeout 设置连接与握手的超时时间。
func WithClientTimeout(d time.Duration) ClientOption {
	return func(c *Client) { c.timeout = d }
}

// NewClient 创建一个经由 proxyAddr 转发流量的 SOCKS5 客户端拨号器。
func NewClient(proxyAddr string, opts ...ClientOption) *Client {
	c := &Client{proxyAddr: proxyAddr, timeout: 10 * time.Second}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Dial 经由 SOCKS5 代理连接目标地址。
func (c *Client) Dial(network, addr string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, addr)
}

// DialContext 与 Dial 相同，但支持上下文取消与超时。
// 由于 SOCKS5 隧道是传输层的，addr 可以是 MongoDB、MySQL 等任意 TCP 服务地址。
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("socks5: 不支持的网络类型 %q", network)
	}

	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	proxyConn, err := c.dialProxy(ctx)
	if err != nil {
		return nil, err
	}

	if err := c.handshake(proxyConn); err != nil {
		_ = proxyConn.Close()
		return nil, err
	}

	target, err := encodeAddrSpecFromAuthority(addr)
	if err != nil {
		_ = proxyConn.Close()
		return nil, err
	}

	req := make([]byte, 0, 3+len(target))
	req = append(req, Version5, CmdConnect, 0x00)
	req = append(req, target...)
	if _, err := proxyConn.Write(req); err != nil {
		_ = proxyConn.Close()
		return nil, err
	}

	if err := readConnectReply(proxyConn); err != nil {
		_ = proxyConn.Close()
		return nil, err
	}
	return proxyConn, nil
}

func (c *Client) dialProxy(ctx context.Context) (net.Conn, error) {
	if c.Dialer != nil {
		return c.Dialer.DialContext(ctx, "tcp", c.proxyAddr)
	}
	d := &net.Dialer{}
	if deadline, ok := ctx.Deadline(); ok {
		d.Deadline = deadline
	}
	return d.DialContext(ctx, "tcp", c.proxyAddr)
}

// handshake 完成方法协商与（可选的）用户名密码认证。
func (c *Client) handshake(conn net.Conn) error {
	methods := []byte{MethodNoAuth}
	if c.user != "" {
		methods = []byte{MethodNoAuth, MethodUserPass}
	}

	greet := make([]byte, 0, 2+len(methods))
	greet = append(greet, Version5, byte(len(methods)))
	greet = append(greet, methods...)
	if _, err := conn.Write(greet); err != nil {
		return err
	}

	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return err
	}
	if sel[0] != Version5 {
		return ErrUnsupportedVersion
	}

	switch sel[1] {
	case MethodNoAuth:
		return nil

	case MethodUserPass:
		if c.user == "" {
			return ErrAuthFailed
		}
		buf := []byte{0x01, byte(len(c.user))}
		buf = append(buf, []byte(c.user)...)
		buf = append(buf, byte(len(c.pass)))
		buf = append(buf, []byte(c.pass)...)
		if _, err := conn.Write(buf); err != nil {
			return err
		}
		status := make([]byte, 2)
		if _, err := io.ReadFull(conn, status); err != nil {
			return err
		}
		if status[1] != 0x00 {
			return ErrAuthFailed
		}
		return nil

	default:
		return ErrNoAcceptableMethods
	}
}

// readConnectReply 读取 CONNECT 响应并校验响应码。
func readConnectReply(conn net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != Version5 {
		return ErrUnsupportedVersion
	}

	var restLen int
	switch head[3] {
	case AtypIPv4:
		restLen = net.IPv4len
	case AtypIPv6:
		restLen = net.IPv6len
	case AtypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		restLen = int(l[0])
	default:
		return ErrAddressNotSupported
	}

	rest := make([]byte, restLen+2)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return err
	}

	switch head[1] {
	case RepSuccess:
		return nil
	case RepConnectionNotAllowed:
		return fmt.Errorf("socks5: 目标被代理规则拒绝")
	case RepNetworkUnreachable:
		return fmt.Errorf("socks5: 网络不可达")
	case RepHostUnreachable:
		return fmt.Errorf("socks5: 主机不可达")
	case RepConnectionRefused:
		return fmt.Errorf("socks5: 目标拒绝连接")
	case RepCommandNotSupported:
		return ErrCommandNotSupported
	case RepAddressTypeNotSupported:
		return ErrAddressNotSupported
	default:
		return errors.New("socks5: 建立连接失败")
	}
}

// encodeAddrSpecFromAuthority 将 host:port 编码为 SOCKS5 地址字段。
func encodeAddrSpecFromAuthority(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("socks5: 无效目标地址 %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("socks5: 无效端口 %q", portStr)
	}
	return encodeAddrSpec(host, port)
}
