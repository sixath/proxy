package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sixath/proxy/internal/acl"
	"github.com/sixath/proxy/internal/relay"
)

// Dialer 抽象到目标服务器的拨号行为，便于后续接入上游代理链。
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Config 是 SOCKS5 服务器的配置项。
type Config struct {
	// Auth 为认证器，nil 表示只允许免认证。
	Auth Authenticator
	// ACL 为访问控制规则，nil 表示全部放行。
	ACL *acl.Set
	// Dialer 用于连接目标服务器，nil 时使用默认拨号器。
	Dialer Dialer
	// ConnectTimeout 为连接目标服务器的超时时间，0 表示不限制。
	ConnectTimeout time.Duration
	// IdleTimeout 为连接空闲超时，0 表示不限制。
	IdleTimeout time.Duration
	// GraceTimeout 为半关闭宽限时长，0 表示不启用。
	GraceTimeout time.Duration
	// EnableUDP 为 true 时支持 UDP ASSOCIATE 命令。
	EnableUDP bool
	// EnableBind 为 true 时支持 BIND 命令。
	EnableBind bool
	// UDPBufferSize 为 UDP 报文缓冲区大小，0 使用默认值 64KB。
	UDPBufferSize int
	// UDPIdleTimeout 为 UDP 中继空闲超时，0 表示复用 IdleTimeout。
	UDPIdleTimeout time.Duration
	// Logger 为日志记录器，nil 时使用 slog.Default()。
	Logger *slog.Logger
}

// Server 是 SOCKS5 代理服务器。
type Server struct {
	cfg    Config
	logger *slog.Logger
	dialer Dialer
}

// New 构造 SOCKS5 服务器。
func New(cfg Config) *Server {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	d := cfg.Dialer
	if d == nil {
		timeout := cfg.ConnectTimeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		d = &net.Dialer{Timeout: timeout}
	}

	s := &Server{cfg: cfg, logger: logger, dialer: d}
	if s.cfg.UDPBufferSize <= 0 {
		s.cfg.UDPBufferSize = 64 * 1024
	}
	if s.cfg.UDPIdleTimeout <= 0 {
		s.cfg.UDPIdleTimeout = cfg.IdleTimeout
	}
	if s.cfg.Auth == nil {
		s.cfg.Auth = NewAuth(nil, false)
	}
	return s
}

// Serve 阻塞地在 listener 上接受连接并处理，直到 ctx 被取消或 listener 关闭。
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	s.logger.Info("socks5 服务已启动", "listen", listener.Addr().String())

	// 监听退出信号，关闭 listener 以打断 Accept。
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var tempDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// 参考 net/http 的指数退避，避免 Accept 持续失败时打满 CPU。
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := time.Second; tempDelay > max {
					tempDelay = max
				}
				s.logger.Warn("socks5 接受连接失败，准备重试", "err", err, "retry", tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0

		go func() {
			defer func() {
				if r := recover(); r != nil {
					s.logger.Error("socks5 连接处理发生 panic", "panic", r)
				}
			}()
			if err := s.Handle(conn); err != nil {
				s.logger.Debug("socks5 连接结束", "client", conn.RemoteAddr().String(), "err", err)
			}
		}()
	}
}

// Handle 处理单条客户端连接，完成协商、命令执行与数据转发。
func (s *Server) Handle(conn net.Conn) error {
	defer conn.Close()

	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	if err := s.negotiate(conn); err != nil {
		return err
	}
	return s.handleRequest(conn)
}

// negotiate 完成认证方法协商与子协商。
func (s *Server) negotiate(conn net.Conn) error {
	idle := s.cfg.IdleTimeout
	if idle > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
	}

	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != Version5 {
		return ErrUnsupportedVersion
	}

	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	method := s.cfg.Auth.Method(methods)
	if _, err := conn.Write([]byte{Version5, method}); err != nil {
		return err
	}
	if method == MethodNoAcceptable {
		return ErrNoAcceptableMethods
	}

	return s.cfg.Auth.Authenticate(conn, method)
}

// handleRequest 读取请求报文并分发到具体命令处理。
func (s *Server) handleRequest(conn net.Conn) error {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	header := make([]byte, 3)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != Version5 {
		return ErrUnsupportedVersion
	}
	if header[2] != 0x00 {
		writeReply(conn, RepGeneralFailure, nil)
		return ErrReservedNonZero
	}

	addr, port, err := readAddrSpec(conn)
	if err != nil {
		writeReply(conn, RepAddressTypeNotSupported, nil)
		return err
	}

	target := net.JoinHostPort(addr, strconv.Itoa(port))

	switch header[1] {
	case CmdConnect:
		return s.handleConnect(conn, addr, port, target)
	case CmdBind:
		return s.handleBind(conn, addr, port, target)
	case CmdUDPAssociate:
		return s.handleUDPAssociate(conn, addr, port, target)
	default:
		writeReply(conn, RepCommandNotSupported, nil)
		return ErrCommandNotSupported
	}
}

// handleConnect 处理 CONNECT 命令：连接目标并做全双工透传。
// MySQL、MongoDB、PostgreSQL、Redis 等基于 TCP 的协议都走这条路径。
func (s *Server) handleConnect(conn net.Conn, addr string, port int, target string) error {
	if !s.checkACL(conn, addr, port) {
		return ErrGeneralDenied
	}

	ctx := context.Background()
	if s.cfg.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.ConnectTimeout)
		defer cancel()
	}

	upstream, err := s.dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		s.logger.Debug("socks5 连接目标失败", "target", target, "err", err)
		writeReply(conn, replyCodeFromError(err), nil)
		return err
	}
	defer upstream.Close()

	if tcp, ok := upstream.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	// 协商完成后清除握手阶段设置的读超时，转发阶段由 relay 自行管理。
	if s.cfg.IdleTimeout > 0 || s.cfg.ConnectTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}

	if err := writeReply(conn, RepSuccess, upstream.LocalAddr()); err != nil {
		return err
	}

	stats, err := relay.Bidirectional(conn, upstream, s.cfg.IdleTimeout, s.cfg.GraceTimeout)
	s.logger.Debug("socks5 CONNECT 结束",
		"client", conn.RemoteAddr().String(),
		"target", target,
		"up", stats.Upstream,
		"down", stats.Downstream,
		"duration", stats.Duration.String(),
		"err", err,
	)
	return err
}

// handleBind 处理 BIND 命令（FTP 主动模式等场景）。
// 流程：先监听端口并回复一次，等待首个入站连接后再回复第二次，随后透传。
func (s *Server) handleBind(conn net.Conn, addr string, port int, target string) error {
	if !s.cfg.EnableBind {
		writeReply(conn, RepCommandNotSupported, nil)
		return ErrCommandNotSupported
	}
	if !s.checkACL(conn, addr, port) {
		return ErrGeneralDenied
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		writeReply(conn, RepGeneralFailure, nil)
		return err
	}
	defer ln.Close()

	// 第一次回复：告知客户端监听地址。
	if err := writeReply(conn, RepSuccess, ln.Addr()); err != nil {
		return err
	}

	acceptCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptCh <- c
	}()

	select {
	case incoming := <-acceptCh:
		defer incoming.Close()
		// 第二次回复：告知客户端入站连接的对端地址。
		if err := writeReply(conn, RepSuccess, incoming.RemoteAddr()); err != nil {
			return err
		}
		stats, err := relay.Bidirectional(conn, incoming, s.cfg.IdleTimeout, s.cfg.GraceTimeout)
		s.logger.Debug("socks5 BIND 结束", "target", target,
			"up", stats.Upstream, "down", stats.Downstream, "err", err)
		return err

	case err := <-errCh:
		writeReply(conn, RepGeneralFailure, nil)
		return err

	case <-time.After(bindAcceptTimeout()):
		writeReply(conn, RepTTLExpired, nil)
		return errors.New("socks5: 等待 BIND 入站连接超时")
	}
}

// bindAcceptTimeout 返回 BIND 等待入站连接的超时时间。
func bindAcceptTimeout() time.Duration { return 60 * time.Second }

// handleUDPAssociate 处理 UDP ASSOCIATE 命令：分配 UDP 端口做数据报中继。
func (s *Server) handleUDPAssociate(conn net.Conn, addr string, port int, target string) error {
	if !s.cfg.EnableUDP {
		writeReply(conn, RepCommandNotSupported, nil)
		return ErrCommandNotSupported
	}
	if !s.checkACL(conn, addr, port) {
		return ErrGeneralDenied
	}

	// 在与客户端同一张网卡上监听 UDP，保证客户端可达。
	udpAddr := &net.UDPAddr{IP: localIPOf(conn), Port: 0}
	pc, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		writeReply(conn, RepGeneralFailure, nil)
		return err
	}
	defer pc.Close()

	// 回复 UDP 中继地址。客户端需保持 TCP 控制连接不关闭。
	if err := writeReply(conn, RepSuccess, pc.LocalAddr()); err != nil {
		return err
	}

	if s.cfg.IdleTimeout > 0 || s.cfg.ConnectTimeout > 0 {
		_ = conn.SetDeadline(time.Time{})
	}

	s.logger.Debug("socks5 UDP 中继已建立", "client", conn.RemoteAddr().String(), "relay", pc.LocalAddr().String())
	return s.serveUDP(conn, pc)
}

// checkACL 校验目标是否被放行，被拒绝时回复 RepConnectionNotAllowed。
func (s *Server) checkACL(conn net.Conn, addr string, port int) bool {
	if s.cfg.ACL == nil {
		return true
	}
	if s.cfg.ACL.Allow(addr, port) {
		return true
	}
	s.logger.Debug("socks5 目标被 ACL 拒绝",
		"client", conn.RemoteAddr().String(), "addr", addr, "port", port)
	writeReply(conn, RepConnectionNotAllowed, nil)
	return false
}

// ErrGeneralDenied 表示目标被访问控制拒绝。
var ErrGeneralDenied = errors.New("socks5: 目标被访问控制拒绝")

// replyCodeFromError 将拨号错误映射为 SOCKS5 响应码。
func replyCodeFromError(err error) byte {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return RepTTLExpired
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return RepTTLExpired
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			return RepHostUnreachable
		}
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) {
			return RepAddressTypeNotSupported
		}
		if opErr.Op == "dial" {
			return RepConnectionRefused
		}
	}
	return RepGeneralFailure
}

// splitHostPort 拆分地址，兼容 IPv6 与监听地址（:1080）形式。
func splitHostPort(addr net.Addr) (string, int, error) {
	s := addr.String()
	if i := strings.LastIndex(s, ":"); i >= 0 {
		host := s[:i]
		port, err := strconv.Atoi(s[i+1:])
		if err == nil {
			if host == "" || host == "::" {
				host = "0.0.0.0"
			}
			return host, port, nil
		}
	}
	return "", 0, fmt.Errorf("无法解析地址 %q", s)
}

// localIPOf 取控制连接本地侧 IP，用于生成 UDP 中继的监听地址。
func localIPOf(conn net.Conn) net.IP {
	if conn == nil || conn.LocalAddr() == nil {
		return net.IPv4zero
	}
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return net.IPv4zero
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return net.IPv4zero
	}
	if ip.IsUnspecified() {
		// 监听在通配地址时，选择一个对外可路由的地址返回给客户端。
		if outbound, err := net.ResolveUDPAddr("udp", "8.8.8.8:80"); err == nil {
			if c, err2 := net.DialUDP("udp", nil, outbound); err2 == nil {
				defer c.Close()
				if la := c.LocalAddr().(*net.UDPAddr); la != nil && la.IP != nil {
					return la.IP
				}
			}
		}
	}
	return ip
}
