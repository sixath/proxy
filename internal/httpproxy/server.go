// Package httpproxy 实现 HTTP/HTTPS 正向代理。
//
// 除常规网页代理外，CONNECT 方法会在客户端与目标之间建立纯 TCP 隧道，
// 因此同样可用于代理任意 TCP 协议（如数据库、SSH 等）。
package httpproxy

import (
	"context"
	"net"
	"net/http"
	"time"

	"log/slog"

	"github.com/sixath/proxy/internal/acl"
	"github.com/sixath/proxy/internal/socks5"
)

// Config 是 HTTP 代理服务器的配置项。
type Config struct {
	// Auth 为认证器，nil 表示不校验。
	Auth *Auth
	// ACL 为访问控制规则，nil 表示全部放行。
	ACL *acl.Set
	// Dialer 用于连接目标服务器，nil 时使用默认拨号器。
	Dialer socks5.Dialer
	// ConnectTimeout 为连接目标服务器的超时时间，0 表示不限制。
	ConnectTimeout time.Duration
	// IdleTimeout 为连接空闲超时，0 表示不限制。
	IdleTimeout time.Duration
	// GraceTimeout 为半关闭宽限时长，0 表示不启用。
	GraceTimeout time.Duration
	// ForwardTimeout 为普通 HTTP 请求的整请求超时，0 表示不限制。
	ForwardTimeout time.Duration
	// Logger 为日志记录器，nil 时使用 slog.Default()。
	Logger *slog.Logger
}

// Server 是 HTTP 代理服务器。
type Server struct {
	cfg       Config
	logger    *slog.Logger
	dialer    socks5.Dialer
	transport *http.Transport
}

// New 构造 HTTP 代理服务器。
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

	if cfg.Auth == nil {
		cfg.Auth = NewAuth(nil, false)
	}

	s := &Server{cfg: cfg, logger: logger, dialer: d}
	s.transport = &http.Transport{
		// 代理自身必须直连目标，不能再走系统代理，否则会形成环路。
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dialer.DialContext(ctx, network, addr)
		},
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     false,
	}
	return s
}

// Serve 阻塞地在 listener 上接受连接并处理，直到 ctx 被取消或 listener 关闭。
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	s.logger.Info("http 代理服务已启动", "listen", listener.Addr().String())

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var tempDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.transport.CloseIdleConnections()
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := time.Second; tempDelay > max {
					tempDelay = max
				}
				s.logger.Warn("http 接受连接失败，准备重试", "err", err, "retry", tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0

		go func() {
			defer func() {
				if r := recover(); r != nil {
					s.logger.Error("http 连接处理发生 panic", "panic", r)
				}
			}()
			if err := s.Handle(conn); err != nil {
				s.logger.Debug("http 连接结束", "client", conn.RemoteAddr().String(), "err", err)
			}
		}()
	}
}

// Close 释放内部空闲连接。
func (s *Server) Close() {
	s.transport.CloseIdleConnections()
}
