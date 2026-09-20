package httpproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sixath/proxy/internal/relay"
)

// hopByHopHeaders 是逐跳首部，代理不得将其转发到下一跳。
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Handle 处理单条客户端连接，支持同一连接上的多个 HTTP 请求（keep-alive）。
func (s *Server) Handle(conn net.Conn) error {
	defer conn.Close()

	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	br := bufio.NewReader(conn)

	for {
		if s.cfg.IdleTimeout > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		}

		req, err := http.ReadRequest(br)
		if err != nil {
			// 客户端正常关闭连接时无需报错。
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		// CONNECT 建立隧道后会独占该连接，处理完即返回。
		if req.Method == http.MethodConnect {
			return s.handleConnect(conn, req)
		}

		closeConn, err := s.handlePlain(conn, req)
		if err != nil || closeConn {
			if err != nil {
				s.logger.Debug("http 请求处理失败", "err", err)
			}
			return err
		}
	}
}

// handleConnect 处理 CONNECT 方法：与目标建立 TCP 连接后原样透传。
// 该隧道不解析上层协议，因此可承载 TLS，也可承载 MySQL/MongoDB 等任意 TCP 流量。
func (s *Server) handleConnect(conn net.Conn, req *http.Request) error {
	host, portStr, err := splitAuthority(req.URL.Host)
	if err != nil {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request")
		return err
	}
	port, _ := strconv.Atoi(portStr)

	// 先认证再鉴权，保证客户端能拿到明确的 407 而不是被当成越权访问。
	if code, _ := s.cfg.Auth.Authenticate(req); code != 0 {
		s.writeAuthRequired(conn)
		return errors.New("http: 代理认证失败")
	}

	if !s.allow(host, port) {
		writeHTTPError(conn, http.StatusForbidden, "Forbidden")
		return errors.New("http: 目标被访问控制拒绝")
	}

	ctx := context.Background()
	if s.cfg.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.ConnectTimeout)
		defer cancel()
	}

	upstream, err := s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, portStr))
	if err != nil {
		s.logger.Debug("http CONNECT 连接目标失败", "target", req.URL.Host, "err", err)
		writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway")
		return err
	}
	defer upstream.Close()

	if tcp, ok := upstream.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	// 隧道建立后清除握手期超时，交由 relay 管理空闲。
	_ = conn.SetDeadline(time.Time{})

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		return err
	}

	stats, err := relay.Bidirectional(conn, upstream, s.cfg.IdleTimeout, s.cfg.GraceTimeout)
	s.logger.Debug("http CONNECT 结束",
		"client", conn.RemoteAddr().String(),
		"target", req.URL.Host,
		"up", stats.Upstream,
		"down", stats.Downstream,
		"duration", stats.Duration.String(),
		"err", err,
	)
	return err
}

// handlePlain 处理普通 HTTP 请求（请求行使用绝对 URI）。
// 返回 true 表示应当关闭连接。
func (s *Server) handlePlain(conn net.Conn, req *http.Request) (bool, error) {
	if req.URL.Host == "" {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request")
		return true, errors.New("http: 请求缺少绝对 URI")
	}

	if code, _ := s.cfg.Auth.Authenticate(req); code != 0 {
		s.writeAuthRequired(conn)
		return true, errors.New("http: 代理认证失败")
	}

	host, portStr, err := splitAuthority(req.URL.Host)
	if err != nil {
		writeHTTPError(conn, http.StatusBadRequest, "Bad Request")
		return true, err
	}
	port, _ := strconv.Atoi(portStr)

	if !s.allow(host, port) {
		writeHTTPError(conn, http.StatusForbidden, "Forbidden")
		return true, errors.New("http: 目标被访问控制拒绝")
	}

	// 清理逐跳首部与代理专有首部。
	removeHopByHopHeaders(req.Header)
	req.Header.Del("Proxy-Connection")

	if clientIP := clientIPOf(conn); clientIP != "" {
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			req.Header.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			req.Header.Set("X-Forwarded-For", clientIP)
		}
	}

	// 未经 CONNECT 的代理请求必须是绝对 URI 形式。
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	req.RequestURI = ""

	ctx := context.Background()
	if s.cfg.ForwardTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.ForwardTimeout)
		defer cancel()
	}

	resp, err := s.transport.RoundTrip(req.WithContext(ctx))
	if err != nil {
		s.logger.Debug("http 转发失败", "target", req.URL.String(), "err", err)
		writeHTTPError(conn, http.StatusBadGateway, "Bad Gateway")
		return true, err
	}
	defer resp.Body.Close()

	removeHopByHopHeaders(resp.Header)
	resp.Header.Set("Via", "1.1 proxy")

	// 隧道建立后不再受握手期超时约束。
	_ = conn.SetDeadline(time.Time{})

	if err := resp.Write(conn); err != nil {
		return true, err
	}

	shouldClose := resp.Close || req.Close
	return shouldClose, nil
}

// allow 执行访问控制判断。
func (s *Server) allow(host string, port int) bool {
	if s.cfg.ACL == nil {
		return true
	}
	return s.cfg.ACL.Allow(host, port)
}

// writeAuthRequired 返回 407 要求代理认证。
func (s *Server) writeAuthRequired(conn net.Conn) {
	resp := &http.Response{
		Status:     "407 Proxy Authentication Required",
		StatusCode: http.StatusProxyAuthRequired,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{},
	}
	resp.Header.Set("Proxy-Authenticate", s.cfg.Auth.challenge())
	resp.Header.Set("Content-Length", "0")
	resp.Header.Set("Connection", "close")
	_ = resp.Write(conn)
}

// writeHTTPError 向客户端写入简单的错误响应。
func writeHTTPError(conn net.Conn, status int, text string) {
	resp := &http.Response{
		Status:     strconv.Itoa(status) + " " + text,
		StatusCode: status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	resp.Header.Set("Content-Length", "0")
	resp.Header.Set("Connection", "close")
	_ = resp.Write(conn)
}

// removeHopByHopHeaders 删除逐跳首部，包括 Connection 列举的那些。
func removeHopByHopHeaders(h http.Header) {
	// 必须先取出 Connection 列举的首部名，
	// 因为随后 Connection 自身就会被删除。
	var extra []string
	if v := h.Get("Connection"); v != "" {
		for _, part := range strings.Split(v, ",") {
			if name := strings.TrimSpace(part); name != "" {
				extra = append(extra, name)
			}
		}
	}

	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
	for _, name := range extra {
		h.Del(name)
	}
}

// splitAuthority 拆分 host:port，缺省端口按协议补全。
func splitAuthority(authority string) (host string, port string, err error) {
	authority = strings.TrimSpace(authority)
	if authority == "" {
		return "", "", errors.New("http: 目标地址为空")
	}

	host, port, err = net.SplitHostPort(authority)
	if err != nil {
		// 没有显式端口时按 HTTP 默认端口处理。
		if strings.Contains(err.Error(), "missing port") {
			return authority, "80", nil
		}
		return "", "", err
	}
	if port == "" {
		port = "80"
	}
	return host, port, nil
}

// clientIPOf 提取客户端 IP（不含端口）。
func clientIPOf(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return ""
	}
	return host
}
