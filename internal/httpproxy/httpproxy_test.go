package httpproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/sixath/proxy/internal/acl"
)

// startProxy 启动 HTTP 代理并返回监听地址。
func startProxy(t *testing.T, cfg Config) string {
	t.Helper()

	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动代理失败: %v", err)
	}

	srv := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})

	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String()
}

// TestPlainHTTPForward 验证普通 HTTP 请求能被正确转发，
// 且代理会补充 X-Forwarded-For、去除逐跳首部。
func TestPlainHTTPForward(t *testing.T) {
	var gotXFF, gotProxyAuth string

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotProxyAuth = r.Header.Get("Proxy-Authorization")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello-backend"))
	}))
	defer backend.Close()

	proxyAddr := startProxy(t, Config{})
	proxyURL, _ := url.Parse("http://" + proxyAddr)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("通过代理请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-backend" {
		t.Fatalf("响应内容不符: %q", string(body))
	}
	if gotXFF == "" {
		t.Fatal("代理应当补充 X-Forwarded-For")
	}
	if gotProxyAuth != "" {
		t.Fatalf("Proxy-Authorization 不应被转发到后端: %q", gotProxyAuth)
	}
}

// TestConnectTunnel 验证 CONNECT 隧道能承载任意 TCP 流量。
func TestConnectTunnel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动后端失败: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// 模拟数据库握手报文 + 回显。
		_, _ = conn.Write([]byte("MONGO>"))
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	proxyAddr := startProxy(t, Config{})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\n\r\n", ln.Addr().String()); err != nil {
		t.Fatalf("发送 CONNECT 失败: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读取 CONNECT 响应失败: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", resp.StatusCode)
	}

	// 隧道建立后，应能收到后端握手报文并实现双向透传。
	handshake := make([]byte, len("MONGO>"))
	if _, err := io.ReadFull(br, handshake); err != nil {
		t.Fatalf("读取隧道数据失败: %v", err)
	}
	if string(handshake) != "MONGO>" {
		t.Fatalf("隧道数据不符: %q", string(handshake))
	}

	if _, err := conn.Write([]byte("db-query")); err != nil {
		t.Fatalf("写入隧道失败: %v", err)
	}
	echo := make([]byte, len("db-query"))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if string(echo) != "db-query" {
		t.Fatalf("回显不符: %q", string(echo))
	}
}

// TestProxyAuthRequired 验证强制认证时返回 407。
func TestProxyAuthRequired(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	proxyAddr := startProxy(t, Config{
		Auth: NewAuth(map[string]string{"u1": "p1"}, true),
	})
	proxyURL, _ := url.Parse("http://" + proxyAddr)

	// 未提供凭据
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("期望 407，实际 %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 提供正确凭据
	cred := base64.StdEncoding.EncodeToString([]byte("u1:p1"))
	req, _ := http.NewRequest(http.MethodGet, backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Basic "+cred)

	resp2, err := client.Do(req)
	if err != nil {
		t.Fatalf("带凭据请求失败: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("带正确凭据应当放行，实际 %d", resp2.StatusCode)
	}
}

// TestACLForbid 验证 ACL 拒绝时返回 403。
func TestACLForbid(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	aclSet, err := acl.New("allow", []acl.Rule{
		{Action: "deny", CIDRs: []string{"127.0.0.0/8"}},
	})
	if err != nil {
		t.Fatalf("编译 ACL 失败: %v", err)
	}

	proxyAddr := startProxy(t, Config{ACL: aclSet})
	proxyURL, _ := url.Parse("http://" + proxyAddr)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("期望 403，实际 %d", resp.StatusCode)
	}
}

// TestKeepAliveReuse 验证同一条客户端连接可复用处理多个请求。
func TestKeepAliveReuse(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("n"))
	}))
	defer backend.Close()

	proxyAddr := startProxy(t, Config{})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	br := bufio.NewReader(conn)
	for i := 0; i < 3; i++ {
		if _, err := fmt.Fprintf(conn, "GET %s/ HTTP/1.1\r\nHost: %s\r\n\r\n", backend.URL, "backend"); err != nil {
			t.Fatalf("写入请求失败: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("第 %d 次读取响应失败: %v", i+1, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("第 %d 次响应状态码异常: %d", i+1, resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// TestHopByHopHeadersRemoved 验证 Connection 列举的首部不会被转发。
func TestHopByHopHeadersRemoved(t *testing.T) {
	var gotCustom string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCustom = r.Header.Get("X-Hop")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	proxyAddr := startProxy(t, Config{})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	raw := fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: X-Hop\r\nX-Hop: secret\r\n\r\n",
		backend.URL, "backend")
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if strings.TrimSpace(gotCustom) != "" {
		t.Fatalf("逐跳首部不应被转发，实际收到: %q", gotCustom)
	}
}
