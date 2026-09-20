package socks5

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"log/slog"

	"github.com/sixath/proxy/internal/acl"
)

// startTCPServer 启动一个"回显 + 前缀响应"的 TCP 服务，
// 用于模拟 MySQL / MongoDB 等任意基于 TCP 的后端服务。
func startTCPServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动测试服务失败: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// 先发送一段"服务欢迎语"，模拟数据库握手报文。
				_, _ = c.Write([]byte("HELLO"))
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if _, err := c.Write([]byte("ECHO:" + line)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String()
}

// startProxy 启动一个 SOCKS5 代理并返回其监听地址。
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

// handshake 完成 SOCKS5 方法协商，返回连接与被选中的方法。
func handshake(t *testing.T, proxy string, methods []byte) (net.Conn, byte) {
	t.Helper()

	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	greet := append([]byte{Version5, byte(len(methods))}, methods...)
	if _, err := conn.Write(greet); err != nil {
		t.Fatalf("发送协商请求失败: %v", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("读取协商响应失败: %v", err)
	}
	if reply[0] != Version5 {
		t.Fatalf("响应版本错误: %#x", reply[0])
	}
	return conn, reply[1]
}

// connectRequest 发送 CONNECT 请求并返回响应码。
func connectRequest(t *testing.T, conn net.Conn, target string) byte {
	t.Helper()

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("拆分目标地址失败: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("测试仅支持 IPv4 目标: %s", target)
	}

	req := []byte{Version5, CmdConnect, 0x00, AtypIPv4}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("发送 CONNECT 请求失败: %v", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("读取 CONNECT 响应失败: %v", err)
	}
	// IPv4 类型响应固定为 10 字节。
	rest := make([]byte, 6)
	if _, err := io.ReadFull(conn, rest); err != nil {
		t.Fatalf("读取 CONNECT 响应地址失败: %v", err)
	}
	return head[1]
}

// TestConnectTransparentTCP 验证 CONNECT 隧道对应用层协议完全透明：
// 客户端可从隧道中读到后端"握手报文"，且双向数据原样透传。
// 这正是代理 MySQL / MongoDB 等数据库协议所依赖的能力。
func TestConnectTransparentTCP(t *testing.T) {
	backend := startTCPServer(t)
	proxy := startProxy(t, Config{})

	conn, method := handshake(t, proxy, []byte{MethodNoAuth})
	if method != MethodNoAuth {
		t.Fatalf("期望选择免认证方法，实际为 %#x", method)
	}

	if rep := connectRequest(t, conn, backend); rep != RepSuccess {
		t.Fatalf("CONNECT 失败，响应码 %#x", rep)
	}

	// 读取后端主动下发的握手报文。
	buf := make([]byte, len("HELLO"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("读取握手报文失败: %v", err)
	}
	if string(buf) != "HELLO" {
		t.Fatalf("握手报文内容不符: %q", string(buf))
	}

	// 发送一段模拟数据库查询报文并校验回显。
	msg := "SELECT 1\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if want := "ECHO:" + msg; got != want {
		t.Fatalf("回显不符，期望 %q 实际 %q", want, got)
	}
}

// TestConnectUserPassAuth 验证 RFC 1929 用户名/密码认证。
func TestConnectUserPassAuth(t *testing.T) {
	backend := startTCPServer(t)
	users := map[string]string{"dbuser": "dbpass"}
	proxy := startProxy(t, Config{Auth: NewAuth(users, true)})

	conn, method := handshake(t, proxy, []byte{MethodNoAuth, MethodUserPass})
	if method != MethodUserPass {
		t.Fatalf("期望选择用户名密码认证，实际为 %#x", method)
	}

	// 先用错误密码，应当被拒绝。
	writeUserPass(t, conn, "dbuser", "wrong")
	status := make([]byte, 2)
	if _, err := io.ReadFull(conn, status); err != nil {
		t.Fatalf("读取认证结果失败: %v", err)
	}
	if status[1] != 0x01 {
		t.Fatalf("错误密码应当认证失败，实际状态 %#x", status[1])
	}

	// 重新协商并使用正确密码。
	conn2, method2 := handshake(t, proxy, []byte{MethodUserPass})
	if method2 != MethodUserPass {
		t.Fatalf("期望用户名密码认证，实际 %#x", method2)
	}
	writeUserPass(t, conn2, "dbuser", "dbpass")
	if _, err := io.ReadFull(conn2, status); err != nil {
		t.Fatalf("读取认证结果失败: %v", err)
	}
	if status[1] != 0x00 {
		t.Fatalf("正确密码应当通过认证，实际状态 %#x", status[1])
	}

	if rep := connectRequest(t, conn2, backend); rep != RepSuccess {
		t.Fatalf("认证通过后 CONNECT 应当成功，实际响应码 %#x", rep)
	}
}

func writeUserPass(t *testing.T, conn net.Conn, user, pass string) {
	t.Helper()
	buf := []byte{0x01, byte(len(user))}
	buf = append(buf, []byte(user)...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, []byte(pass)...)
	if _, err := conn.Write(buf); err != nil {
		t.Fatalf("发送认证报文失败: %v", err)
	}
}

// TestConnectNoAcceptableMethod 验证未配置认证时不会接受用户名/密码方式以外的方法。
func TestConnectNoAcceptableMethod(t *testing.T) {
	proxy := startProxy(t, Config{Auth: NewAuth(map[string]string{"u": "p"}, true)})

	// 客户端仅支持免认证，而服务端强制要求认证，应返回 NoAcceptable。
	_, method := handshake(t, proxy, []byte{MethodNoAuth})
	if method != MethodNoAcceptable {
		t.Fatalf("期望返回无可用方法，实际 %#x", method)
	}
}

// TestConnectDeniedByACL 验证 ACL 能拦截目标地址。
func TestConnectDeniedByACL(t *testing.T) {
	backend := startTCPServer(t)

	aclSet, err := acl.New("allow", []acl.Rule{
		{Action: "deny", CIDRs: []string{"127.0.0.0/8"}},
	})
	if err != nil {
		t.Fatalf("编译 ACL 失败: %v", err)
	}

	proxy := startProxy(t, Config{ACL: aclSet})

	conn, _ := handshake(t, proxy, []byte{MethodNoAuth})
	if rep := connectRequest(t, conn, backend); rep != RepConnectionNotAllowed {
		t.Fatalf("期望被 ACL 拒绝（%#x），实际响应码 %#x", RepConnectionNotAllowed, rep)
	}
}

// TestUnsupportedVersion 验证非 SOCKS5 版本会被拒绝。
func TestUnsupportedVersion(t *testing.T) {
	proxy := startProxy(t, Config{})

	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatalf("连接代理失败: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x04, 0x01, 0x00}); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	// 服务端应当直接断开连接。
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err == nil {
		t.Fatalf("SOCKS4 版本请求不应被接受")
	}
}
