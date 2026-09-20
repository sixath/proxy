package socks5

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// TestClientDialThroughProxy 验证客户端拨号器能经由 SOCKS5 代理访问后端，
// 这是把代理接入 MongoDB / MySQL 驱动的标准方式。
func TestClientDialThroughProxy(t *testing.T) {
	backend := startTCPServer(t)
	proxy := startProxy(t, Config{})

	client := NewClient(proxy, WithClientTimeout(5*time.Second))

	conn, err := client.Dial("tcp", backend)
	if err != nil {
		t.Fatalf("经由代理拨号失败: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, len("HELLO"))
	if _, err := readFull(conn, buf); err != nil {
		t.Fatalf("读取握手报文失败: %v", err)
	}
	if string(buf) != "HELLO" {
		t.Fatalf("握手报文不符: %q", string(buf))
	}

	if _, err := conn.Write([]byte("PING\n")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	br := bufio.NewReader(conn)
	got, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if got != "ECHO:PING\n" {
		t.Fatalf("回显不符: %q", got)
	}
}

// TestClientAuth 验证客户端使用用户名密码方式通过代理认证。
func TestClientAuth(t *testing.T) {
	backend := startTCPServer(t)
	proxy := startProxy(t, Config{Auth: NewAuth(map[string]string{"u": "p"}, true)})

	// 正确凭据应当成功。
	c := NewClient(proxy, WithClientAuth("u", "p"), WithClientTimeout(5*time.Second))
	conn, err := c.Dial("tcp", backend)
	if err != nil {
		t.Fatalf("正确凭据应当通过: %v", err)
	}
	conn.Close()

	// 错误凭据应当失败。
	bad := NewClient(proxy, WithClientAuth("u", "wrong"), WithClientTimeout(5*time.Second))
	if conn, err := bad.Dial("tcp", backend); err == nil {
		conn.Close()
		t.Fatal("错误凭据应当被拒绝")
	}
}

// TestClientUnsupportedNetwork 验证非 TCP 网络会被拒绝。
func TestClientUnsupportedNetwork(t *testing.T) {
	proxy := startProxy(t, Config{})
	c := NewClient(proxy)
	if _, err := c.Dial("udp", "127.0.0.1:53"); err == nil {
		t.Fatal("udp 不应被客户端拨号器支持")
	}
}

// readFull 是 io.ReadFull 的薄封装，便于测试断言。
func readFull(conn net.Conn, buf []byte) (int, error) {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
