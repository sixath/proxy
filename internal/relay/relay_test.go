package relay

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// connPair 建立一对独立的 TCP 连接端点（a、b 互为对端）。
// 用于模拟"代理客户端"与"目标服务"两条互不相同的连接。
func connPair(t *testing.T) (a, b net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动监听失败: %v", err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()

	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	t.Cleanup(func() { _ = dialed.Close() })

	peer := <-accepted
	if peer == nil {
		_ = dialed.Close()
		t.Fatal("接受连接失败")
	}
	t.Cleanup(func() { _ = peer.Close() })

	return dialed, peer
}

// TestBidirectionalEcho 验证双向转发能正确搬运数据，
// 并在半关闭后及时返回（覆盖半关闭与宽限期逻辑，防止死锁回归）。
//
// 连接拓扑：
//
//	userEnd ──(连接1)── client ── relay ── target ──(连接2)── serverEnd
func TestBidirectionalEcho(t *testing.T) {
	userEnd, client := connPair(t)
	target, serverEnd := connPair(t)

	const req, resp = "hello\n", "echo:hello\n"

	// 模拟后端服务：读取请求后回显，并主动半关闭写端。
	go func() {
		br := bufio.NewReader(serverEnd)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if _, err := fmt.Fprint(serverEnd, "echo:"+line); err != nil {
			return
		}
		_ = serverEnd.(*net.TCPConn).CloseWrite()
		_, _ = io.Copy(io.Discard, serverEnd)
	}()

	type result struct {
		stats Stats
		err   error
	}
	resultCh := make(chan result, 1)

	start := time.Now()
	go func() {
		s, err := Bidirectional(client, target, 0, 2*time.Second)
		resultCh <- result{s, err}
	}()

	if _, err := fmt.Fprint(userEnd, req); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	_ = userEnd.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, len(resp))
	if _, err := io.ReadFull(userEnd, buf); err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if string(buf) != resp {
		t.Fatalf("回显不符: %q", string(buf))
	}

	// 客户端半关闭，触发转发收尾。
	_ = userEnd.(*net.TCPConn).CloseWrite()

	select {
	case res := <-resultCh:
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("转发收尾过慢，可能发生了死锁: %v", elapsed)
		}
		if res.stats.Upstream != int64(len(req)) {
			t.Fatalf("上行字节数不符: up=%d down=%d err=%v",
				res.stats.Upstream, res.stats.Downstream, res.err)
		}
		if res.stats.Downstream != int64(len(resp)) {
			t.Fatalf("下行字节数不符: up=%d down=%d err=%v",
				res.stats.Upstream, res.stats.Downstream, res.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Bidirectional 未能在超时前返回")
	}
}

// TestBidirectionalGraceTimeout 验证一侧结束后，另一侧不会无限期悬挂：
// 宽限期到点后转发必须返回。
func TestBidirectionalGraceTimeout(t *testing.T) {
	userEnd, client := connPair(t)
	target, serverEnd := connPair(t)
	defer serverEnd.Close()

	// 后端服务只接收数据、从不关闭也不回写。
	resultCh := make(chan struct{}, 1)
	go func() {
		Bidirectional(client, target, 0, time.Second)
		resultCh <- struct{}{}
	}()

	if _, err := fmt.Fprint(userEnd, "data"); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	// 客户端半关闭：上行方向结束，下行方向无数据可收。
	_ = userEnd.(*net.TCPConn).CloseWrite()

	start := time.Now()
	select {
	case <-resultCh:
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("宽限期未生效，耗时 %v", elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Bidirectional 在宽限期后仍未返回")
	}
}
