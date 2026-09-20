// Package relay 提供连接双向转发能力，是 SOCKS5 CONNECT 与 HTTP CONNECT
// 隧道的公共底层实现。由于工作在传输层，它对 MongoDB、MySQL、Redis 等
// 任意基于 TCP 的应用层协议都是透明的。
package relay

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// idleConn 在每次读操作前刷新读超时，从而实现"空闲超时"而不是"总时长超时"。
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	if c.idle > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.idle))
	}
	return c.Conn.Read(p)
}

// closeWrite 尽量向对端发送 FIN（半关闭），让对端能够正常结束写入。
// 不支持 CloseWrite 的连接会被忽略。
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// Stats 描述一次双向转发的统计信息。
type Stats struct {
	// Upstream 为客户端发往目标服务器的字节数。
	Upstream int64
	// Downstream 为目标服务器发往客户端的字节数。
	Downstream int64
	// Duration 为转发持续时长。
	Duration time.Duration
}

// Bidirectional 在 client 与 target 之间做全双工数据转发，直到任一侧结束。
//
// 参数说明：
//   - idle: 空闲超时，0 表示不限制。任意一侧在 idle 时间内没有新数据即断开。
//   - grace: 半关闭宽限期。一侧先结束后，另一侧最多再保留 grace 时间，
//     超时则强制关闭，避免出现永久悬挂的连接。0 表示一直等到自然结束。
//
// 返回值为上行/下行字节数与首个非 nil 的错误（超时或被关闭时通常返回错误，
// 调用方一般只需记录日志）。
func Bidirectional(client, target net.Conn, idle, grace time.Duration) (Stats, error) {
	c := &idleConn{Conn: client, idle: idle}
	t := &idleConn{Conn: target, idle: idle}

	start := time.Now()

	var (
		wg       sync.WaitGroup
		once     sync.Once
		up       atomic.Int64
		down     atomic.Int64
		errCh    = make(chan error, 2)
		finishCh = make(chan struct{})
	)

	// finish 在任一侧拷贝结束时被调用，并给两端设置宽限期截止时间，
	// 使另一侧不会无限期等待。
	finish := func() {
		once.Do(func() {
			close(finishCh)
			if grace > 0 {
				deadline := time.Now().Add(grace)
				_ = client.SetDeadline(deadline)
				_ = target.SetDeadline(deadline)
			}
		})
	}

	wg.Add(2)

	// 客户端 -> 目标（上行）
	go func() {
		defer wg.Done()
		n, err := io.Copy(t, c)
		up.Store(n)
		if err != nil {
			errCh <- err
		}
		// 客户端不再发送数据，通知目标可以关闭写入。
		closeWrite(target)
		finish()
	}()

	// 目标 -> 客户端（下行）
	go func() {
		defer wg.Done()
		n, err := io.Copy(c, t)
		down.Store(n)
		if err != nil {
			errCh <- err
		}
		closeWrite(client)
		finish()
	}()

	// allDone 在两个方向都结束后关闭。
	allDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(allDone)
	}()

	// 等待任意一侧结束。
	<-finishCh

	if grace > 0 {
		select {
		case <-allDone:
		case <-time.After(grace):
		}
	} else {
		<-allDone
	}

	// 关闭两端可确保尚未退出的拷贝立即返回错误，避免 goroutine 泄漏。
	_ = client.Close()
	_ = target.Close()
	<-allDone

	var firstErr error
	select {
	case firstErr = <-errCh:
	default:
	}

	return Stats{
		Upstream:   up.Load(),
		Downstream: down.Load(),
		Duration:   time.Since(start),
	}, firstErr
}
