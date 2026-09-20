package socks5

import (
	"net"
	"sync"
	"time"
)

// udpSession 维护一次 UDP ASSOCIATE 的中继状态。
type udpSession struct {
	server *Server
	ctrl   net.Conn     // TCP 控制连接，用于感知客户端存活
	pc     *net.UDPConn // 与客户端通信的 UDP socket
	// remotes 缓存 目标地址 -> 目标 socket，避免每个数据报重新建连。
	remotes map[string]*net.UDPConn
	mu      sync.Mutex
	// clientAddr 为客户端发来数据报的源地址；首次收到后锁定，
	// 非该地址的数据报将被丢弃，避免被第三方利用为开放中继。
	clientAddr *net.UDPAddr
}

// serveUDP 在 TCP 控制连接存活期间中继 UDP 数据报。
func (s *Server) serveUDP(ctrl net.Conn, pc *net.UDPConn) error {
	sess := &udpSession{
		server:  s,
		ctrl:    ctrl,
		pc:      pc,
		remotes: make(map[string]*net.UDPConn),
	}

	// 控制连接一旦关闭（客户端断开），立即结束中继。
	go func() {
		_, _ = readDiscard(ctrl)
		_ = pc.Close()
	}()

	return sess.loop()
}

// readDiscard 读取直到 EOF 或出错，用于监测控制连接关闭。
func readDiscard(r net.Conn) (int64, error) {
	buf := make([]byte, 512)
	var total int64
	for {
		n, err := r.Read(buf)
		total += int64(n)
		if err != nil {
			return total, err
		}
	}
}

func (s *udpSession) loop() error {
	buf := make([]byte, s.server.cfg.UDPBufferSize)
	idle := s.server.cfg.UDPIdleTimeout

	for {
		if idle > 0 {
			_ = s.pc.SetReadDeadline(time.Now().Add(idle))
		}

		n, src, err := s.pc.ReadFromUDP(buf)
		if err != nil {
			// 控制连接关闭导致的 socket 关闭属于正常退出。
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if s.ctrlClosed() {
					return nil
				}
				return err
			}
			return err
		}
		if n < 4 {
			continue
		}

		// 仅接受来自已认证客户端地址的数据报。
		if s.clientAddr == nil {
			s.clientAddr = src
		} else if !src.IP.Equal(s.clientAddr.IP) || src.Port != s.clientAddr.Port {
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		host, port, payload, err := parseUDPDatagram(data)
		if err != nil {
			s.server.logger.Debug("socks5 丢弃非法 UDP 数据报", "err", err)
			continue
		}

		if !s.server.checkACLQuiet(host, port) {
			s.server.logger.Debug("socks5 UDP 目标被 ACL 拒绝", "host", host, "port", port)
			continue
		}

		rc, err := s.remoteConn(host, port)
		if err != nil {
			s.server.logger.Debug("socks5 UDP 目标连接失败", "host", host, "port", port, "err", err)
			continue
		}
		if _, err := rc.Write(payload); err != nil {
			s.server.logger.Debug("socks5 UDP 发送失败", "host", host, "port", port, "err", err)
		}
	}
}

// remoteConn 获取（必要时创建）到目标 host:port 的 UDP socket，
// 并为该 socket 启动一个将响应回写给客户端的 goroutine。
func (s *udpSession) remoteConn(host string, port int) (*net.UDPConn, error) {
	key := net.JoinHostPort(host, itoa(port))

	s.mu.Lock()
	defer s.mu.Unlock()

	if rc, ok := s.remotes[key]; ok {
		return rc, nil
	}

	raddr, err := net.ResolveUDPAddr("udp", key)
	if err != nil {
		return nil, err
	}
	rc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	s.remotes[key] = rc

	go s.pumpRemote(rc, host, port, key)
	return rc, nil
}

// pumpRemote 读取目标响应，封装 SOCKS5 UDP 头部后回写给客户端。
func (s *udpSession) pumpRemote(rc *net.UDPConn, host string, port int, key string) {
	defer func() {
		s.mu.Lock()
		delete(s.remotes, key)
		s.mu.Unlock()
		_ = rc.Close()
	}()

	buf := make([]byte, s.server.cfg.UDPBufferSize)
	idle := s.server.cfg.UDPIdleTimeout

	for {
		if idle > 0 {
			_ = rc.SetReadDeadline(time.Now().Add(idle))
		}
		n, _, err := rc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if s.clientAddr == nil {
			continue
		}

		out, err := buildUDPDatagram(host, port, buf[:n])
		if err != nil {
			continue
		}
		if _, err := s.pc.WriteToUDP(out, s.clientAddr); err != nil {
			return
		}
	}
}

// ctrlClosed 判断控制连接是否已经关闭。
func (s *udpSession) ctrlClosed() bool {
	if s.ctrl == nil {
		return true
	}
	// 对已关闭的连接读取会立刻返回错误。
	if err := s.ctrl.SetReadDeadline(time.Now()); err != nil {
		return true
	}
	buf := make([]byte, 1)
	if _, err := s.ctrl.Read(buf); err != nil {
		return true
	}
	return false
}

// parseUDPDatagram 解析 SOCKS5 UDP 数据报头部：
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
func parseUDPDatagram(data []byte) (host string, port int, payload []byte, err error) {
	if len(data) < 4 {
		return "", 0, nil, ErrMalformedRequest
	}
	if data[0] != 0x00 || data[1] != 0x00 {
		return "", 0, nil, ErrMalformedRequest
	}
	if data[2] != 0x00 {
		// 本实现不支持分片。
		return "", 0, nil, ErrFragmented
	}

	addr, port, err := readAddrSpec(bytesReader(data[3:]))
	if err != nil {
		return "", 0, nil, err
	}

	// 计算头部长度以定位负载。
	headLen := 3 // RSV(2) + FRAG(1)
	headLen += 1 // ATYP
	switch data[3] {
	case AtypIPv4:
		headLen += net.IPv4len
	case AtypIPv6:
		headLen += net.IPv6len
	case AtypDomain:
		headLen += 1 + int(data[4])
	default:
		return "", 0, nil, ErrAddressNotSupported
	}
	headLen += 2 // PORT

	if len(data) < headLen {
		return "", 0, nil, ErrMalformedRequest
	}
	return addr, port, data[headLen:], nil
}

// buildUDPDatagram 构造发往客户端的 SOCKS5 UDP 数据报。
func buildUDPDatagram(host string, port int, payload []byte) ([]byte, error) {
	spec, err := encodeAddrSpec(host, port)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 3+len(spec)+len(payload))
	out = append(out, 0x00, 0x00, 0x00) // RSV(2) + FRAG(1)
	out = append(out, spec...)
	out = append(out, payload...)
	return out, nil
}

// checkACLQuiet 仅做 ACL 判断，不发送任何回复（UDP 无连接，无法回复）。
func (s *Server) checkACLQuiet(host string, port int) bool {
	if s.cfg.ACL == nil {
		return true
	}
	return s.cfg.ACL.Allow(host, port)
}
