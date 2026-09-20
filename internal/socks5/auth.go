package socks5

import (
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
)

// Authenticator 负责认证方法协商与子协商。
type Authenticator interface {
	// Method 从客户端提供的方法列表中挑选一个；返回 MethodNoAcceptable 表示拒绝。
	Method(methods []byte) byte
	// Authenticate 执行已选定方法的子协商，返回 nil 表示认证通过。
	Authenticate(conn net.Conn, method byte) error
}

// Auth 是内置的认证器实现，支持"免认证"与"用户名/密码"(RFC 1929) 两种方式。
//
// 行为：
//   - Users 为空且 Required 为 false：只接受免认证方式。
//   - Users 非空且 Required 为 false：优先免认证，其次用户名/密码。
//   - Required 为 true：只接受用户名/密码。
type Auth struct {
	// Users 为 用户名 -> 密码 映射。
	Users map[string]string
	// Required 为 true 时强制要求用户名/密码认证。
	Required bool
}

// NewAuth 构造认证器。
func NewAuth(users map[string]string, required bool) *Auth {
	if users == nil {
		users = map[string]string{}
	}
	return &Auth{Users: users, Required: required}
}

func (a *Auth) hasUsers() bool { return len(a.Users) > 0 }

// Method 实现 Authenticator。
func (a *Auth) Method(methods []byte) byte {
	var supportUserPass, supportNoAuth bool

	for _, m := range methods {
		switch m {
		case MethodUserPass:
			if a.hasUsers() {
				supportUserPass = true
			}
		case MethodNoAuth:
			if !a.Required {
				supportNoAuth = true
			}
		}
	}

	// Required 为 false 表示"认证可选"，此时优先免认证，允许匿名访问；
	// 只有客户端不支持免认证（或强制认证）时才走用户名/密码。
	if supportNoAuth && !a.Required {
		return MethodNoAuth
	}
	if supportUserPass {
		return MethodUserPass
	}
	if supportNoAuth {
		return MethodNoAuth
	}
	return MethodNoAcceptable
}

// Authenticate 实现 Authenticator。免认证方式直接通过；
// 用户名/密码方式按 RFC 1929 解析请求报文并校验凭据。
func (a *Auth) Authenticate(conn net.Conn, method byte) error {
	switch method {
	case MethodNoAuth:
		return nil

	case MethodUserPass:
		return a.authenticateUserPass(conn)

	default:
		return ErrAuthFailed
	}
}

func (a *Auth) authenticateUserPass(conn net.Conn) error {
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	ver := header[0]
	ulen := int(header[1])
	// RFC 1929 规定认证子协商版本为 0x01。
	if ver != 0x01 || ulen == 0 {
		writeAuthReply(conn, 0x01)
		return ErrAuthFailed
	}

	user := make([]byte, ulen)
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}

	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return err
	}
	plen := int(plenBuf[0])

	pass := make([]byte, plen)
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	if a.check(string(user), string(pass)) {
		return writeAuthReply(conn, 0x00)
	}
	writeAuthReply(conn, 0x01)
	return ErrAuthFailed
}

// check 使用常量时间比较避免时序侧信道。
func (a *Auth) check(user, pass string) bool {
	want, ok := a.Users[user]
	if !ok {
		// 即使用户不存在也执行一次比较，保持时间一致。
		_ = subtle.ConstantTimeCompare([]byte(pass), []byte(pass))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(pass)) == 1
}

// writeAuthReply 回复认证结果，STATUS 0x00 为成功，其它为失败。
func writeAuthReply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{0x01, status})
	return err
}

// readAddrSpec 从报文中读取 ATYP + DST.ADDR + DST.PORT。
func readAddrSpec(r io.Reader) (addr string, port int, err error) {
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return "", 0, err
	}

	switch atyp[0] {
	case AtypIPv4:
		b := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		addr = net.IP(b).String()

	case AtypIPv6:
		b := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		addr = net.IP(b).String()

	case AtypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			return "", 0, ErrMalformedRequest
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		addr = string(b)

	default:
		return "", 0, ErrAddressNotSupported
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(r, pb); err != nil {
		return "", 0, err
	}
	port = int(binary.BigEndian.Uint16(pb))

	return addr, port, nil
}

// encodeAddrSpec 按 SOCKS5 地址格式编码 addr:port。
func encodeAddrSpec(addr string, port int) ([]byte, error) {
	var (
		atyp byte
		host []byte
	)

	if ip := net.ParseIP(addr); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			atyp = AtypIPv4
			host = v4
		} else {
			atyp = AtypIPv6
			host = ip.To16()
		}
	} else {
		if len(addr) > 255 {
			return nil, ErrAddressNotSupported
		}
		atyp = AtypDomain
		host = append([]byte{byte(len(addr))}, []byte(addr)...)
	}

	out := make([]byte, 0, 1+len(host)+2)
	out = append(out, atyp)
	out = append(out, host...)
	out = append(out, byte(port>>8), byte(port&0xff))
	return out, nil
}

// writeReply 发送 SOCKS5 响应报文。
// bind 为 BND.ADDR/BND.PORT，传 nil 时使用 0.0.0.0:0。
func writeReply(w io.Writer, rep byte, bind net.Addr) error {
	atyp := byte(AtypIPv4)
	host := []byte{0, 0, 0, 0}
	port := 0

	if bind != nil {
		h, p, err := splitHostPort(bind)
		if err == nil {
			port = p
			if ip := net.ParseIP(h); ip != nil {
				if v4 := ip.To4(); v4 != nil {
					atyp = AtypIPv4
					host = v4
				} else {
					atyp = AtypIPv6
					host = ip.To16()
				}
			} else if len(h) <= 255 {
				atyp = AtypDomain
				host = append([]byte{byte(len(h))}, []byte(h)...)
			}
		}
	}

	buf := make([]byte, 0, 4+len(host)+2)
	buf = append(buf, Version5, rep, 0x00, atyp)
	buf = append(buf, host...)
	buf = append(buf, byte(port>>8), byte(port&0xff))

	_, err := w.Write(buf)
	return err
}
