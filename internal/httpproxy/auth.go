package httpproxy

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

// Auth 是 HTTP 代理的身份认证器，基于 RFC 7617 的 Basic 方案，
// 通过 Proxy-Authorization 请求头传递凭据。
type Auth struct {
	// Users 为 用户名 -> 密码 映射。
	Users map[string]string
	// Required 为 true 时强制要求认证。
	Required bool
}

// NewAuth 构造认证器。
func NewAuth(users map[string]string, required bool) *Auth {
	if users == nil {
		users = map[string]string{}
	}
	return &Auth{Users: users, Required: required}
}

// Authenticate 校验请求是否通过认证。返回 code == 0 表示通过。
//
// 语义与配置的 auth.enabled 对应：
//   - Required 为 false：允许匿名访问；若客户端主动提供了凭据，则凭据必须有效。
//   - Required 为 true：必须提供有效凭据，否则返回 407。
func (a *Auth) Authenticate(r *http.Request) (code int, msg string) {
	user, pass, hasCred := parseBasicAuth(r.Header.Get("Proxy-Authorization"))

	if !a.Required {
		// 未配置用户时无从校验，一律放行。
		if len(a.Users) == 0 || !hasCred {
			return 0, ""
		}
		if a.check(user, pass) {
			return 0, ""
		}
		return http.StatusProxyAuthRequired, "Proxy Authentication Required"
	}

	if !hasCred || !a.check(user, pass) {
		return http.StatusProxyAuthRequired, "Proxy Authentication Required"
	}
	return 0, ""
}

// challenge 返回 407 响应要求客户端提供凭据。
func (a *Auth) challenge() string {
	return `Basic realm="proxy"`
}

func (a *Auth) check(user, pass string) bool {
	want, ok := a.Users[user]
	if !ok {
		_ = subtle.ConstantTimeCompare([]byte(pass), []byte(pass))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(pass)) == 1
}

// parseBasicAuth 解析 "Basic base64(user:pass)" 形式的凭据。
func parseBasicAuth(v string) (user, pass string, ok bool) {
	if v == "" {
		return "", "", false
	}
	parts := strings.SplitN(v, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "basic") {
		return "", "", false
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return "", "", false
	}
	u, p, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return u, p, true
}
