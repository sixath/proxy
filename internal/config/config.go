// Package config 负责代理配置文件的加载、默认值填充与校验。
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sixath/proxy/internal/acl"
)

// Duration 支持以 "10s"、"2m" 等字符串形式书写的时长。
type Duration time.Duration

// UnmarshalYAML 同时接受字符串（如 "30s"）与整数（按秒计算）。
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	switch value.Tag {
	case "!!int":
		var secs int64
		if err := value.Decode(&secs); err != nil {
			return err
		}
		*d = Duration(time.Duration(secs) * time.Second)
		return nil
	default:
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("无效的时长 %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
}

// Std 转换为标准库 time.Duration。
func (d Duration) Std() time.Duration { return time.Duration(d) }

// User 是一个代理账号。
type User struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

// Auth 是认证配置。
type Auth struct {
	// Enabled 为 true 时强制要求用户名/密码认证。
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Users   []User `yaml:"users" json:"users"`
}

// Map 将用户列表转换为 用户名 -> 密码 映射。
func (a Auth) Map() map[string]string {
	m := make(map[string]string, len(a.Users))
	for _, u := range a.Users {
		if u.Username == "" {
			continue
		}
		m[u.Username] = u.Password
	}
	return m
}

// ServerCommon 是 SOCKS5 与 HTTP 服务共用的配置段。
type ServerCommon struct {
	// Enabled 为 false 时不启动该服务。
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Listen 为监听地址，例如 ":1080"。
	Listen string `yaml:"listen" json:"listen"`
	// ConnectTimeout 为连接目标服务器的超时。
	ConnectTimeout Duration `yaml:"connect_timeout" json:"connect_timeout"`
	// IdleTimeout 为连接空闲超时，0 表示不限制。
	IdleTimeout Duration `yaml:"idle_timeout" json:"idle_timeout"`
	// GraceTimeout 为半关闭宽限时长。
	GraceTimeout Duration `yaml:"grace_timeout" json:"grace_timeout"`
	// Auth 为认证配置。
	Auth Auth `yaml:"auth" json:"auth"`
}

// Socks5 是 SOCKS5 服务的配置段。
type Socks5 struct {
	ServerCommon `yaml:",inline"`
	// EnableUDP 为 true 时支持 UDP ASSOCIATE。
	EnableUDP bool `yaml:"udp" json:"udp"`
	// EnableBind 为 true 时支持 BIND 命令。
	EnableBind bool `yaml:"bind" json:"bind"`
	// UDPBufferSize 为 UDP 缓冲区大小（字节）。
	UDPBufferSize int `yaml:"udp_buffer_size" json:"udp_buffer_size"`
	// UDPIdleTimeout 为 UDP 中继空闲超时。
	UDPIdleTimeout Duration `yaml:"udp_idle_timeout" json:"udp_idle_timeout"`
}

// HTTP 是 HTTP 代理服务的配置段。
type HTTP struct {
	ServerCommon `yaml:",inline"`
	// ForwardTimeout 为单个 HTTP 请求的整体超时。
	ForwardTimeout Duration `yaml:"forward_timeout" json:"forward_timeout"`
}

// Log 是日志配置段。
type Log struct {
	// Level 取值 debug/info/warn/error。
	Level string `yaml:"level" json:"level"`
	// Format 取值 text/json。
	Format string `yaml:"format" json:"format"`
	// Output 取值 stdout/stderr 或文件路径。
	Output string `yaml:"output" json:"output"`
}

// ACL 是访问控制配置段。
type ACL struct {
	// Default 为无规则命中时的默认动作：allow 或 deny。
	Default string     `yaml:"default" json:"default"`
	Rules   []acl.Rule `yaml:"rules" json:"rules"`
}

// Config 是完整配置。
type Config struct {
	Log    Log    `yaml:"log" json:"log"`
	Socks5 Socks5 `yaml:"socks5" json:"socks5"`
	HTTP   HTTP   `yaml:"http" json:"http"`
	ACL    ACL    `yaml:"acl" json:"acl"`
}

// Default 返回一份开箱即用的默认配置：
// SOCKS5 监听 :1080，HTTP 代理监听 :8080，均不强制认证，全部放行。
func Default() *Config {
	return &Config{
		Log: Log{Level: "info", Format: "text", Output: "stdout"},
		Socks5: Socks5{
			ServerCommon: ServerCommon{
				Enabled:        true,
				Listen:         ":1080",
				ConnectTimeout: Duration(10 * time.Second),
				IdleTimeout:    Duration(5 * time.Minute),
				GraceTimeout:   Duration(15 * time.Second),
			},
			EnableUDP:      true,
			EnableBind:     false,
			UDPBufferSize:  64 * 1024,
			UDPIdleTimeout: Duration(5 * time.Minute),
		},
		HTTP: HTTP{
			ServerCommon: ServerCommon{
				Enabled:        true,
				Listen:         ":8080",
				ConnectTimeout: Duration(10 * time.Second),
				IdleTimeout:    Duration(5 * time.Minute),
				GraceTimeout:   Duration(15 * time.Second),
			},
			ForwardTimeout: Duration(0),
		},
		ACL: ACL{Default: "allow"},
	}
}

// Load 从 path 读取配置；文件不存在时返回默认配置。
func Load(path string) (*Config, error) {
	if path == "" {
		return Default(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate 校验配置合法性。
func (c *Config) Validate() error {
	if !c.Socks5.Enabled && !c.HTTP.Enabled {
		return errors.New("socks5 与 http 至少启用一个服务")
	}
	if c.Socks5.Enabled && c.Socks5.Listen == "" {
		return errors.New("socks5.listen 不能为空")
	}
	if c.HTTP.Enabled && c.HTTP.Listen == "" {
		return errors.New("http.listen 不能为空")
	}

	for name, a := range map[string]Auth{"socks5": c.Socks5.Auth, "http": c.HTTP.Auth} {
		if a.Enabled && len(a.Users) == 0 {
			return fmt.Errorf("%s 启用了认证但没有配置任何用户", name)
		}
		for _, u := range a.Users {
			if u.Username == "" {
				return fmt.Errorf("%s 的用户名不能为空", name)
			}
		}
	}
	return nil
}

// ACLSet 编译访问控制规则集。
func (c *Config) ACLSet() (*acl.Set, error) {
	return acl.New(c.ACL.Default, c.ACL.Rules)
}
