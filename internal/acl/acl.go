// Package acl 提供代理目标的访问控制能力，支持按 IP/CIDR、域名、端口放行或拒绝。
package acl

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Action 表示一条规则的动作。
type Action string

const (
	// Allow 表示放行。
	Allow Action = "allow"
	// Deny 表示拒绝。
	Deny Action = "deny"
)

// Rule 是一条未编译的访问控制规则。
type Rule struct {
	// Action 为 allow 或 deny。
	Action string `yaml:"action" json:"action"`
	// CIDRs 为目标 IP 或 CIDR 列表，例如 "10.0.0.0/8"、"192.168.1.5"。
	CIDRs []string `yaml:"cidr" json:"cidr"`
	// Domains 为目标域名列表，支持 "example.com"（含子域后缀匹配）
	// 与 "*.example.com"（通配）两种写法。
	Domains []string `yaml:"domain" json:"domain"`
	// Ports 为目标端口列表，支持单端口 "3306" 与范围 "8000-8080"。
	Ports []string `yaml:"port" json:"port"`
}

// Set 是编译后的规则集。
type Set struct {
	defaultAction Action
	rules         []compiledRule
}

type compiledRule struct {
	action  Action
	nets    []*net.IPNet
	domains []string
	ports   []portRange
}

type portRange struct {
	lo, hi int
}

// New 编译规则集。defaultAction 为没有任何规则命中时的默认动作。
func New(defaultAction string, rules []Rule) (*Set, error) {
	def, err := parseAction(defaultAction)
	if err != nil {
		return nil, err
	}

	s := &Set{defaultAction: def}
	for i, r := range rules {
		cr, err := compileRule(r)
		if err != nil {
			return nil, fmt.Errorf("第 %d 条 ACL 规则无效: %w", i+1, err)
		}
		s.rules = append(s.rules, cr)
	}
	return s, nil
}

func parseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "allow":
		return Allow, nil
	case "deny":
		return Deny, nil
	default:
		return "", fmt.Errorf("未知动作 %q，仅支持 allow/deny", s)
	}
}

func compileRule(r Rule) (compiledRule, error) {
	action, err := parseAction(r.Action)
	if err != nil {
		return compiledRule{}, err
	}

	cr := compiledRule{action: action}

	for _, c := range r.CIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			ip := net.ParseIP(c)
			if ip == nil {
				return compiledRule{}, fmt.Errorf("无效 IP 地址 %q", c)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			_, n, err := net.ParseCIDR(c + "/" + strconv.Itoa(bits))
			if err != nil {
				return compiledRule{}, fmt.Errorf("无效 IP 地址 %q", c)
			}
			cr.nets = append(cr.nets, n)
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return compiledRule{}, fmt.Errorf("无效 CIDR %q: %w", c, err)
		}
		cr.nets = append(cr.nets, n)
	}

	for _, d := range r.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		cr.domains = append(cr.domains, strings.TrimPrefix(d, "*."))
	}

	for _, p := range r.Ports {
		pr, err := parsePortRange(p)
		if err != nil {
			return compiledRule{}, err
		}
		cr.ports = append(cr.ports, pr)
	}

	return cr, nil
}

func parsePortRange(s string) (portRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return portRange{}, fmt.Errorf("端口不能为空")
	}

	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		lo, err := parsePort(parts[0])
		if err != nil {
			return portRange{}, fmt.Errorf("无效端口范围 %q", s)
		}
		hi, err := parsePort(parts[1])
		if err != nil {
			return portRange{}, fmt.Errorf("无效端口范围 %q", s)
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		return portRange{lo: lo, hi: hi}, nil
	}

	p, err := parsePort(s)
	if err != nil {
		return portRange{}, err
	}
	return portRange{lo: p, hi: p}, nil
}

func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("端口不能为空")
	}
	p, err := strconv.Atoi(s)
	if err != nil || p < 0 || p > 65535 {
		return 0, fmt.Errorf("无效端口 %q", s)
	}
	return p, nil
}

// Allow 判断访问 host:port 是否被放行。host 可以是 IP 字面量或域名。
// 规则按配置顺序匹配，第一条命中的规则决定结果；无命中时使用默认动作。
func (s *Set) Allow(host string, port int) bool {
	if s == nil {
		return true
	}

	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	isIP := net.ParseIP(host) != nil

	for _, r := range s.rules {
		if r.matches(host, port, isIP) {
			return r.action == Allow
		}
	}
	return s.defaultAction == Allow
}

func (r compiledRule) matches(host string, port int, isIP bool) bool {
	// 规则内各维度条件是"与"关系，但空维度视为不限制。
	matched := false

	if len(r.ports) > 0 {
		portOK := false
		for _, pr := range r.ports {
			if port >= pr.lo && port <= pr.hi {
				portOK = true
				break
			}
		}
		if !portOK {
			return false
		}
		matched = true
	}

	if len(r.nets) > 0 {
		if !isIP {
			return false
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		ipOK := false
		for _, n := range r.nets {
			if n.Contains(ip) {
				ipOK = true
				break
			}
		}
		if !ipOK {
			return false
		}
		matched = true
	}

	if len(r.domains) > 0 {
		if isIP {
			return false
		}
		domainOK := false
		for _, d := range r.domains {
			if host == d || strings.HasSuffix(host, "."+d) {
				domainOK = true
				break
			}
		}
		if !domainOK {
			return false
		}
		matched = true
	}

	// 三个维度都为空的规则视为不匹配任何目标（避免误伤全部流量）。
	return matched
}
