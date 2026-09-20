// proxy 是一个同时提供 HTTP 与 SOCKS5 正向代理的 Go 程序。
//
// 两者都工作在传输层：SOCKS5 CONNECT 与 HTTP CONNECT 都会在客户端和目标
// 之间建立纯 TCP 隧道，因此 MongoDB、MySQL、PostgreSQL、Redis 等任意基于
// TCP 的协议都可以直接使用本代理，无需任何额外适配。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sixath/proxy/internal/config"
	"github.com/sixath/proxy/internal/httpproxy"
	"github.com/sixath/proxy/internal/logger"
	"github.com/sixath/proxy/internal/socks5"
)

func main() {
	var (
		cfgPath    string
		socks5Addr string
		httpAddr   string
		username   string
		password   string
		logLevel   string
		showVer    bool
	)

	flag.StringVar(&cfgPath, "c", "config.yaml", "配置文件路径（不存在时使用默认配置）")
	flag.StringVar(&socks5Addr, "socks5", "", "覆盖 SOCKS5 监听地址，例如 :1080")
	flag.StringVar(&httpAddr, "http", "", "覆盖 HTTP 代理监听地址，例如 :8080")
	flag.StringVar(&username, "user", "", "设置代理用户名（与 -pass 同时使用）")
	flag.StringVar(&password, "pass", "", "设置代理密码（与 -user 同时使用）")
	flag.StringVar(&logLevel, "log-level", "", "覆盖日志级别：debug/info/warn/error")
	flag.BoolVar(&showVer, "version", false, "打印版本信息")
	flag.Usage = usage
	flag.Parse()

	if showVer {
		fmt.Printf("proxy %s\n", version)
		return
	}

	if err := run(cfgPath, socks5Addr, httpAddr, username, password, logLevel); err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
}

// version 为构建版本号，编译时可用
// -ldflags "-X main.version=v1.2.3" 覆盖，Dockerfile 与 CI 均通过该方式注入。
var version = "v1.0.0"

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `用法: proxy [选项]

一个同时支持 HTTP 与 SOCKS5 的正向代理服务器。
由于两者都在传输层建立 TCP 隧道，可直接代理 MongoDB、MySQL 等任意 TCP 协议。

选项:
`)
	flag.PrintDefaults()
	fmt.Fprintf(flag.CommandLine.Output(), `
示例:
  proxy                                  使用默认配置启动（SOCKS5 :1080 / HTTP :8080）
  proxy -c config.yaml                   指定配置文件
  proxy -socks5 :1080 -user u -pass p    仅命令行方式开启 SOCKS5 并要求认证
`)
}

func run(cfgPath, socks5Addr, httpAddr, username, password, logLevel string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	// 命令行参数优先级高于配置文件。
	if socks5Addr != "" {
		cfg.Socks5.Enabled = true
		cfg.Socks5.Listen = socks5Addr
	}
	if httpAddr != "" {
		cfg.HTTP.Enabled = true
		cfg.HTTP.Listen = httpAddr
	}
	if username != "" {
		u := config.User{Username: username, Password: password}
		cfg.Socks5.Auth = config.Auth{Enabled: true, Users: []config.User{u}}
		cfg.HTTP.Auth = config.Auth{Enabled: true, Users: []config.User{u}}
	}
	if logLevel != "" {
		cfg.Log.Level = logLevel
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	lg, err := logger.New(logger.Options{Level: cfg.Log.Level, Format: cfg.Log.Format, Output: cfg.Log.Output})
	if err != nil {
		return err
	}
	slog.SetDefault(lg)

	aclSet, err := cfg.ACLSet()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// SOCKS5 服务
	if cfg.Socks5.Enabled {
		socksSrv := socks5.New(socks5.Config{
			Auth:           socks5.NewAuth(cfg.Socks5.Auth.Map(), cfg.Socks5.Auth.Enabled),
			ACL:            aclSet,
			ConnectTimeout: cfg.Socks5.ConnectTimeout.Std(),
			IdleTimeout:    cfg.Socks5.IdleTimeout.Std(),
			GraceTimeout:   cfg.Socks5.GraceTimeout.Std(),
			EnableUDP:      cfg.Socks5.EnableUDP,
			EnableBind:     cfg.Socks5.EnableBind,
			UDPBufferSize:  cfg.Socks5.UDPBufferSize,
			UDPIdleTimeout: cfg.Socks5.UDPIdleTimeout.Std(),
			Logger:         lg.With("service", "socks5"),
		})

		ln, err := net.Listen("tcp", cfg.Socks5.Listen)
		if err != nil {
			return fmt.Errorf("socks5 监听 %s 失败: %w", cfg.Socks5.Listen, err)
		}
		defer ln.Close()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := socksSrv.Serve(ctx, ln); err != nil && !ctxDone(ctx) {
				errCh <- fmt.Errorf("socks5 服务异常: %w", err)
			}
		}()
	}

	// HTTP 代理服务
	if cfg.HTTP.Enabled {
		httpSrv := httpproxy.New(httpproxy.Config{
			Auth:           httpproxy.NewAuth(cfg.HTTP.Auth.Map(), cfg.HTTP.Auth.Enabled),
			ACL:            aclSet,
			ConnectTimeout: cfg.HTTP.ConnectTimeout.Std(),
			IdleTimeout:    cfg.HTTP.IdleTimeout.Std(),
			GraceTimeout:   cfg.HTTP.GraceTimeout.Std(),
			ForwardTimeout: cfg.HTTP.ForwardTimeout.Std(),
			Logger:         lg.With("service", "http"),
		})
		defer httpSrv.Close()

		ln, err := net.Listen("tcp", cfg.HTTP.Listen)
		if err != nil {
			return fmt.Errorf("http 监听 %s 失败: %w", cfg.HTTP.Listen, err)
		}
		defer ln.Close()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := httpSrv.Serve(ctx, ln); err != nil && !ctxDone(ctx) {
				errCh <- fmt.Errorf("http 服务异常: %w", err)
			}
		}()
	}

	lg.Info("代理服务已就绪",
		"socks5", listenDesc(cfg.Socks5.Enabled, cfg.Socks5.Listen),
		"http", listenDesc(cfg.HTTP.Enabled, cfg.HTTP.Listen),
		"acl_default", cfg.ACL.Default,
		"version", version,
	)
	lg.Info("按 Ctrl+C 停止服务")

	// 等待退出信号或任一服务异常退出。
	select {
	case err := <-errCh:
		stop()
		wg.Wait()
		return err
	case <-ctx.Done():
	}

	// 触发优雅退出，等待所有服务收尾。
	stop()
	wg.Wait()

	lg.Info("代理服务已停止")
	return nil
}

func ctxDone(ctx context.Context) bool {
	return errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded)
}

func listenDesc(enabled bool, addr string) string {
	if !enabled {
		return "disabled"
	}
	return addr
}
