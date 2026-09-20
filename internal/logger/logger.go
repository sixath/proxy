// Package logger 提供基于标准库 log/slog 的统一日志封装。
package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Options 描述日志初始化参数。
type Options struct {
	// Level 取值：debug / info / warn / error，默认 info。
	Level string
	// Format 取值：text / json，默认 text。
	Format string
	// Output 取值：stdout / stderr 或文件路径，默认 stdout。
	Output string
}

// New 根据选项构造 Logger。
func New(opts Options) (*slog.Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	w, err := openOutput(opts.Output)
	if err != nil {
		return nil, err
	}

	handlerOpts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if strings.EqualFold(opts.Format, "json") {
		handler = slog.NewJSONHandler(w, handlerOpts)
	} else {
		handler = slog.NewTextHandler(w, handlerOpts)
	}

	return slog.New(handler), nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("未知日志级别: %q", s)
	}
}

func openOutput(s string) (io.Writer, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	default:
		f, err := os.OpenFile(s, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, fmt.Errorf("打开日志文件 %q 失败: %w", s, err)
		}
		return f, nil
	}
}
