package socks5

import (
	"bytes"
	"io"
	"strconv"
)

// bytesReader 返回一个基于字节切片的 io.Reader。
func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// itoa 将端口号转换为十进制字符串。
func itoa(i int) string { return strconv.Itoa(i) }
