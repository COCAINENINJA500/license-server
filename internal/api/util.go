package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"strconv"
	"strings"
)

// subtleCompare 常数时间字符串比较(防 timing attack).
func subtleCompare(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}

// randomHex 生成 n 字节随机数的 hex 串.
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// atoiDefault 字符串转 int,失败返回默认值.
func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}
