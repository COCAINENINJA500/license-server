// Package licensing 承载签名密钥、JWT 签发/校验与防重放 nonce 存储.
package licensing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
)

// LoadOrCreateKey 加载 Ed25519 私钥文件,不存在则生成.
// 文件内容为 hex(seed 32 字节 或私钥 64 字节),权限 0600.
func LoadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		raw := strings.TrimSpace(string(data))
		b, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("私钥文件解析失败(应为 hex): %w", err)
		}
		switch len(b) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(b), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(b), nil
		default:
			return nil, fmt.Errorf("私钥文件长度非法: %d 字节", len(b))
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := priv.Seed()
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		return nil, err
	}
	log.Printf("已生成新的 Ed25519 签名密钥: %s", path)
	log.Printf("公钥(随客户端发布, base64): %s", base64.StdEncoding.EncodeToString(pub))
	return priv, nil
}

// GenerateAdminKey 生成 48 位 hex 管理 Key.
func GenerateAdminKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
