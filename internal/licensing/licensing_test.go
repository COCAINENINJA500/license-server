package licensing

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 密钥文件加载/生成
// ---------------------------------------------------------------------------

func TestLoadOrCreateKey_GeneratesAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.key")

	k1, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("首次应自动生成: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("密钥文件应存在: %v", err)
	}
	// POSIX 权限位仅在全平台语义一致的系统上断言(Windows ACL 不映射 0600).
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0600 {
			t.Fatalf("密钥文件权限应为 0600: got %v", mode)
		}
	}

	k2, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("二次加载失败: %v", err)
	}
	if !k1.Equal(k2) {
		t.Fatalf("两次加载应为同一把密钥")
	}
}

func TestLoadOrCreateKey_InvalidContent(t *testing.T) {
	dir := t.TempDir()

	// 非法 hex.
	p1 := filepath.Join(dir, "bad-hex.key")
	if err := os.WriteFile(p1, []byte("zzzz"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(p1); err == nil {
		t.Fatalf("非法 hex 应报错")
	}

	// 长度非法.
	p2 := filepath.Join(dir, "bad-len.key")
	if err := os.WriteFile(p2, []byte("aabb"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(p2); err == nil {
		t.Fatalf("长度非法应报错")
	}
}

func TestGenerateAdminKey(t *testing.T) {
	k, err := GenerateAdminKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != 48 { // 24 字节 hex
		t.Fatalf("admin key 长度应为 48: got %d", len(k))
	}
}

// ---------------------------------------------------------------------------
// NonceStore: 格式/超窗/重放/双代清理
// ---------------------------------------------------------------------------

func TestNonceStore_Basics(t *testing.T) {
	now := time.Unix(1700000000, 0)
	n := NewNonceStore(NonceRetention, func() time.Time { return now })

	// 格式非法.
	if err := n.CheckAndRecord(now.Unix(), "bad nonce!"); err == nil {
		t.Fatalf("非法格式应拒绝")
	}
	// timestamp 超窗(前后方向).
	if err := n.CheckAndRecord(now.Unix()-3600, "nonce-ok-1"); err == nil {
		t.Fatalf("超窗应拒绝")
	}
	// 正常记录.
	if err := n.CheckAndRecord(now.Unix(), "nonce-ok-1"); err != nil {
		t.Fatalf("正常 nonce 应通过: %v", err)
	}
	// 重放.
	if err := n.CheckAndRecord(now.Unix(), "nonce-ok-1"); err != ErrReplay {
		t.Fatalf("重放应 ErrReplay: got %v", err)
	}
}

func TestNonceStore_GenerationalEviction(t *testing.T) {
	current := time.Unix(1700000000, 0)
	n := NewNonceStore(time.Minute, func() time.Time { return current })

	if err := n.CheckAndRecord(current.Unix(), "nonce-gen-1"); err != nil {
		t.Fatalf("记录失败: %v", err)
	}

	// 前进 3 分钟:第一次惰性轮换把 G1 降级为上一代,nonce 仍在保留期内 -> 重放.
	current = current.Add(3 * time.Minute)
	if err := n.CheckAndRecord(current.Unix(), "nonce-gen-1"); err != ErrReplay {
		t.Fatalf("保留期内应仍判重放: got %v", err)
	}

	// 再前进 1 分钟以上:第二次轮换,G1 整体丢弃,nonce 应被遗忘.
	// ReplayWindow=5min,timestamp 仍在窗口内,因此这是真实的"过期遗忘".
	current = current.Add(61 * time.Second)
	if err := n.CheckAndRecord(current.Unix(), "nonce-gen-1"); err != nil {
		t.Fatalf("代际清理后同 nonce 应可再次使用: %v", err)
	}
}
