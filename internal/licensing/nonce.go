package licensing

import (
	"errors"
	"regexp"
	"sync"
	"time"
)

// 防重放参数.
const (
	// ReplayWindow timestamp 与服务端时间差允许范围.
	ReplayWindow = 5 * time.Minute
	// NonceRetention nonce 记忆时长(须 >= ReplayWindow).
	NonceRetention = 10 * time.Minute
)

// nonce 校验:8~128 位字母数字/-/_
var nonceFmt = regexp.MustCompile(`^[A-Za-z0-9\-_]{8,128}$`)

// 防重放错误(由 API 层映射为对应 HTTP 状态码).
var (
	ErrNonceFormat    = errors.New("nonce 格式非法(需 8~128 位字母数字/-/_ )")
	ErrTimestampStale = errors.New("timestamp 超出 ±5 分钟窗口(请校准客户端时钟)")
	ErrReplay         = errors.New("重放拒绝: nonce 已使用")
)

// NonceStore 记录最近见过的 nonce,防止重放攻击.
//
// 采用双代(generational)设计:当前代写满保留期后整体轮换为上一代,
// 清理代价 O(1),避免每请求全表扫描.
type NonceStore struct {
	mu        sync.Mutex
	cur       map[string]int64 // 当前代: nonce -> 记录时间 unix 秒
	prev      map[string]int64 // 上一代: 仍在保留期内
	rotatedAt time.Time
	retention time.Duration
	now       func() time.Time
}

// NewNonceStore 创建 nonce 存储. now 可注入固定时钟(测试).
func NewNonceStore(retention time.Duration, now func() time.Time) *NonceStore {
	if retention <= 0 {
		retention = NonceRetention
	}
	if now == nil {
		now = time.Now
	}
	return &NonceStore{
		cur:       make(map[string]int64),
		prev:      make(map[string]int64),
		rotatedAt: now(),
		retention: retention,
		now:       now,
	}
}

// CheckAndRecord 校验 timestamp 是否在窗口内、nonce 是否未见过,通过则记录.
// 返回 ErrTimestampStale / ErrNonceFormat / ErrReplay 之一,或 nil 表示通过.
func (n *NonceStore) CheckAndRecord(ts int64, nonce string) error {
	if !nonceFmt.MatchString(nonce) {
		return ErrNonceFormat
	}
	now := n.now()
	nowUnix := now.Unix()
	diff := nowUnix - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(ReplayWindow/time.Second) {
		return ErrTimestampStale
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	// 双代轮换:超过保留期,上一代整体丢弃,当前代降级为上一代.
	if now.Sub(n.rotatedAt) >= n.retention {
		n.prev = n.cur
		n.cur = make(map[string]int64)
		n.rotatedAt = now
	}
	// 命中当前代或上一代 = 重放.
	if _, ok := n.cur[nonce]; ok {
		return ErrReplay
	}
	if _, ok := n.prev[nonce]; ok {
		return ErrReplay
	}
	n.cur[nonce] = nowUnix
	return nil
}
