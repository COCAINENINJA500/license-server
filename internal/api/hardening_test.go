package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 限流:burst 用尽后 429
// ---------------------------------------------------------------------------

func TestRateLimit(t *testing.T) {
	env := testServerWithRate(t, 0.5, 2) // 0.5 rps, burst 2
	var tooMany, ok int
	for i := 0; i < 6; i++ {
		rec := doReq(t, env, "GET", "/v1/pubkey", nil, nil)
		switch rec.Code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			tooMany++
			if ra := rec.Header().Get("Retry-After"); ra == "" {
				t.Fatalf("429 应带 Retry-After")
			}
		default:
			t.Fatalf("未预期状态码 %d", rec.Code)
		}
	}
	if ok != 2 || tooMany != 4 {
		t.Fatalf("限流结果不符: ok=%d tooMany=%d", ok, tooMany)
	}
	// 非 /v1/ 前缀不受限流影响.
	for i := 0; i < 5; i++ {
		if rec := doReq(t, env, "GET", "/healthz", nil, nil); rec.Code != http.StatusOK {
			t.Fatalf("healthz 不应被限流: %d", rec.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// 请求体上限:超限 413
// ---------------------------------------------------------------------------

func TestBodySizeLimit(t *testing.T) {
	env := testServer(t)
	// 构造 >1MiB 的合法 JSON 请求体.
	big := strings.Repeat("A", 1<<20)
	body := fmt.Sprintf(`{"license_key":"%s","machine_hash":"m","timestamp":%d,"nonce":"%s"}`,
		big, time.Now().Unix(), freshNonce())
	req := httptest.NewRequest("POST", "/v1/activate", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("超大请求体应 413: got %d %s", rec.Code, rec.Body.String())
	}
	// 正常体积不受影响.
	small := map[string]any{"license_key": "LIC-x", "machine_hash": "m", "timestamp": time.Now().Unix(), "nonce": freshNonce()}
	rec2 := doReq(t, env, "POST", "/v1/activate", small, nil)
	if rec2.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("正常请求不应 413")
	}
}

// ---------------------------------------------------------------------------
// 健康检查带版本号
// ---------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	env := testServer(t)
	rec := doReq(t, env, "GET", "/healthz", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz 应 200: %d", rec.Code)
	}
	out := decodeBody(t, rec)
	if out["status"] != "ok" || out["version"] != "test" {
		t.Fatalf("healthz 字段不符: %v", out)
	}
}
