package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

var nonceSeq atomic.Int64

func testServer(t *testing.T) *Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err := initDB(db); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(db, "test-admin-key", priv, 24*time.Hour, 30*24*time.Hour)
	return s
}

func doReq(t *testing.T, s *Server, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, req)
	return rec
}

func adminHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer test-admin-key"}
}

func freshNonce() string {
	return fmt.Sprintf("test-nonce-%d-%d", time.Now().UnixNano(), nonceSeq.Add(1))
}

// issueLicense 经管理 API 签发,返回 license_id 与明文 license_key.
func issueLicense(t *testing.T, s *Server, customer string, days, seats int) (string, string) {
	t.Helper()
	rec := doReq(t, s, "POST", "/admin/licenses", map[string]any{
		"customer": customer, "days": days, "seats": seats,
		"features": map[string]any{"pro": true, "level": "vip"},
	}, adminHeaders())
	if rec.Code != http.StatusCreated {
		t.Fatalf("签发失败: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		LicenseID  string `json:"license_id"`
		LicenseKey string `json:"license_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.LicenseKey == "" || out.LicenseID == "" {
		t.Fatalf("签发返回缺字段: %s", rec.Body.String())
	}
	return out.LicenseID, out.LicenseKey
}

func activate(t *testing.T, s *Server, key, machine string, ts int64, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	return doReq(t, s, "POST", "/v1/activate", map[string]any{
		"license_key": key, "machine_hash": machine,
		"timestamp": ts, "nonce": nonce,
	}, nil)
}

func refresh(t *testing.T, s *Server, refreshToken string, ts int64, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	return doReq(t, s, "POST", "/v1/refresh", map[string]any{
		"refresh_token": refreshToken, "timestamp": ts, "nonce": nonce,
	}, nil)
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("响应不是 JSON: %v body=%s", err, rec.Body.String())
	}
	return out
}

// ---------------------------------------------------------------------------
// 1. 签发 -> 激活 -> access JWT 本地可验
// ---------------------------------------------------------------------------

func TestIssueAndActivate(t *testing.T) {
	s := testServer(t)
	lid, key := issueLicense(t, s, "Acme", 30, 2)

	rec := activate(t, s, key, "machine-aaa", time.Now().Unix(), freshNonce())
	if rec.Code != http.StatusOK {
		t.Fatalf("激活失败: code=%d body=%s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("缺少 access_token: %s", rec.Body.String())
	}

	// 客户端侧:用公钥本地验签.
	claims, herr := s.parseToken(access)
	if herr != nil {
		t.Fatalf("access JWT 验签失败: %v", herr)
	}
	if claims["sub"] != lid {
		t.Fatalf("sub 不符: %v != %s", claims["sub"], lid)
	}
	if claims["typ"] != "access" {
		t.Fatalf("typ 不符: %v", claims["typ"])
	}
	if claims["mhash"] != "machine-aaa" {
		t.Fatalf("mhash 不符: %v", claims["mhash"])
	}
	feat, _ := claims["features"].(map[string]any)
	if feat["pro"] != true {
		t.Fatalf("features 丢失: %v", claims["features"])
	}

	// status(Bearer 模式)可用.
	rec2 := doReq(t, s, "GET", "/v1/status", nil, map[string]string{"Authorization": "Bearer " + access})
	if rec2.Code != http.StatusOK {
		t.Fatalf("status 失败: code=%d body=%s", rec2.Code, rec2.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 2. 超席位拒绝(同机幂等不占新席位)
// ---------------------------------------------------------------------------

func TestSeatsExceeded(t *testing.T) {
	s := testServer(t)
	_, key := issueLicense(t, s, "SeatsCo", 30, 1)

	now := time.Now().Unix()
	if rec := activate(t, s, key, "m-1", now, freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("首台激活应成功: %d %s", rec.Code, rec.Body.String())
	}
	// 同一机器重复激活:幂等成功,不占新席位.
	if rec := activate(t, s, key, "m-1", now, freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("同机重复激活应幂等成功: %d %s", rec.Code, rec.Body.String())
	}
	// 第二台:403.
	rec := activate(t, s, key, "m-2", now, freshNonce())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("超席位应 403: got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 3. 吊销后 refresh 拒绝(吊销与续费的唯一卡点) + 激活同步拒绝
// ---------------------------------------------------------------------------

func TestRefreshRejectedAfterRevoke(t *testing.T) {
	s := testServer(t)
	lid, key := issueLicense(t, s, "RevokeCo", 30, 2)

	now := time.Now().Unix()
	rec := activate(t, s, key, "m-1", now, freshNonce())
	if rec.Code != http.StatusOK {
		t.Fatalf("激活失败: %d %s", rec.Code, rec.Body.String())
	}
	rt := decodeBody(t, rec)["refresh_token"].(string)

	// 吊销前 refresh 正常.
	if rec := refresh(t, s, rt, now, freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("吊销前 refresh 应成功: %d %s", rec.Code, rec.Body.String())
	}

	// 管理 API 吊销.
	rec2 := doReq(t, s, "POST", "/admin/licenses/"+lid+"/revoke", map[string]any{}, adminHeaders())
	if rec2.Code != http.StatusOK {
		t.Fatalf("吊销失败: %d %s", rec2.Code, rec2.Body.String())
	}

	// 吊销后 refresh 必须拒绝.
	if rec := refresh(t, s, rt, now, freshNonce()); rec.Code != http.StatusForbidden {
		t.Fatalf("吊销后 refresh 应 403: got %d %s", rec.Code, rec.Body.String())
	}
	// 吊销后新激活也拒绝.
	if rec := activate(t, s, key, "m-2", now, freshNonce()); rec.Code != http.StatusForbidden {
		t.Fatalf("吊销后激活应 403: got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 4. 过期后 refresh 拒绝(续费卡点)
// ---------------------------------------------------------------------------

func TestRefreshRejectedAfterExpiry(t *testing.T) {
	s := testServer(t)
	_, key := issueLicense(t, s, "ExpireCo", 30, 2)

	now := time.Now().Unix()
	rec := activate(t, s, key, "m-1", now, freshNonce())
	if rec.Code != http.StatusOK {
		t.Fatalf("激活失败: %d %s", rec.Code, rec.Body.String())
	}
	rt := decodeBody(t, rec)["refresh_token"].(string)

	// 直接把到期时间改到过去,模拟过期.
	if _, err := s.db.Exec(`UPDATE licenses SET expires_at=? WHERE key_hash=?`, now-10, sha256Hex(key)); err != nil {
		t.Fatal(err)
	}
	if rec := refresh(t, s, rt, now, freshNonce()); rec.Code != http.StatusForbidden {
		t.Fatalf("过期后 refresh 应 403: got %d %s", rec.Code, rec.Body.String())
	}

	// 续期 30 天后,旧 refresh token 若仍在 30 天有效期内应恢复可用.
	if _, err := s.db.Exec(`UPDATE licenses SET expires_at=? WHERE key_hash=?`, now+30*86400, sha256Hex(key)); err != nil {
		t.Fatal(err)
	}
	if rec := refresh(t, s, rt, now, freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("续期后 refresh 应恢复成功: %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 5. 重放拒绝: nonce 复用 + timestamp 超窗
// ---------------------------------------------------------------------------

func TestReplayRejected(t *testing.T) {
	s := testServer(t)
	_, key := issueLicense(t, s, "ReplayCo", 30, 5)

	now := time.Now().Unix()
	nonce := freshNonce()
	body := map[string]any{"license_key": key, "machine_hash": "m-1", "timestamp": now, "nonce": nonce}
	if rec := doReq(t, s, "POST", "/v1/activate", body, nil); rec.Code != http.StatusOK {
		t.Fatalf("首次激活失败: %d %s", rec.Code, rec.Body.String())
	}
	// 同一 nonce 重放 -> 409.
	if rec := doReq(t, s, "POST", "/v1/activate", body, nil); rec.Code != http.StatusConflict {
		t.Fatalf("重放 nonce 应 409: got %d %s", rec.Code, rec.Body.String())
	}
	// timestamp 超出 ±5 分钟窗口 -> 400.
	stale := map[string]any{"license_key": key, "machine_hash": "m-2", "timestamp": now - 600, "nonce": freshNonce()}
	if rec := doReq(t, s, "POST", "/v1/activate", stale, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("过期 timestamp 应 400: got %d %s", rec.Code, rec.Body.String())
	}
	// refresh 的重放同样拒绝.
	rec := activate(t, s, key, "m-3", now, freshNonce())
	rt := decodeBody(t, rec)["refresh_token"].(string)
	rbody := map[string]any{"refresh_token": rt, "timestamp": now, "nonce": freshNonce()}
	rnonce := rbody["nonce"]
	if rec := doReq(t, s, "POST", "/v1/refresh", rbody, nil); rec.Code != http.StatusOK {
		t.Fatalf("首次 refresh 失败: %d %s", rec.Code, rec.Body.String())
	}
	_ = rnonce
	// 复用同一 nonce 再次 refresh.
	if rec := doReq(t, s, "POST", "/v1/refresh", rbody, nil); rec.Code != http.StatusConflict {
		t.Fatalf("refresh 重放应 409: got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 7. 内嵌管理台可访问(单租户,无多租户概念)
// ---------------------------------------------------------------------------

func TestAdminUI(t *testing.T) {
	s := testServer(t)
	for _, p := range []string{"/admin", "/admin/"} {
		rec := doReq(t, s, "GET", p, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s 应 200: got %d", p, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Fatalf("GET %s Content-Type 应为 html: got %q", p, ct)
		}
		if !bytes.Contains(rec.Body.Bytes(), []byte(`id="loginView"`)) {
			t.Fatalf("GET %s 应只暴露登录门禁", p)
		}
		// 管理台默认隐藏(验 Key 前不渲染操作区).
		if !bytes.Contains(rec.Body.Bytes(), []byte(`id="appView" style="display:none"`)) {
			t.Fatalf("GET %s 管理台主体默认应隐藏", p)
		}
	}
	// 管理台依赖的列表接口同样可用.
	issueLicense(t, s, "UI客户", 30, 2)
	rec := doReq(t, s, "GET", "/admin/licenses", nil, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/licenses 应 200: got %d %s", rec.Code, rec.Body.String())
	}
	if total := decodeBody(t, rec)["total"]; total != float64(1) {
		t.Fatalf("列表 total 应为 1: got %v", total)
	}
}

// ---------------------------------------------------------------------------
// 8. 分页 / 统计 / 删除 / 编辑功能标记
// ---------------------------------------------------------------------------

func TestListPaginationStatsDeleteAndFeatures(t *testing.T) {
	s := testServer(t)
	ids := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		lid, _ := issueLicense(t, s, fmt.Sprintf("Co%d", i), 30, 2)
		ids = append(ids, lid)
	}

	// 分页：page_size=2 应有 2 条、total=3、total_pages=2。
	rec := doReq(t, s, "GET", "/admin/licenses?page=1&page_size=2", nil, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("分页列表应 200: %d %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	if out["total"] != float64(3) || out["total_pages"] != float64(2) {
		t.Fatalf("分页字段不符: %v", out)
	}
	if n := len(out["licenses"].([]any)); n != 2 {
		t.Fatalf("本页应 2 条: got %d", n)
	}

	// 统计。
	rec = doReq(t, s, "GET", "/admin/stats", nil, adminHeaders())
	st := decodeBody(t, rec)
	if st["total"] != float64(3) || st["active"] != float64(3) {
		t.Fatalf("统计不符: %v", st)
	}

	// 编辑功能标记。
	rec = doReq(t, s, "POST", "/admin/licenses/"+ids[0]+"/features",
		map[string]any{"features": map[string]any{"pro": false}}, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("编辑功能标记应 200: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s, "GET", "/admin/licenses/"+ids[0], nil, adminHeaders())
	got := decodeBody(t, rec)["license"].(map[string]any)["features"].(map[string]any)
	if got["pro"] != false {
		t.Fatalf("功能标记未更新: %v", got)
	}

	// 删除（含已吊销的）。
	if rec := doReq(t, s, "POST", "/admin/licenses/"+ids[1]+"/revoke", map[string]any{}, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("吊销失败: %d", rec.Code)
	}
	if rec := doReq(t, s, "DELETE", "/admin/licenses/"+ids[1], nil, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("删除应 200: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, s, "GET", "/admin/licenses", nil, adminHeaders())
	if decodeBody(t, rec)["total"] != float64(2) {
		t.Fatalf("删除后 total 应为 2: %s", rec.Body.String())
	}
	if rec := doReq(t, s, "DELETE", "/admin/licenses/"+ids[1], nil, adminHeaders()); rec.Code != http.StatusNotFound {
		t.Fatalf("删除不存在应 404: %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 9. 修改客户名/席位 + 解绑全部设备
// ---------------------------------------------------------------------------

func TestUpdateLicenseAndUnbindAll(t *testing.T) {
	s := testServer(t)
	lid, key := issueLicense(t, s, "OldCo", 30, 3)

	now := time.Now().Unix()
	for _, m := range []string{"m-1", "m-2"} {
		if rec := activate(t, s, key, m, now, freshNonce()); rec.Code != http.StatusOK {
			t.Fatalf("激活失败: %d %s", rec.Code, rec.Body.String())
		}
	}

	// 改名 + 扩容.
	rec := doReq(t, s, "POST", "/admin/licenses/"+lid+"/update",
		map[string]any{"customer": "NewCo", "seats": 5}, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("更新应 200: %d %s", rec.Code, rec.Body.String())
	}
	v := decodeBody(t, rec)["license"].(map[string]any)
	if v["customer"] != "NewCo" || v["seats"] != float64(5) || v["used"] != float64(2) {
		t.Fatalf("更新未生效: %v", v)
	}
	// 非法席位 / 空 body.
	if rec := doReq(t, s, "POST", "/admin/licenses/"+lid+"/update", map[string]any{"seats": 0}, adminHeaders()); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法席位应 400: %d", rec.Code)
	}
	if rec := doReq(t, s, "POST", "/admin/licenses/"+lid+"/update", map[string]any{}, adminHeaders()); rec.Code != http.StatusBadRequest {
		t.Fatalf("空更新体应 400: %d", rec.Code)
	}

	// 解绑全部设备.
	rec = doReq(t, s, "DELETE", "/admin/licenses/"+lid+"/machines", nil, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("解绑全部应 200: %d %s", rec.Code, rec.Body.String())
	}
	if decodeBody(t, rec)["unbound"] != float64(2) {
		t.Fatalf("应解绑 2 台: %s", rec.Body.String())
	}
	rec = doReq(t, s, "GET", "/admin/licenses/"+lid, nil, adminHeaders())
	if n := len(decodeBody(t, rec)["machines"].([]any)); n != 0 {
		t.Fatalf("解绑后应无设备: got %d", n)
	}
}

// ---------------------------------------------------------------------------
// 6. 管理 API 鉴权 + 踢设备后 refresh 拒绝(附带)
// ---------------------------------------------------------------------------

func TestAdminAuthAndKick(t *testing.T) {
	s := testServer(t)
	// 无鉴权应 401.
	rec := doReq(t, s, "POST", "/admin/licenses", map[string]any{"customer": "x", "days": 1, "seats": 1}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无鉴权应 401: got %d", rec.Code)
	}
	lid, key := issueLicense(t, s, "KickCo", 30, 2)
	now := time.Now().Unix()
	rec2 := activate(t, s, key, "m-kick", now, freshNonce())
	rt := decodeBody(t, rec2)["refresh_token"].(string)

	// 踢设备.
	del := doReq(t, s, "DELETE", "/admin/licenses/"+lid+"/machines/m-kick", nil, adminHeaders())
	if del.Code != http.StatusOK {
		t.Fatalf("踢设备失败: %d %s", del.Code, del.Body.String())
	}
	// 被踢后 refresh 拒绝.
	if rec := refresh(t, s, rt, now, freshNonce()); rec.Code != http.StatusForbidden {
		t.Fatalf("被踢后 refresh 应 403: got %d %s", rec.Code, rec.Body.String())
	}
}
