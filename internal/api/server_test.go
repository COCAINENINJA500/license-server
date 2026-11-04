package api

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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/COCAINENINJA500/license-server/internal/licensing"
	"github.com/COCAINENINJA500/license-server/internal/store"
)

// ---------------------------------------------------------------------------
// 测试脚手架
// ---------------------------------------------------------------------------

var nonceSeq atomic.Int64

type testEnv struct {
	s  *Server
	db *sql.DB
}

func testServer(t *testing.T) *testEnv {
	t.Helper()
	return testServerWithRate(t, 0, 0)
}

// testServerWithRate 允许打开限流(rps<=0 关闭).
func testServerWithRate(t *testing.T, rps float64, burst int) *testEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(db)
	signer := licensing.NewSigner(priv, 24*time.Hour, 30*24*time.Hour)
	nonces := licensing.NewNonceStore(licensing.NonceRetention, nil)
	s := NewServer(st, signer, "test-admin-key", nonces, "test", rps, burst)
	return &testEnv{s: s, db: db}
}

func doReq(t *testing.T, env *testEnv, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
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
	env.s.Routes().ServeHTTP(rec, req)
	return rec
}

func adminHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer test-admin-key"}
}

func freshNonce() string {
	return fmt.Sprintf("test-nonce-%d-%d", time.Now().UnixNano(), nonceSeq.Add(1))
}

// issueLicense 经管理 API 签发,返回 license_id 与明文 license_key.
// 功能标记只来自产品模板: 先创建带标准 features 的产品,再按 product_id 签发.
func issueLicense(t *testing.T, env *testEnv, customer string, days, seats int) (string, string) {
	t.Helper()
	pd := doReq(t, env, "POST", "/admin/products", map[string]any{
		"name":     fmt.Sprintf("P-%s-%d", customer, time.Now().UnixNano()),
		"features": map[string]any{"pro": true, "level": "vip"},
	}, adminHeaders())
	if pd.Code != http.StatusCreated {
		t.Fatalf("创建产品失败: code=%d body=%s", pd.Code, pd.Body.String())
	}
	var pout struct {
		ProductID string `json:"product_id"`
	}
	if err := json.Unmarshal(pd.Body.Bytes(), &pout); err != nil {
		t.Fatal(err)
	}
	rec := doReq(t, env, "POST", "/admin/licenses", map[string]any{
		"customer": customer, "product_id": pout.ProductID, "days": days, "seats": seats,
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

func activate(t *testing.T, env *testEnv, key, machine string, ts int64, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	return doReq(t, env, "POST", "/v1/activate", map[string]any{
		"license_key": key, "machine_hash": machine,
		"timestamp": ts, "nonce": nonce,
	}, nil)
}

func refresh(t *testing.T, env *testEnv, refreshToken string, ts int64, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	return doReq(t, env, "POST", "/v1/refresh", map[string]any{
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
	env := testServer(t)
	lid, key := issueLicense(t, env, "Acme", 30, 2)

	rec := activate(t, env, key, "machine-aaa", time.Now().Unix(), freshNonce())
	if rec.Code != http.StatusOK {
		t.Fatalf("激活失败: code=%d body=%s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("缺少 access_token: %s", rec.Body.String())
	}

	// 客户端侧:用公钥本地验签.
	claims, err := env.s.Signer.Parse(access)
	if err != nil {
		t.Fatalf("access JWT 验签失败: %v", err)
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
	rec2 := doReq(t, env, "GET", "/v1/status", nil, map[string]string{"Authorization": "Bearer " + access})
	if rec2.Code != http.StatusOK {
		t.Fatalf("status 失败: code=%d body=%s", rec2.Code, rec2.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 2. 超席位拒绝(同机幂等不占新席位)
// ---------------------------------------------------------------------------

func TestSeatsExceeded(t *testing.T) {
	env := testServer(t)
	_, key := issueLicense(t, env, "SeatsCo", 30, 1)

	now := time.Now().Unix()
	if rec := activate(t, env, key, "m-1", now, freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("首台激活应成功: %d %s", rec.Code, rec.Body.String())
	}
	// 同一机器重复激活:幂等成功,不占新席位.
	if rec := activate(t, env, key, "m-1", now, freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("同机重复激活应幂等成功: %d %s", rec.Code, rec.Body.String())
	}
	// 第二台:403.
	rec := activate(t, env, key, "m-2", now, freshNonce())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("超席位应 403: got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 3. 吊销后 refresh 拒绝 + 激活同步拒绝
// ---------------------------------------------------------------------------

func TestRefreshRejectedAfterRevoke(t *testing.T) {
	env := testServer(t)
	lid, key := issueLicense(t, env, "RevokeCo", 30, 2)

	now := time.Now().Unix()
	rec := activate(t, env, key, "m-1", now, freshNonce())
	if rec.Code != http.StatusOK {
		t.Fatalf("激活失败: %d %s", rec.Code, rec.Body.String())
	}
	rt := decodeBody(t, rec)["refresh_token"].(string)

	// 吊销前 refresh 正常.
	if rec := refresh(t, env, rt, now, freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("吊销前 refresh 应成功: %d %s", rec.Code, rec.Body.String())
	}

	// 管理 API 吊销.
	rec2 := doReq(t, env, "POST", "/admin/licenses/"+lid+"/revoke", map[string]any{}, adminHeaders())
	if rec2.Code != http.StatusOK {
		t.Fatalf("吊销失败: %d %s", rec2.Code, rec2.Body.String())
	}

	// 吊销后 refresh 必须拒绝.
	if rec := refresh(t, env, rt, now, freshNonce()); rec.Code != http.StatusForbidden {
		t.Fatalf("吊销后 refresh 应 403: got %d %s", rec.Code, rec.Body.String())
	}
	// 吊销后新激活也拒绝.
	if rec := activate(t, env, key, "m-2", now, freshNonce()); rec.Code != http.StatusForbidden {
		t.Fatalf("吊销后激活应 403: got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 4. 过期后 refresh 拒绝(续费卡点) + 续期后恢复
// ---------------------------------------------------------------------------

func TestRefreshRejectedAfterExpiry(t *testing.T) {
	env := testServer(t)
	_, key := issueLicense(t, env, "ExpireCo", 30, 2)

	now := time.Now().Unix()
	rec := activate(t, env, key, "m-1", now, freshNonce())
	if rec.Code != http.StatusOK {
		t.Fatalf("激活失败: %d %s", rec.Code, rec.Body.String())
	}
	rt := decodeBody(t, rec)["refresh_token"].(string)

	// 直接把到期时间改到过去,模拟过期.
	if _, err := env.db.Exec(`UPDATE licenses SET expires_at=? WHERE key_hash=?`, now-10, sha256Hex(key)); err != nil {
		t.Fatal(err)
	}
	if rec := refresh(t, env, rt, now, freshNonce()); rec.Code != http.StatusForbidden {
		t.Fatalf("过期后 refresh 应 403: got %d %s", rec.Code, rec.Body.String())
	}

	// 续期 30 天后,当前有效的 refresh 应恢复可用.
	if _, err := env.db.Exec(`UPDATE licenses SET expires_at=? WHERE key_hash=?`, now+30*86400, sha256Hex(key)); err != nil {
		t.Fatal(err)
	}
	if rec := refresh(t, env, rt, now, freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("续期后 refresh 应恢复成功: %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 5. 重放拒绝: nonce 复用 + timestamp 超窗
// ---------------------------------------------------------------------------

func TestReplayRejected(t *testing.T) {
	env := testServer(t)
	_, key := issueLicense(t, env, "ReplayCo", 30, 5)

	now := time.Now().Unix()
	nonce := freshNonce()
	body := map[string]any{"license_key": key, "machine_hash": "m-1", "timestamp": now, "nonce": nonce}
	if rec := doReq(t, env, "POST", "/v1/activate", body, nil); rec.Code != http.StatusOK {
		t.Fatalf("首次激活失败: %d %s", rec.Code, rec.Body.String())
	}
	// 同一 nonce 重放 -> 409.
	if rec := doReq(t, env, "POST", "/v1/activate", body, nil); rec.Code != http.StatusConflict {
		t.Fatalf("重放 nonce 应 409: got %d %s", rec.Code, rec.Body.String())
	}
	// timestamp 超出 ±5 分钟窗口 -> 400.
	stale := map[string]any{"license_key": key, "machine_hash": "m-2", "timestamp": now - 600, "nonce": freshNonce()}
	if rec := doReq(t, env, "POST", "/v1/activate", stale, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("过期 timestamp 应 400: got %d %s", rec.Code, rec.Body.String())
	}
	// refresh 的重放同样拒绝.
	rec := activate(t, env, key, "m-3", now, freshNonce())
	rt := decodeBody(t, rec)["refresh_token"].(string)
	rbody := map[string]any{"refresh_token": rt, "timestamp": now, "nonce": freshNonce()}
	if rec := doReq(t, env, "POST", "/v1/refresh", rbody, nil); rec.Code != http.StatusOK {
		t.Fatalf("首次 refresh 失败: %d %s", rec.Code, rec.Body.String())
	}
	// 复用同一 nonce 再次 refresh.
	if rec := doReq(t, env, "POST", "/v1/refresh", rbody, nil); rec.Code != http.StatusConflict {
		t.Fatalf("refresh 重放应 409: got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 5.5 refresh 轮换重用检测:被轮换掉的旧 refresh 立即作废
// ---------------------------------------------------------------------------

func TestRefreshReuseRejected(t *testing.T) {
	env := testServer(t)
	_, key := issueLicense(t, env, "ReuseCo", 30, 2)

	now := time.Now().Unix()
	rec := activate(t, env, key, "m-1", now, freshNonce())
	if rec.Code != http.StatusOK {
		t.Fatalf("激活失败: %d %s", rec.Code, rec.Body.String())
	}
	rt0 := decodeBody(t, rec)["refresh_token"].(string)

	// 第一次 refresh: 成功并轮换出新 token.
	rec = refresh(t, env, rt0, now, freshNonce())
	if rec.Code != http.StatusOK {
		t.Fatalf("首次 refresh 应成功: %d %s", rec.Code, rec.Body.String())
	}
	rt1 := decodeBody(t, rec)["refresh_token"].(string)

	// 重用被轮换掉的 rt0 -> 401(而非 403/409).
	if rec := refresh(t, env, rt0, now, freshNonce()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("重用旧 refresh 应 401: got %d %s", rec.Code, rec.Body.String())
	}
	// 当前有效的 rt1 仍可用.
	if rec := refresh(t, env, rt1, now, freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("当前 refresh 应可用: %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 6. 管理 API 鉴权 + 踢设备后 refresh 拒绝
// ---------------------------------------------------------------------------

func TestAdminAuthAndKick(t *testing.T) {
	env := testServer(t)
	// 无鉴权应 401.
	rec := doReq(t, env, "POST", "/admin/licenses", map[string]any{"customer": "x", "days": 1, "seats": 1}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无鉴权应 401: got %d", rec.Code)
	}
	lid, key := issueLicense(t, env, "KickCo", 30, 2)
	now := time.Now().Unix()
	rec2 := activate(t, env, key, "m-kick", now, freshNonce())
	rt := decodeBody(t, rec2)["refresh_token"].(string)

	// 踢设备.
	del := doReq(t, env, "DELETE", "/admin/licenses/"+lid+"/machines/m-kick", nil, adminHeaders())
	if del.Code != http.StatusOK {
		t.Fatalf("踢设备失败: %d %s", del.Code, del.Body.String())
	}
	// 被踢后 refresh 拒绝.
	if rec := refresh(t, env, rt, now, freshNonce()); rec.Code != http.StatusForbidden {
		t.Fatalf("被踢后 refresh 应 403: got %d %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// 7. 内嵌管理台可访问
// ---------------------------------------------------------------------------

func TestAdminUI(t *testing.T) {
	env := testServer(t)
	for _, p := range []string{"/admin", "/admin/"} {
		rec := doReq(t, env, "GET", p, nil, nil)
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
	issueLicense(t, env, "UI客户", 30, 2)
	rec := doReq(t, env, "GET", "/admin/licenses", nil, adminHeaders())
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
	env := testServer(t)
	ids := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		lid, _ := issueLicense(t, env, fmt.Sprintf("Co%d", i), 30, 2)
		ids = append(ids, lid)
	}

	// 分页:page_size=2 应有 2 条、total=3、total_pages=2.
	rec := doReq(t, env, "GET", "/admin/licenses?page=1&page_size=2", nil, adminHeaders())
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

	// 统计.
	rec = doReq(t, env, "GET", "/admin/stats", nil, adminHeaders())
	st := decodeBody(t, rec)
	if st["total"] != float64(3) || st["active"] != float64(3) {
		t.Fatalf("统计不符: %v", st)
	}

	// 编辑功能标记.
	rec = doReq(t, env, "POST", "/admin/licenses/"+ids[0]+"/features",
		map[string]any{"features": map[string]any{"pro": false}}, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("编辑功能标记应 200: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, env, "GET", "/admin/licenses/"+ids[0], nil, adminHeaders())
	got := decodeBody(t, rec)["license"].(map[string]any)["features"].(map[string]any)
	if got["pro"] != false {
		t.Fatalf("功能标记未更新: %v", got)
	}

	// 删除(含已吊销的).
	if rec := doReq(t, env, "POST", "/admin/licenses/"+ids[1]+"/revoke", map[string]any{}, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("吊销失败: %d", rec.Code)
	}
	if rec := doReq(t, env, "DELETE", "/admin/licenses/"+ids[1], nil, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("删除应 200: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, env, "GET", "/admin/licenses", nil, adminHeaders())
	if decodeBody(t, rec)["total"] != float64(2) {
		t.Fatalf("删除后 total 应为 2: %s", rec.Body.String())
	}
	if rec := doReq(t, env, "DELETE", "/admin/licenses/"+ids[1], nil, adminHeaders()); rec.Code != http.StatusNotFound {
		t.Fatalf("删除不存在应 404: %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 9. 修改客户名/席位 + 解绑全部设备
// ---------------------------------------------------------------------------

func TestUpdateLicenseAndUnbindAll(t *testing.T) {
	env := testServer(t)
	lid, key := issueLicense(t, env, "OldCo", 30, 3)

	now := time.Now().Unix()
	for _, m := range []string{"m-1", "m-2"} {
		if rec := activate(t, env, key, m, now, freshNonce()); rec.Code != http.StatusOK {
			t.Fatalf("激活失败: %d %s", rec.Code, rec.Body.String())
		}
	}

	// 改名 + 扩容.
	rec := doReq(t, env, "POST", "/admin/licenses/"+lid+"/update",
		map[string]any{"customer": "NewCo", "seats": 5}, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("更新应 200: %d %s", rec.Code, rec.Body.String())
	}
	v := decodeBody(t, rec)["license"].(map[string]any)
	if v["customer"] != "NewCo" || v["seats"] != float64(5) || v["used"] != float64(2) {
		t.Fatalf("更新未生效: %v", v)
	}
	// 非法席位 / 空 body.
	if rec := doReq(t, env, "POST", "/admin/licenses/"+lid+"/update", map[string]any{"seats": 0}, adminHeaders()); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法席位应 400: %d", rec.Code)
	}
	if rec := doReq(t, env, "POST", "/admin/licenses/"+lid+"/update", map[string]any{}, adminHeaders()); rec.Code != http.StatusBadRequest {
		t.Fatalf("空更新体应 400: %d", rec.Code)
	}

	// 解绑全部设备.
	rec = doReq(t, env, "DELETE", "/admin/licenses/"+lid+"/machines", nil, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("解绑全部应 200: %d %s", rec.Code, rec.Body.String())
	}
	if decodeBody(t, rec)["unbound"] != float64(2) {
		t.Fatalf("应解绑 2 台: %s", rec.Body.String())
	}
	rec = doReq(t, env, "GET", "/admin/licenses/"+lid, nil, adminHeaders())
	if n := len(decodeBody(t, rec)["machines"].([]any)); n != 0 {
		t.Fatalf("解绑后应无设备: got %d", n)
	}
}

// ---------------------------------------------------------------------------
// 10. status 明文 key 模式(只读台账摘要)
// ---------------------------------------------------------------------------

func TestStatusKeyMode(t *testing.T) {
	env := testServer(t)
	_, key := issueLicense(t, env, "StatusCo", 30, 3)

	// 未激活时 bound=false.
	rec := doReq(t, env, "GET", "/v1/status?license_key="+key+"&machine_hash=m-x", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status 应 200: %d %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	if out["valid"] != true || out["bound"] != false {
		t.Fatalf("status 字段不符: %v", out)
	}
	// 激活后 bound=true.
	if rec := activate(t, env, key, "m-x", time.Now().Unix(), freshNonce()); rec.Code != http.StatusOK {
		t.Fatalf("激活失败: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, env, "GET", "/v1/status?license_key="+key+"&machine_hash=m-x", nil, nil)
	out = decodeBody(t, rec)
	if out["bound"] != true || out["used"] != float64(1) {
		t.Fatalf("激活后 status 不符: %v", out)
	}
	// 无效 key.
	if rec := doReq(t, env, "GET", "/v1/status?license_key=LIC-deadbeef", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无效 key 应 401: got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 11. 续期 / 恢复管理端点
// ---------------------------------------------------------------------------

func TestExtendAndRestore(t *testing.T) {
	env := testServer(t)
	lid, _ := issueLicense(t, env, "ExtCo", 30, 1)

	// 续期 30 天:到期时间应显著后移.
	rec := doReq(t, env, "POST", "/admin/licenses/"+lid+"/extend", map[string]any{"add_days": 30}, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("续期应 200: %d %s", rec.Code, rec.Body.String())
	}
	newExp := int64(decodeBody(t, rec)["expires_at"].(float64))
	if newExp < time.Now().Unix()+59*86400 {
		t.Fatalf("续期后到期时间异常: %d", newExp)
	}
	// 非法天数.
	if rec := doReq(t, env, "POST", "/admin/licenses/"+lid+"/extend", map[string]any{"add_days": 0}, adminHeaders()); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法天数应 400: %d", rec.Code)
	}
	// 恢复未吊销的(幂等 200)→ 吊销 → 恢复.
	if rec := doReq(t, env, "POST", "/admin/licenses/"+lid+"/restore", map[string]any{}, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("恢复应 200: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, env, "POST", "/admin/licenses/"+lid+"/revoke", map[string]any{}, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("吊销应 200: %d", rec.Code)
	}
	if rec := doReq(t, env, "POST", "/admin/licenses/"+lid+"/restore", map[string]any{}, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("恢复应 200: %d %s", rec.Code, rec.Body.String())
	}
	rec = doReq(t, env, "GET", "/admin/licenses/"+lid, nil, adminHeaders())
	if st := decodeBody(t, rec)["license"].(map[string]any)["status"]; st != "active" {
		t.Fatalf("恢复后状态应 active: %v", st)
	}
}

// ---------------------------------------------------------------------------
// 12. 对接文档:实时生成,内嵌真实公钥
// ---------------------------------------------------------------------------

func TestIntegrationDoc(t *testing.T) {
	env := testServer(t)
	// 未带 Admin Key 应 401.
	if rec := doReq(t, env, "GET", "/admin/integration.md", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无鉴权应 401: got %d", rec.Code)
	}
	rec := doReq(t, env, "GET", "/admin/integration.md", nil, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("对接文档应 200: %d %s", rec.Code, rec.Body.String())
	}
	// 文档中的公钥应与 /v1/pubkey 一致.
	pub := doReq(t, env, "GET", "/v1/pubkey", nil, nil)
	b64 := decodeBody(t, pub)["pubkey_b64"].(string)
	if !bytes.Contains(rec.Body.Bytes(), []byte(b64)) {
		t.Fatalf("对接文档应内嵌真实公钥 %s", b64)
	}
}

// ---------------------------------------------------------------------------
// 13. AI 对接提示词: 鉴权 + 内嵌文档全文与真实公钥
// ---------------------------------------------------------------------------

func TestIntegrationPrompt(t *testing.T) {
	env := testServer(t)
	if rec := doReq(t, env, "GET", "/admin/integration-prompt.txt", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无鉴权应 401: got %d", rec.Code)
	}
	rec := doReq(t, env, "GET", "/admin/integration-prompt.txt", nil, adminHeaders())
	if rec.Code != http.StatusOK {
		t.Fatalf("提示词应 200: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type 应为 text/plain: %q", ct)
	}
	body := rec.Body.String()
	// 任务头 + 文档全文 + 真实公钥,缺一不可.
	for _, marker := range []string{"实现 License 客户端授权模块", "对接文档", "machine_hash", "EdDSA"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("提示词缺少关键内容: %q", marker)
		}
	}
	pub := decodeBody(t, doReq(t, env, "GET", "/v1/pubkey", nil, nil))["pubkey_b64"].(string)
	if !strings.Contains(body, pub) {
		t.Fatalf("提示词应内嵌真实公钥 %s", pub)
	}
	// 提示词应是文档的严格超集(任务头 + 全文).
	doc := doReq(t, env, "GET", "/admin/integration.md", nil, adminHeaders()).Body.String()
	if !strings.Contains(body, doc) {
		t.Fatalf("提示词应完整包含对接文档全文")
	}
}

// ---------------------------------------------------------------------------
// 14. 产品目录: CRUD + 签发按产品带入默认值
// ---------------------------------------------------------------------------

func TestProducts(t *testing.T) {
	env := testServer(t)
	// create
	rec := doReq(t, env, "POST", "/admin/products", map[string]any{
		"name": "Pro 版", "features": map[string]any{"pro": true, "level": "vip"},
		"default_days": 90, "default_seats": 3,
	}, adminHeaders())
	if rec.Code != http.StatusCreated {
		t.Fatalf("创建产品应 201: %d %s", rec.Code, rec.Body.String())
	}
	pid := decodeBody(t, rec)["product_id"].(string)

	// 重名冲突 409
	if rec := doReq(t, env, "POST", "/admin/products", map[string]any{"name": "Pro 版"}, adminHeaders()); rec.Code != http.StatusConflict {
		t.Fatalf("重名应 409: got %d", rec.Code)
	}

	// 列表
	if rec := doReq(t, env, "GET", "/admin/products", nil, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("列表应 200: %d", rec.Code)
	}

	// update
	if rec := doReq(t, env, "POST", "/admin/products/"+pid+"/update", map[string]any{"name": "Pro Max", "default_days": 180}, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("更新应 200: %d %s", rec.Code, rec.Body.String())
	}

	// 签发: 只带 product_id → 全部取产品默认值
	rec = doReq(t, env, "POST", "/admin/licenses", map[string]any{"customer": "Acme", "product_id": pid}, adminHeaders())
	if rec.Code != http.StatusCreated {
		t.Fatalf("按产品签发应 201: %d %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	if out["seats"] != float64(3) {
		t.Fatalf("席位应取产品默认 3: %v", out["seats"])
	}
	if feat := out["features"].(map[string]any); feat["pro"] != true {
		t.Fatalf("features 应取产品模板: %v", out["features"])
	}
	lid := out["license_id"].(string)

	// 到期时间 = +180 天
	rec = doReq(t, env, "GET", "/admin/licenses/"+lid, nil, adminHeaders())
	exp := int64(decodeBody(t, rec)["license"].(map[string]any)["expires_at"].(float64))
	if exp < time.Now().Unix()+178*86400 {
		t.Fatalf("天数应取产品默认 180: %d", exp)
	}

	// 签发: 功能标记只取产品模板(签发接口不接受 features,按单微调走 /features 端点)
	rec = doReq(t, env, "POST", "/admin/licenses", map[string]any{
		"customer": "Acme2", "product_id": pid,
	}, adminHeaders())
	if rec.Code != http.StatusCreated {
		t.Fatalf("按产品签发应 201: %d %s", rec.Code, rec.Body.String())
	}
	if feat := decodeBody(t, rec)["features"].(map[string]any); feat["pro"] != true {
		t.Fatalf("features 应取产品模板: %v", feat)
	}

	// 不存在的 product
	if rec := doReq(t, env, "POST", "/admin/licenses", map[string]any{"customer": "X", "product_id": "deadbeef"}, adminHeaders()); rec.Code != http.StatusBadRequest {
		t.Fatalf("product 不存在应 400: got %d", rec.Code)
	}

	// delete + 重复删除 404
	if rec := doReq(t, env, "DELETE", "/admin/products/"+pid, nil, adminHeaders()); rec.Code != http.StatusOK {
		t.Fatalf("删除应 200: %d", rec.Code)
	}
	if rec := doReq(t, env, "DELETE", "/admin/products/"+pid, nil, adminHeaders()); rec.Code != http.StatusNotFound {
		t.Fatalf("重复删除应 404: %d", rec.Code)
	}
}
