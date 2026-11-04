package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/COCAINENINJA500/ed25519-license-server/internal/licensing"
	"github.com/COCAINENINJA500/ed25519-license-server/internal/store"
)

// checkUsable 吊销与续费的统一卡点:状态必须 active 且未过期.
func checkUsable(l *store.LicenseRow, nowUnix int64) *httpError {
	if l.Status != "active" {
		return forbidden("license 已吊销")
	}
	if nowUnix >= l.ExpiresAt {
		return forbidden("license 已过期")
	}
	return nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// nonceHTTPError 把防重放错误映射为 HTTP 状态码(nil = 通过).
func nonceHTTPError(err error) *httpError {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, licensing.ErrReplay):
		return &httpError{Code: http.StatusConflict, Msg: err.Error()}
	case errors.Is(err, licensing.ErrNonceFormat), errors.Is(err, licensing.ErrTimestampStale):
		return badRequest(err.Error())
	default:
		return badRequest(err.Error())
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// GET /healthz 探活. 版本号由 -ldflags -X main.version 注入.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.Version})
}

// GET /v1/pubkey 返回 Ed25519 公钥(客户端抓取后嵌入发布,用于本地验签).
func (s *Server) handlePubkey(w http.ResponseWriter, r *http.Request) {
	pub := s.Signer.Pubkey()
	writeJSON(w, http.StatusOK, map[string]string{
		"alg":        "EdDSA",
		"pubkey_b64": base64.StdEncoding.EncodeToString(pub),
		"pubkey_hex": hex.EncodeToString(pub),
	})
}

type activateReq struct {
	LicenseKey  string `json:"license_key"`
	MachineHash string `json:"machine_hash"`
	Timestamp   int64  `json:"timestamp"`
	Nonce       string `json:"nonce"`
}

// POST /v1/activate 激活设备并下发 access + refresh.
func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	var req activateReq
	if herr := decodeJSON(r, &req); herr != nil {
		writeErr(w, herr)
		return
	}
	if herr := nonceHTTPError(s.Nonces.CheckAndRecord(req.Timestamp, req.Nonce)); herr != nil {
		writeErr(w, herr)
		return
	}
	req.LicenseKey = strings.TrimSpace(req.LicenseKey)
	req.MachineHash = strings.TrimSpace(req.MachineHash)
	if req.LicenseKey == "" || req.MachineHash == "" || len(req.MachineHash) > 128 {
		writeErr(w, badRequest("license_key 与 machine_hash 必填(machine_hash 建议为设备标识的 SHA256 hex)"))
		return
	}
	ctx := r.Context()
	l, err := s.Store.GetLicenseByHash(ctx, sha256Hex(req.LicenseKey))
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, unauthorized("license_key 无效"))
		return
	}
	nowUnix := s.nowTime().Unix()
	if herr := checkUsable(l, nowUnix); herr != nil {
		writeErr(w, herr)
		return
	}
	// 席位控制: 同一 machine 重复激活幂等,不占新席位.
	exists, err := s.Store.ActivationExists(ctx, l.ID, req.MachineHash)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if exists {
		if err := s.Store.TouchActivation(ctx, l.ID, req.MachineHash, nowUnix); err != nil {
			writeInternal(w, err)
			return
		}
	} else {
		used, err := s.Store.CountActivations(ctx, l.ID)
		if err != nil {
			writeInternal(w, err)
			return
		}
		if used >= l.Seats {
			writeErr(w, forbidden("席位已满"))
			return
		}
		if err := s.Store.InsertActivation(ctx, l.ID, req.MachineHash, nowUnix); err != nil {
			// 并发窗口下唯一键冲突等价于席位竞争失败.
			if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "PRIMARY") {
				writeErr(w, forbidden("席位已满"))
				return
			}
			writeInternal(w, err)
			return
		}
	}
	access, accessExp, err := s.Signer.SignAccess(l.ID, req.MachineHash, json.RawMessage(l.Features), l.ExpiresAt)
	if err != nil {
		writeInternal(w, err)
		return
	}
	refresh, refreshExp, jti, err := s.Signer.SignRefresh(l.ID, req.MachineHash)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if err := s.Store.SetActivationRefresh(ctx, l.ID, req.MachineHash, jti, nowUnix); err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":       access,
		"refresh_token":      refresh,
		"expires_in":         accessExp - nowUnix,
		"access_expires_at":  accessExp,
		"refresh_expires_at": refreshExp,
		"license_expires_at": l.ExpiresAt,
		"features":           json.RawMessage(l.Features),
		"license_id":         l.ID,
	})
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
	Timestamp    int64  `json:"timestamp"`
	Nonce        string `json:"nonce"`
}

// POST /v1/refresh 用 refresh 换新 access.
// 吊销 / 过期 / 超席位 / 被踢 / 旧 refresh 重用 均在此拒绝.
// 每次 refresh 轮换 refresh token;旧 token 的 jti 与库中不符即判为重用,立即 401.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req refreshReq
	if herr := decodeJSON(r, &req); herr != nil {
		writeErr(w, herr)
		return
	}
	if herr := nonceHTTPError(s.Nonces.CheckAndRecord(req.Timestamp, req.Nonce)); herr != nil {
		writeErr(w, herr)
		return
	}
	if req.RefreshToken == "" {
		writeErr(w, badRequest("refresh_token 必填"))
		return
	}
	claims, err := s.Signer.Parse(req.RefreshToken)
	if err != nil {
		writeErr(w, unauthorized(err.Error()))
		return
	}
	if claims["typ"] != "refresh" {
		writeErr(w, unauthorized("不是合法的 refresh token"))
		return
	}
	lid, _ := claims["sub"].(string)
	mhash, _ := claims["mhash"].(string)
	jti, _ := claims["jti"].(string)
	if lid == "" || mhash == "" || jti == "" {
		writeErr(w, unauthorized("refresh token 内容非法"))
		return
	}
	ctx := r.Context()
	l, err := s.Store.GetLicenseByID(ctx, lid)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, forbidden("license 不存在或已吊销"))
		return
	}
	nowUnix := s.nowTime().Unix()
	if herr := checkUsable(l, nowUnix); herr != nil {
		writeErr(w, herr) // 吊销 / 过期在此拒绝
		return
	}
	// 被踢检查: 设备行不在即拒绝.
	curJTI, err := s.Store.CurrentRefreshJTI(ctx, lid, mhash)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if curJTI == nil {
		writeErr(w, forbidden("设备已被解绑"))
		return
	}
	// 轮换重用检测: 库中的 jti 才是当前有效的 refresh;拿被轮换掉的旧 token = 疑似被盗,立即作废.
	if *curJTI != jti {
		writeErr(w, unauthorized("refresh token 已失效(已被轮换)"))
		return
	}
	// 超席位检查(如管理员下调 seats):总数超限即拒绝.
	used, err := s.Store.CountActivations(ctx, lid)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if used > l.Seats {
		writeErr(w, forbidden("席位已满(管理员下调了席位数)"))
		return
	}
	access, accessExp, err := s.Signer.SignAccess(l.ID, mhash, json.RawMessage(l.Features), l.ExpiresAt)
	if err != nil {
		writeInternal(w, err)
		return
	}
	// 轮换 refresh: 每次 refresh 同时下发新的 refresh token,并更新库中 jti.
	newRefresh, refreshExp, newJTI, err := s.Signer.SignRefresh(l.ID, mhash)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if err := s.Store.SetActivationRefresh(ctx, lid, mhash, newJTI, nowUnix); err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":       access,
		"refresh_token":      newRefresh,
		"expires_in":         accessExp - nowUnix,
		"access_expires_at":  accessExp,
		"refresh_expires_at": refreshExp,
		"license_expires_at": l.ExpiresAt,
		"features":           json.RawMessage(l.Features),
		"license_id":         l.ID,
	})
}

// GET /v1/status 查询剩余有效期.
// 两种用法:
//  1. Authorization: Bearer <access_token> -> 返回 token/license 到期信息(推荐,不暴露 license_key)
//  2. ?license_key=...&machine_hash=...   -> 返回台账摘要(只读,无需 nonce)
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if tok := bearerToken(r); tok != "" {
		claims, err := s.Signer.Parse(tok)
		if err != nil {
			writeErr(w, unauthorized(err.Error()))
			return
		}
		expF, _ := claims["exp"].(float64)
		licExpF, _ := claims["lic_exp"].(float64)
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":              true,
			"license_id":         claims["sub"],
			"machine_hash":       claims["mhash"],
			"token_expires_at":   int64(expF),
			"license_expires_at": int64(licExpF),
			"features":           claims["features"],
		})
		return
	}
	key := strings.TrimSpace(r.URL.Query().Get("license_key"))
	mhash := strings.TrimSpace(r.URL.Query().Get("machine_hash"))
	if key == "" {
		writeErr(w, badRequest("缺少 license_key(或改用 Authorization: Bearer <access_token>)"))
		return
	}
	ctx := r.Context()
	l, err := s.Store.GetLicenseByHash(ctx, sha256Hex(key))
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, unauthorized("license_key 无效"))
		return
	}
	used, err := s.Store.CountActivations(ctx, l.ID)
	if err != nil {
		writeInternal(w, err)
		return
	}
	nowUnix := s.nowTime().Unix()
	valid := l.Status == "active" && nowUnix < l.ExpiresAt
	bound := false
	if mhash != "" {
		if ok, err := s.Store.ActivationExists(ctx, l.ID, mhash); err == nil && ok {
			bound = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":             valid,
		"license_id":        l.ID,
		"status":            l.Status,
		"expires_at":        l.ExpiresAt,
		"remaining_seconds": max(l.ExpiresAt-nowUnix, 0),
		"seats":             l.Seats,
		"used":              used,
		"bound":             bound,
		"features":          json.RawMessage(l.Features),
	})
}
