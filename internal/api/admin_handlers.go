package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/COCAINENINJA500/license-server/internal/adminui"
	"github.com/COCAINENINJA500/license-server/internal/store"
)

// requireAdmin 管理 API Bearer Key 鉴权(常数时间比较).
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := bearerToken(r)
		if got == "" || subtleCompare(got, s.AdminKey) != 1 {
			writeErr(w, unauthorized("管理鉴权失败"))
			return
		}
		next(w, r)
	}
}

// GET /admin/integration.md 实时生成"给其他 Coding Agent 的对接文档"并可下载.
func (s *Server) handleIntegrationDoc(w http.ResponseWriter, r *http.Request) {
	doc := adminui.IntegrationMarkdown(s.Signer.Pubkey(), s.Signer.AccessTTL, s.Signer.RefreshTTL)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="license-server-integration.md"`)
	_, _ = w.Write([]byte(doc))
}

// GET /admin/integration-prompt.txt 实时生成"AI 一键对接提示词":
// 任务要求 + 对接文档全文(内嵌真实公钥),复制给任意 Coding Agent 即可开工.
func (s *Server) handleIntegrationPrompt(w http.ResponseWriter, r *http.Request) {
	prompt := adminui.IntegrationPrompt(s.Signer.Pubkey(), s.Signer.AccessTTL, s.Signer.RefreshTTL)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(prompt))
}

type issueReq struct {
	Customer string          `json:"customer"`
	Days     int             `json:"days"`
	Seats    int             `json:"seats"`
	Features json.RawMessage `json:"features"`
}

// POST /admin/licenses 签发 license. license_key 明文仅此一次返回,服务端只存 SHA256.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	var req issueReq
	if herr := decodeJSON(r, &req); herr != nil {
		writeErr(w, herr)
		return
	}
	req.Customer = strings.TrimSpace(req.Customer)
	if req.Customer == "" || len(req.Customer) > 128 {
		writeErr(w, badRequest("customer 必填且不超过 128 字符"))
		return
	}
	if req.Days < 1 || req.Days > 3650 {
		writeErr(w, badRequest("days 取值范围 1~3650"))
		return
	}
	if req.Seats < 1 || req.Seats > 100000 {
		writeErr(w, badRequest("seats 取值范围 1~100000"))
		return
	}
	features := "{}"
	if len(req.Features) > 0 {
		var v any
		if err := json.Unmarshal(req.Features, &v); err != nil {
			writeErr(w, badRequest("features 必须是合法 JSON"))
			return
		}
		features = string(req.Features)
	}

	nowUnix := s.nowTime().Unix()
	ctx := r.Context()
	for tries := 0; tries < 3; tries++ {
		id, err := randomHex(8)
		if err != nil {
			writeInternal(w, err)
			return
		}
		keyBytes := make([]byte, 24)
		if _, err := rand.Read(keyBytes); err != nil {
			writeInternal(w, err)
			return
		}
		key := "LIC-" + hex.EncodeToString(keyBytes)
		l := &store.LicenseRow{
			ID:        id,
			KeyHash:   sha256Hex(key),
			Customer:  req.Customer,
			Seats:     req.Seats,
			ExpiresAt: nowUnix + int64(req.Days)*86400,
			Features:  features,
			Status:    "active",
			CreatedAt: nowUnix,
		}
		if err := s.Store.CreateLicense(ctx, l); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				continue // 极小概率碰撞,重试
			}
			writeInternal(w, err)
			return
		}
		log.Printf("签发 license: id=%s customer=%s seats=%d days=%d", id, req.Customer, req.Seats, req.Days)
		writeJSON(w, http.StatusCreated, map[string]any{
			"license_id":  id,
			"license_key": key, // 明文仅返回一次
			"customer":    req.Customer,
			"seats":       req.Seats,
			"expires_at":  l.ExpiresAt,
			"features":    json.RawMessage(features),
			"status":      "active",
		})
		return
	}
	writeInternal(w, fmt.Errorf("license id 碰撞重试耗尽"))
}

// GET /admin/licenses?q=&status=&page=&page_size=&sort=&order= 分页列出台账.
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page := atoiDefault(query.Get("page"), 1)
	if page < 1 {
		page = 1
	}
	pageSize := atoiDefault(query.Get("page_size"), 20)
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	dir := "DESC"
	if strings.EqualFold(query.Get("order"), "asc") {
		dir = "ASC"
	}

	licenses, total, err := s.Store.ListPage(r.Context(),
		strings.TrimSpace(query.Get("q")), strings.TrimSpace(query.Get("status")),
		page, pageSize, query.Get("sort"), dir, s.nowTime().Unix())
	if err != nil {
		writeInternal(w, err)
		return
	}
	totalPages := (total + pageSize - 1) / pageSize
	writeJSON(w, http.StatusOK, map[string]any{
		"licenses": licenses, "total": total,
		"page": page, "page_size": pageSize, "total_pages": totalPages,
	})
}

// GET /admin/stats 汇总统计.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st, err := s.Store.Stats(r.Context(), s.nowTime().Unix())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// GET /admin/licenses/{id} 查询单个台账(含设备列表).
func (s *Server) handleGetOne(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	l, err := s.Store.GetLicenseByID(ctx, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, notFound("license 不存在"))
		return
	}
	v, err := s.Store.ToView(ctx, l)
	if err != nil {
		writeInternal(w, err)
		return
	}
	machines, err := s.Store.ListMachines(ctx, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"license": v, "machines": machines})
}

// POST /admin/licenses/{id}/revoke 吊销(下次 refresh 生效,最长延迟 1 个 access 有效期).
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.Store.SetStatus(r.Context(), id, "revoked")
	if err != nil {
		writeInternal(w, err)
		return
	}
	if n == 0 {
		writeErr(w, notFound("license 不存在"))
		return
	}
	log.Printf("吊销 license: id=%s", id)
	writeJSON(w, http.StatusOK, map[string]string{"license_id": id, "status": "revoked"})
}

// POST /admin/licenses/{id}/restore 恢复已吊销的 license.
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.Store.SetStatus(r.Context(), id, "active")
	if err != nil {
		writeInternal(w, err)
		return
	}
	if n == 0 {
		writeErr(w, notFound("license 不存在"))
		return
	}
	log.Printf("恢复 license: id=%s", id)
	writeJSON(w, http.StatusOK, map[string]string{"license_id": id, "status": "active"})
}

// POST /admin/licenses/{id}/extend 续费: body {"add_days": 30}.
func (s *Server) handleExtend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		AddDays int `json:"add_days"`
	}
	if herr := decodeJSON(r, &req); herr != nil {
		writeErr(w, herr)
		return
	}
	if req.AddDays < 1 || req.AddDays > 3650 {
		writeErr(w, badRequest("add_days 取值范围 1~3650"))
		return
	}
	ctx := r.Context()
	l, err := s.Store.GetLicenseByID(ctx, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, notFound("license 不存在"))
		return
	}
	base := l.ExpiresAt
	if base < s.nowTime().Unix() {
		base = s.nowTime().Unix() // 已过期的从现在起续
	}
	newExp := base + int64(req.AddDays)*86400
	if err := s.Store.Extend(ctx, id, newExp); err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("续期 license: id=%s add_days=%d new_expires_at=%d", id, req.AddDays, newExp)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "expires_at": newExp})
}

// DELETE /admin/licenses/{id} 彻底删除 license 及其全部激活记录(不可恢复).
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.Store.DeleteLicense(r.Context(), id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if n == 0 {
		writeErr(w, notFound("license 不存在"))
		return
	}
	log.Printf("删除 license: id=%s", id)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "deleted": true})
}

// POST /admin/licenses/{id}/update 修改客户名 / 席位数.
// 下调 seats 到低于占用量时,超出部分的设备会在下次 refresh 被拒.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Customer *string `json:"customer"`
		Seats    *int    `json:"seats"`
	}
	if herr := decodeJSON(r, &req); herr != nil {
		writeErr(w, herr)
		return
	}
	if req.Customer == nil && req.Seats == nil {
		writeErr(w, badRequest("至少提供 customer 或 seats"))
		return
	}
	ctx := r.Context()
	l, err := s.Store.GetLicenseByID(ctx, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, notFound("license 不存在"))
		return
	}
	if req.Customer != nil {
		c := strings.TrimSpace(*req.Customer)
		if c == "" || len(c) > 128 {
			writeErr(w, badRequest("customer 必填且不超过 128 字符"))
			return
		}
		l.Customer = c
	}
	if req.Seats != nil {
		if *req.Seats < 1 || *req.Seats > 100000 {
			writeErr(w, badRequest("seats 取值范围 1~100000"))
			return
		}
		l.Seats = *req.Seats
	}
	if err := s.Store.UpdateLicense(ctx, id, l.Customer, l.Seats); err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("更新 license: id=%s customer=%s seats=%d", id, l.Customer, l.Seats)
	v, err := s.Store.ToView(ctx, l)
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"license": v})
}

// DELETE /admin/licenses/{id}/machines 解绑该 license 的全部设备.
func (s *Server) handleUnbindAll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	l, err := s.Store.GetLicenseByID(ctx, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if l == nil {
		writeErr(w, notFound("license 不存在"))
		return
	}
	n, err := s.Store.UnbindAll(ctx, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("解绑全部设备: license=%s unbound=%d", id, n)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "unbound": n})
}

// POST /admin/licenses/{id}/features 修改功能标记(客户端下次 refresh 生效).
func (s *Server) handleUpdateFeatures(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Features json.RawMessage `json:"features"`
	}
	if herr := decodeJSON(r, &req); herr != nil {
		writeErr(w, herr)
		return
	}
	if len(req.Features) == 0 {
		writeErr(w, badRequest("features 必填"))
		return
	}
	var v any
	if err := json.Unmarshal(req.Features, &v); err != nil {
		writeErr(w, badRequest("features 必须是合法 JSON"))
		return
	}
	if err := s.Store.UpdateFeatures(r.Context(), id, string(req.Features)); err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("更新功能标记: id=%s", id)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "features": json.RawMessage(req.Features)})
}

// DELETE /admin/licenses/{id}/machines/{mhash} 踢掉一台设备,释放席位.
func (s *Server) handleKick(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	mhash := r.PathValue("mhash")
	n, err := s.Store.Kick(r.Context(), id, mhash)
	if err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("踢设备: license=%s machine=%.12s... deleted=%d", id, mhash, n)
	writeJSON(w, http.StatusOK, map[string]any{"license_id": id, "deleted": n > 0})
}
