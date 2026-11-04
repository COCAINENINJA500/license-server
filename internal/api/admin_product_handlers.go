package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/COCAINENINJA500/license-server/internal/store"
)

// 产品目录: 签发 license 时按产品带入默认 features / 天数 / 席位.
// 产品是签发侧模板;license 持有签发时的 features 快照,后续产品变更不影响已发 license.

type productReq struct {
	Name         string          `json:"name"`
	Features     json.RawMessage `json:"features"`
	DefaultDays  *int            `json:"default_days"`
	DefaultSeats *int            `json:"default_seats"`
}

func (s *Server) validateProductReq(req *productReq) (*store.ProductRow, *httpError) {
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 64 {
		return nil, badRequest("name 必填且不超过 64 字符")
	}
	features := "{}"
	if len(req.Features) > 0 {
		var v any
		if err := json.Unmarshal(req.Features, &v); err != nil {
			return nil, badRequest("features 必须是合法 JSON")
		}
		features = string(req.Features)
	}
	days := 365
	if req.DefaultDays != nil {
		if *req.DefaultDays < 1 || *req.DefaultDays > 3650 {
			return nil, badRequest("default_days 取值范围 1~3650")
		}
		days = *req.DefaultDays
	}
	seats := 5
	if req.DefaultSeats != nil {
		if *req.DefaultSeats < 1 || *req.DefaultSeats > 100000 {
			return nil, badRequest("default_seats 取值范围 1~100000")
		}
		seats = *req.DefaultSeats
	}
	return &store.ProductRow{
		Name: name, Features: features,
		DefaultDays: days, DefaultSeats: seats,
		CreatedAt: s.nowTime().Unix(),
	}, nil
}

// POST /admin/products 新增产品.
func (s *Server) handleProductCreate(w http.ResponseWriter, r *http.Request) {
	var req productReq
	if herr := decodeJSON(r, &req); herr != nil {
		writeErr(w, herr)
		return
	}
	p, herr := s.validateProductReq(&req)
	if herr != nil {
		writeErr(w, herr)
		return
	}
	id, err := randomHex(8)
	if err != nil {
		writeInternal(w, err)
		return
	}
	p.ID = id
	if err := s.Store.CreateProduct(r.Context(), p); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, &httpError{Code: http.StatusConflict, Msg: "产品名已存在"})
			return
		}
		writeInternal(w, err)
		return
	}
	log.Printf("新增产品: id=%s name=%s", p.ID, p.Name)
	writeJSON(w, http.StatusCreated, p.View())
}

// GET /admin/products 产品列表.
func (s *Server) handleProductList(w http.ResponseWriter, r *http.Request) {
	products, err := s.Store.ListProducts(r.Context())
	if err != nil {
		writeInternal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"products": products})
}

// POST /admin/products/{id}/update 修改产品(不影响已签发 license 的快照).
func (s *Server) handleProductUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req productReq
	if herr := decodeJSON(r, &req); herr != nil {
		writeErr(w, herr)
		return
	}
	ctx := r.Context()
	p, err := s.Store.GetProductByID(ctx, id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if p == nil {
		writeErr(w, notFound("product 不存在"))
		return
	}
	if req.Name != "" {
		p.Name = strings.TrimSpace(req.Name)
		if len(p.Name) > 64 {
			writeErr(w, badRequest("name 不超过 64 字符"))
			return
		}
	}
	if len(req.Features) > 0 {
		var v any
		if err := json.Unmarshal(req.Features, &v); err != nil {
			writeErr(w, badRequest("features 必须是合法 JSON"))
			return
		}
		p.Features = string(req.Features)
	}
	if req.DefaultDays != nil {
		if *req.DefaultDays < 1 || *req.DefaultDays > 3650 {
			writeErr(w, badRequest("default_days 取值范围 1~3650"))
			return
		}
		p.DefaultDays = *req.DefaultDays
	}
	if req.DefaultSeats != nil {
		if *req.DefaultSeats < 1 || *req.DefaultSeats > 100000 {
			writeErr(w, badRequest("default_seats 取值范围 1~100000"))
			return
		}
		p.DefaultSeats = *req.DefaultSeats
	}
	if err := s.Store.UpdateProduct(ctx, id, p.Name, p.Features, p.DefaultDays, p.DefaultSeats); err != nil {
		writeInternal(w, err)
		return
	}
	log.Printf("更新产品: id=%s name=%s", id, p.Name)
	writeJSON(w, http.StatusOK, p.View())
}

// DELETE /admin/products/{id} 删除产品(已签发 license 不受影响).
func (s *Server) handleProductDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.Store.DeleteProduct(r.Context(), id)
	if err != nil {
		writeInternal(w, err)
		return
	}
	if n == 0 {
		writeErr(w, notFound("product 不存在"))
		return
	}
	log.Printf("删除产品: id=%s", id)
	writeJSON(w, http.StatusOK, map[string]any{"product_id": id, "deleted": true})
}
