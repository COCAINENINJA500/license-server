package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
)

// httpError 携带 HTTP 状态码的业务错误.
type httpError struct {
	Code int
	Msg  string
}

func (e *httpError) Error() string { return e.Msg }

func badRequest(msg string) *httpError   { return &httpError{Code: http.StatusBadRequest, Msg: msg} }
func unauthorized(msg string) *httpError { return &httpError{Code: http.StatusUnauthorized, Msg: msg} }
func forbidden(msg string) *httpError    { return &httpError{Code: http.StatusForbidden, Msg: msg} }
func notFound(msg string) *httpError     { return &httpError{Code: http.StatusNotFound, Msg: msg} }

// decodeJSON 解析 JSON 请求体: 超出 MaxBytesReader 上限返回 413,非法 JSON 返回 400.
func decodeJSON(r *http.Request, v any) *httpError {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &httpError{Code: http.StatusRequestEntityTooLarge, Msg: "请求体过大"}
		}
		return badRequest("请求体不是合法 JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err *httpError) {
	writeJSON(w, err.Code, map[string]string{"error": err.Msg})
}

func writeInternal(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "内部错误"})
}
