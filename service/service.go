package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const viewCookie = "vtoken"

// writeJSON 은 공통 JSON 응답 헬퍼.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func browserToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(viewCookie); err == nil && c.Value != "" {
		return c.Value
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     viewCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: false, // 참가자가 쿠키를 보고 지울 수 있도록 (Lv1 우회 실습용)
		MaxAge:   60 * 60 * 24,
	})
	return tok
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
