package service

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	"rank-project_v1/defense"
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

// sentToken 은 클라이언트가 보낸 쿠키에서 "서명 검증을 통과한" 토큰을 돌려준다(없거나 위조면 "").
// 중복제거 식별자로는 반드시 이 값을 써야 한다.
func sentToken(r *http.Request) string {
	c, err := r.Cookie(viewCookie)
	if err != nil {
		return ""
	}
	tok, ok := defense.VerifySignedValue(c.Value) // HMAC 서명 검증 → 위조 쿠키 차단
	if !ok {
		return ""
	}
	return tok
}

// ensureCookie 는 쿠키가 없거나 위조된 방문자에게 서명된 식별용 쿠키를 새로 발급한다.
func ensureCookie(w http.ResponseWriter, r *http.Request) {
	if sentToken(r) != "" {
		return
	}
	signed := defense.SignValue(defense.NewIdentityToken())
	http.SetCookie(w, &http.Cookie{
		Name:     viewCookie,
		Value:    signed,
		Path:     "/",
		HttpOnly: false, // 참가자가 쿠키를 보고 지울 수 있도록 (Lv1 우회 실습용)
		MaxAge:   60 * 60 * 24,
	})
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
