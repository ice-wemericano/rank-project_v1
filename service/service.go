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
const deviceCookie = "dkey" // Lv7: owner 에 묶인 공개키를 담은 서명 토큰

// writeJSON 은 공통 JSON 응답 헬퍼.
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// realIP 는 클라이언트가 조작할 수 없는 실제 접속 IP 다.
// 직접 접속이면 RemoteAddr. 앞단 리버스 프록시(루프백/사설 주소)를 거쳐 왔으면
// 프록시가 마지막에 덧붙인 X-Forwarded-For "맨 오른쪽" 값을 쓴다(클라이언트가 넣은 앞부분은 무시).
func realIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
				return last
			}
		}
	}
	return host
}

// claimedIP 는 X-Forwarded-For 맨 앞 값(클라이언트가 마음대로 넣을 수 있음). Lv2 의도된 취약점용.
func claimedIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	return ""
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
// 이 방문자의 (기존 또는 새) 토큰을 돌려준다.
func ensureCookie(w http.ResponseWriter, r *http.Request) string {
	if tok := sentToken(r); tok != "" {
		return tok
	}
	tok := defense.NewIdentityToken()
	signed := defense.SignValue(tok)
	http.SetCookie(w, &http.Cookie{
		Name:     viewCookie,
		Value:    signed,
		Path:     "/",
		HttpOnly: false, // 참가자가 쿠키를 보고 지울 수 있도록 (Lv1 우회 실습용)
		MaxAge:   60 * 60 * 24,
	})
	return tok
}

// sentDeviceToken 은 클라이언트가 보낸 dkey 쿠키 값을 그대로 돌려준다(서명 검증은 defense 가 한다).
func sentDeviceToken(r *http.Request) string {
	c, err := r.Cookie(deviceCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
