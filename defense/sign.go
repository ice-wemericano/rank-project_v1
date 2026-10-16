package defense

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// secret 은 HMAC 서명 키다. 여러 서버가 같은 쿠키/토큰을 검증하려면 SECRET_KEY 를 공유해야 한다.
var secret []byte

// InitSecret 은 서명 키를 설정한다. 비어 있으면 임시 키를 생성한다(단일 서버 전용).
// 임시 키를 쓰면 재시작 시 기존 쿠키/토큰이 무효화되고, 다중 서버 간 공유도 안 된다.
func InitSecret(key string) bool {
	if key != "" {
		secret = []byte(key)
		return true
	}
	secret = make([]byte, 32)
	_, _ = rand.Read(secret)
	return false // 임시 키 사용함을 알림
}

func sign(msg string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// SignValue 는 값에 서명을 붙여 "value.signature" 형태로 돌려준다(쿠키용).
func SignValue(value string) string {
	return value + "." + sign(value)
}

// VerifySignedValue 는 서명된 값에서 원래 값을 꺼낸다. 서명이 틀리면 ("", false).
func VerifySignedValue(signed string) (string, bool) {
	i := strings.LastIndex(signed, ".")
	if i < 0 {
		return "", false
	}
	value, sig := signed[:i], signed[i+1:]
	want := sign(value)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", false
	}
	return value, true
}

// NewIdentityToken 은 브라우저 식별용 랜덤 토큰을 만든다(서명은 쿠키에 붙일 때 한다).
func NewIdentityToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type proofPayload struct {
	Nonce    string `json:"n"`
	PostID   int    `json:"p"`
	IP       string `json:"ip"`
	Owner    string `json:"o"` // 발급 시점의 쿠키 토큰 (다른 브라우저로 넘겨 쓰기 차단)
	IssuedAt int64  `json:"t"` // unix ms
}

// IssueProofToken 은 서명된 열람증명 토큰과 nonce 를 만든다.
func IssueProofToken(postID int, ip, owner string) (token, nonce string) {
	nonce = NewIdentityToken()
	payload := proofPayload{Nonce: nonce, PostID: postID, IP: ip, Owner: owner, IssuedAt: time.Now().UnixMilli()}
	b, _ := json.Marshal(payload)
	body := base64.RawURLEncoding.EncodeToString(b)
	return body + "." + sign(body), nonce
}

// VerifyProofToken 은 토큰의 서명을 확인하고 payload 를 돌려준다.
func VerifyProofToken(token string) (*proofPayload, bool) {
	i := strings.LastIndex(token, ".")
	if i < 0 {
		return nil, false
	}
	body, sig := token[:i], token[i+1:]
	if subtle.ConstantTimeCompare([]byte(sig), []byte(sign(body))) != 1 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, false
	}
	var p proofPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, false
	}
	return &p, true
}
