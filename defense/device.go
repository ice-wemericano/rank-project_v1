package defense

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
)

// ---------- 디바이스 소유증명 (Lv7) ----------
//
// Lv7 은 "이 조회가 특정 비대칭 키의 소유자에게서 왔음"을 요구한다. 브라우저는 open 때 받은
// 챌린지(열람증명 nonce)를 자신이 보관한 ECDSA 개인키(WebCrypto, 비추출)로 서명하고, view 에
// 서명을 동봉한다. 서버는 그 신원(쿠키 owner)에 묶인 공개키로 서명을 검증한다.
//
// 공개키는 "owner|pub" 을 HMAC 서명한 디바이스 토큰(dkey 쿠키)에 담겨 다닌다 → 남의 신원으로
// 등록된 키를 가로채 쓸 수 없다. 정직한 한계: 이는 "신원별 희소 키의 소유 + 서명 증명"이지
// 하드웨어 증명은 아니다. 스크립트 공격자도 키쌍을 만들어 서명할 수 있으나(=PoW 수준 비용),
// 브라우저에선 키가 비추출이라 신원 간 복제·공유가 어렵고, 단순 봇은 이 흐름을 못 넘는다.

// IssueDeviceToken 은 공개키를 신원(owner)에 묶어 서명한 디바이스 토큰을 만든다(dkey 쿠키용).
func IssueDeviceToken(owner, pubB64 string) string {
	return SignValue(owner + "|" + pubB64)
}

// VerifyDeviceToken 은 디바이스 토큰의 서명을 확인하고, 묶인 owner 가 기대값과 같으면 공개키를 돌려준다.
func VerifyDeviceToken(dtoken, owner string) (pubB64 string, ok bool) {
	val, ok := VerifySignedValue(dtoken)
	if !ok || owner == "" {
		return "", false
	}
	i := strings.IndexByte(val, '|')
	if i < 0 || val[:i] != owner {
		return "", false
	}
	return val[i+1:], true
}

// VerifyDeviceSig 는 pubB64(SPKI, base64url) 공개키로 challenge 에 대한 서명(sigB64)을 검증한다.
// WebCrypto ECDSA(P-256, SHA-256)의 서명은 raw r||s(64바이트) 형식이다.
func VerifyDeviceSig(pubB64, challenge, sigB64 string) bool {
	pubDER, err := b64urlDecode(pubB64)
	if err != nil {
		return false
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	sig, err := b64urlDecode(sigB64)
	if err != nil || len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	h := sha256.Sum256([]byte(challenge))
	return ecdsa.Verify(pub, h[:], r, s)
}

// b64urlDecode 는 패딩 유무에 상관없이 base64url 을 디코드한다.
func b64urlDecode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}
