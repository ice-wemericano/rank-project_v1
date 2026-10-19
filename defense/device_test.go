package defense

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

// WebCrypto ECDSA(P-256)가 내는 raw r||s(64바이트) 서명을 흉내 내 base64url 로 돌려준다.
func signRaw(t *testing.T, priv *ecdsa.PrivateKey, challenge string) string {
	h := sha256.Sum256([]byte(challenge))
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

func pubSPKI(t *testing.T, priv *ecdsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(der)
}

func TestDeviceToken_RoundTripAndBinding(t *testing.T) {
	InitSecret("test-secret")
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := pubSPKI(t, priv)

	dtoken := IssueDeviceToken("owner-A", pub)

	// 올바른 owner → 공개키 복원.
	if got, ok := VerifyDeviceToken(dtoken, "owner-A"); !ok || got != pub {
		t.Fatalf("정상 owner 검증 실패: ok=%v", ok)
	}
	// 다른 owner → 거부(남의 신원으로 가로채 쓰기 차단).
	if _, ok := VerifyDeviceToken(dtoken, "owner-B"); ok {
		t.Fatal("owner 불일치인데 통과됨")
	}
	// 서명 위조 → 거부.
	if _, ok := VerifyDeviceToken(dtoken+"x", "owner-A"); ok {
		t.Fatal("변조된 디바이스 토큰이 통과됨")
	}
}

func TestDeviceSig_VerifyAndReject(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := pubSPKI(t, priv)
	const challenge = "nonce-abc123"

	// 올바른 키로 올바른 챌린지 서명 → 통과.
	if !VerifyDeviceSig(pub, challenge, signRaw(t, priv, challenge)) {
		t.Fatal("정상 서명이 검증 실패")
	}
	// 다른 챌린지에 대한 서명 → 거부(리플레이·치환 방지).
	if VerifyDeviceSig(pub, challenge, signRaw(t, priv, "다른-챌린지")) {
		t.Fatal("다른 챌린지 서명이 통과됨")
	}
	// 다른 키로 서명 → 거부.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if VerifyDeviceSig(pub, challenge, signRaw(t, other, challenge)) {
		t.Fatal("다른 키 서명이 통과됨")
	}
	// 깨진 입력 → 거부(패닉 없이).
	if VerifyDeviceSig("!!bad", challenge, "!!bad") {
		t.Fatal("깨진 입력이 통과됨")
	}
}
