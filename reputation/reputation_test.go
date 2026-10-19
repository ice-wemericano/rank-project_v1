package reputation

import "testing"

func TestIsBad(t *testing.T) {
	cases := map[string]bool{
		"3.1.2.3":      true,  // AWS 샘플 대역
		"192.168.1.50": true,  // 사설(실습 프록시 대역)
		"10.9.8.7":     true,  // 사설
		"203.0.113.10": false, // 일반 공인(문서용 대역, 목록에 없음)
		"8.8.8.8":      false, // 목록에 없는 공인
		"not-an-ip":    false,
	}
	for ip, want := range cases {
		if got := IsBad(ip); got != want {
			t.Errorf("IsBad(%q) = %v, want %v", ip, got, want)
		}
	}
}
