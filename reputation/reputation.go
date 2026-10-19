// Package reputation 은 Lv10 의 보조 신호: IP 가 데이터센터/프록시 대역인지 본다.
//
// 봇·프록시 풀은 대개 클라우드/호스팅 대역에서 나온다. 여기서는 잘 알려진 대역 몇 개를
// 정적 CIDR 리스트로 제공한다(교체 가능). 실전에서는 이 자리에 MaxMind GeoLite2 ASN 같은
// 평판 피드를 끼워 "이 IP 의 ASN 이 호스팅 사업자인가"를 조회한다 — 인터페이스는 그대로 둔다.
package reputation

import "net"

// Ranges 는 "나쁜 평판"으로 볼 CIDR 목록(데이터센터/클라우드 샘플 + 로컬 실습용).
// 실습 환경(프록시가 사설/로컬 대역)에서도 데모되도록 RFC1918·로컬 대역을 포함한다.
// 운영에서는 이 목록을 실제 호스팅 ASN 대역으로 교체한다.
var Ranges = []string{
	// 실습용: 로컬/사설 프록시 대역(데모에서 프록시가 여기서 나옴)
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	// 잘 알려진 클라우드/호스팅 대역 샘플 (예시 — 전수가 아니다)
	"3.0.0.0/8",     // AWS
	"34.0.0.0/8",    // GCP
	"13.64.0.0/11",  // Azure
	"104.16.0.0/12", // Cloudflare
	"167.99.0.0/16", // DigitalOcean
	"51.38.0.0/16",  // OVH
}

// nets 는 Ranges 를 파싱해 캐시한다.
var nets []*net.IPNet

func init() { Reload() }

// Reload 는 Ranges 를 다시 파싱한다(런타임에 목록을 바꿨을 때 호출).
func Reload() {
	nets = nets[:0]
	for _, c := range Ranges {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
}

// IsBad 는 ip 가 평판 대역(데이터센터/프록시)에 속하면 true.
func IsBad(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
