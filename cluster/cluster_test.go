package cluster

import (
	"testing"
	"time"
)

// 전이적 캠페인: A-B-C-D 가 서로 다른 축(UA∧/24, /24∧버스트, UA∧버스트)으로 사슬처럼 이어지면
// 단일 속성 임계값엔 안 걸려도 하나의 연결 요소(크기 4)로 묶여야 한다.
func TestCampaigns_TransitiveChain(t *testing.T) {
	t0 := time.Now()
	evs := []Event{
		{ID: 1, UA: "u1", IP: "203.0.113.1", At: t0},
		{ID: 2, UA: "u1", IP: "203.0.113.2", At: t0.Add(30 * time.Second)}, // A와 UA∧/24
		{ID: 3, UA: "u2", IP: "203.0.113.3", At: t0.Add(33 * time.Second)}, // B와 /24∧버스트
		{ID: 4, UA: "u2", IP: "8.8.8.8", At: t0.Add(34 * time.Second)},     // C와 UA∧버스트
	}
	camps := Campaigns(evs, 4)
	if len(camps) != 1 || len(camps[0]) != 4 {
		t.Fatalf("전이적 캠페인 1개(크기4) 기대, 실제 %v", camps)
	}
}

// 정상 트래픽: UA·대역·시간이 모두 제각각 → 간선이 없어 캠페인이 안 생긴다.
func TestCampaigns_DiverseNoCampaign(t *testing.T) {
	t0 := time.Now()
	evs := []Event{
		{ID: 1, UA: "a", IP: "203.0.113.1", At: t0},
		{ID: 2, UA: "b", IP: "198.51.100.2", At: t0.Add(2 * time.Minute)},
		{ID: 3, UA: "c", IP: "192.0.2.3", At: t0.Add(5 * time.Minute)},
		{ID: 4, UA: "d", IP: "8.8.8.8", At: t0.Add(9 * time.Minute)},
	}
	if camps := Campaigns(evs, 4); len(camps) != 0 {
		t.Fatalf("정상 트래픽인데 캠페인 생김: %v", camps)
	}
}

// 같은 브라우저(동일 UA)지만 대역·시간이 흩어진 정상 군중은 묶이면 안 된다(간선 조건이 축 2개 이상).
func TestCampaigns_SameUADispersedSafe(t *testing.T) {
	t0 := time.Now()
	ips := []string{"1.0.0.1", "2.0.0.1", "3.0.0.1", "4.0.0.1", "5.0.0.1", "6.0.0.1"}
	var evs []Event
	for i, ip := range ips {
		evs = append(evs, Event{ID: int64(i + 1), UA: "Chrome", IP: ip, At: t0.Add(time.Duration(i) * 3 * time.Minute)})
	}
	if camps := Campaigns(evs, 4); len(camps) != 0 {
		t.Fatalf("동일 UA 지만 대역·시간 분산인데 캠페인 생김: %v", camps)
	}
}
