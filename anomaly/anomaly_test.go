package anomaly

import (
	"fmt"
	"testing"
	"time"
)

const threshold = 0.6 // scrubber.AnomalyThreshold 과 동일한 기준으로 검증

// 회피형 공격: UA 4개만 공유(하드 UA<5), 2개 /24 에 2개씩(하드 서브넷<4), 짧은 버스트.
// 하드 규칙은 피하지만 서브넷 집중 + UA 지배가 합쳐져 임계값을 넘어 전부 플래그돼야 한다.
func TestStatScorer_EvasionFlagged(t *testing.T) {
	s := Default()
	base := time.Now()
	ips := []string{"203.0.113.1", "203.0.113.2", "198.51.100.1", "198.51.100.2"}
	var evs []Event
	for i, ip := range ips {
		evs = append(evs, Event{ID: int64(i + 1), IP: ip, UA: "bot", At: base.Add(time.Duration(i) * 300 * time.Millisecond)})
	}
	if flagged := Flagged(s, evs, threshold); len(flagged) != len(evs) {
		t.Fatalf("회피형 공격 전부 플래그 기대(%d), 실제 %d (점수 %v)", len(evs), len(flagged), s.Score(evs))
	}
}

// 정상 플래시 크라우드: 같은 브라우저(동일 UA)로 몰려오지만 수많은 서로 다른 대역에 흩어짐.
// UA·버스트는 공격과 똑같이 크지만 서브넷이 분산돼 있어 플래그되면 안 된다(오탐 방지 핵심).
func TestStatScorer_FlashCrowdSafe(t *testing.T) {
	s := Default()
	base := time.Now()
	var crowd []Event
	for i := 0; i < 12; i++ {
		crowd = append(crowd, Event{ID: int64(i + 1), IP: fmt.Sprintf("%d.%d.%d.1", 10+i, i, i), UA: "Chrome", At: base})
	}
	if flagged := Flagged(s, crowd, threshold); len(flagged) != 0 {
		t.Fatalf("정상 플래시크라우드가 플래그됨: %d건 (점수[1]=%.3f)", len(flagged), s.Score(crowd)[1])
	}
}

// 핵심 설계 목표: 서브넷에 몰린 공격이, 같은 규모의 분산된 정상 군중보다 높은 점수를 받아야 한다.
func TestStatScorer_ConcentrationRanksAboveCrowd(t *testing.T) {
	s := Default()
	base := time.Now()
	var attack, crowd []Event
	for i := 0; i < 8; i++ {
		attack = append(attack, Event{ID: int64(i + 1), IP: fmt.Sprintf("203.0.113.%d", i), UA: "bot", At: base})     // 전부 한 /24
		crowd = append(crowd, Event{ID: int64(i + 1), IP: fmt.Sprintf("%d.%d.0.1", 20+i, i), UA: "Chrome", At: base}) // 서로 다른 /24
	}
	if s.Score(attack)[1] <= s.Score(crowd)[1] {
		t.Fatalf("서브넷 집중 공격이 분산 군중보다 낮거나 같음: attack=%.3f crowd=%.3f",
			s.Score(attack)[1], s.Score(crowd)[1])
	}
}

// 정상 트래픽(서로 다른 UA·대역, 시간 분산)은 플래그되면 안 된다.
func TestStatScorer_DiverseSlowTrafficSafe(t *testing.T) {
	s := Default()
	base := time.Now()
	evs := []Event{
		{ID: 1, IP: "203.0.113.10", UA: "UA-A", At: base},
		{ID: 2, IP: "198.51.100.22", UA: "UA-B", At: base.Add(2 * time.Minute)},
		{ID: 3, IP: "192.0.2.33", UA: "UA-C", At: base.Add(5 * time.Minute)},
	}
	if flagged := Flagged(s, evs, threshold); len(flagged) != 0 {
		t.Fatalf("정상 트래픽이 플래그됨: %d건 (점수 %v)", len(flagged), s.Score(evs))
	}
}
