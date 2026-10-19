// Package anomaly 는 Lv8 "이상탐지" 점수기를 담는다.
//
// Lv6 의 하드 규칙(UA 5개·서브넷 4개 같은 고정 임계값)은 그 선을 아슬아슬하게 피하는
// 분산 공격을 놓친다. anomaly 는 여러 "약한 신호"를 0~1 점수로 합성해, 개별 규칙으로는
// 안 걸리지만 종합적으로 수상한 이벤트를 가려낸다.
//
// 지금 구현(StatScorer)은 고정 가중치를 쓰는 비지도(unsupervised) 점수기다. 즉 "학습된
// 모델"이 아니라 모델의 추론부에 해당한다. Scorer 인터페이스로 분리해 뒀으므로, 라벨
// 데이터로 학습한 모델(IsolationForest/오토인코더 등)을 같은 인터페이스로 끼워넣으면
// 호출부(스크러버)는 그대로 둔 채 Lv8 을 "진짜 학습 모델"로 승격할 수 있다.
package anomaly

import "time"

// Event 는 점수 계산에 필요한 최소 정보다(db 패키지에 의존하지 않게 자체 정의 → 테스트 용이).
type Event struct {
	ID int64
	IP string // 실제 소스 IP
	UA string // User-Agent
	At time.Time
}

// Scorer 는 이벤트 묶음을 받아 id 별 이상 점수(0~1)를 돌려준다.
// 점수가 높을수록 "협업/자동화된 트래픽"일 가능성이 크다.
type Scorer interface {
	Score(events []Event) map[int64]float64
}

// StatScorer 는 고정 가중치 통계 점수기다. "규모"가 아니라 "집중 비율(share)"을 본다.
// 핵심 통찰: 같은 브라우저를 쓰는 정상 플래시 크라우드도 UA·버스트는 똑같이 커진다.
// 정상 군중과 봇/프록시 풀을 실제로 가르는 신호는 "서브넷 집중도"다
// (봇 풀은 소수 대역에 IP 가 몰리고, 정상 군중은 수많은 대역에 흩어진다). 그래서 서브넷에
// 가장 큰 가중치를 둔다. 세 특징은 모두 0~1 비율이다:
//
//	uaShare     : 이 이벤트의 UA 를 공유하는 이벤트 비율      (한 UA 가 트래픽을 지배할수록 1에 가까움)
//	subnetShare : 이 이벤트의 /24 에 속한 이벤트 비율         (소수 대역에 몰릴수록 1에 가까움 ← 주력 신호)
//	burstShare  : BurstWindow 안에 몰린 이벤트 비율           (짧은 파도로 몰아칠수록 1에 가까움)
type StatScorer struct {
	UAWeight     float64
	SubnetWeight float64
	BurstWeight  float64
	BurstWindow  time.Duration // 버스트로 묶는 시간 폭(이벤트 전후)
}

// Default 는 실습용 기본 점수기. 값은 자유롭게 조절해도 된다.
// 서브넷 집중도에 가장 큰 가중치를 둬서, 같은 UA 를 쓰는 정상 군중은 통과시키고
// 소수 대역에 몰린 프록시/봇 풀만 걸러낸다.
func Default() StatScorer {
	return StatScorer{
		UAWeight: 0.25, SubnetWeight: 0.55, BurstWeight: 0.20,
		BurstWindow: 10 * time.Second,
	}
}

// subnet24 는 IPv4 의 앞 3옥텟("a.b.c")을 돌려준다. IPv4 가 아니면 전체 문자열.
func subnet24(ip string) string {
	dots := 0
	for i := 0; i < len(ip); i++ {
		if ip[i] == '.' {
			dots++
			if dots == 3 {
				return ip[:i]
			}
		}
		if ip[i] == ':' { // IPv6 는 여기서 /24 개념을 안 쓰므로 전체를 키로(별도 군집)
			return ip
		}
	}
	return ip
}

func (s StatScorer) Score(events []Event) map[int64]float64 {
	out := make(map[int64]float64, len(events))
	total := float64(len(events))
	if total == 0 {
		return out
	}

	// UA·서브넷별 이벤트 수 집계.
	uaCount := map[string]float64{}
	subCount := map[string]float64{}
	for _, e := range events {
		uaCount[e.UA]++
		subCount[subnet24(e.IP)]++
	}

	for _, e := range events {
		uaShare := uaCount[e.UA] / total
		subShare := subCount[subnet24(e.IP)] / total

		// 버스트 비율: 이 이벤트 전후 BurstWindow 안에 몰린 이벤트 비율.
		burst := 0.0
		for _, o := range events {
			d := e.At.Sub(o.At)
			if d < 0 {
				d = -d
			}
			if d <= s.BurstWindow {
				burst++
			}
		}
		burstShare := burst / total

		out[e.ID] = s.UAWeight*uaShare + s.SubnetWeight*subShare + s.BurstWeight*burstShare
	}
	return out
}

// Flagged 는 점수가 threshold 이상인 이벤트 id 를 돌려준다.
func Flagged(s Scorer, events []Event, threshold float64) []int64 {
	scores := s.Score(events)
	var ids []int64
	for id, sc := range scores {
		if sc >= threshold {
			ids = append(ids, id)
		}
	}
	return ids
}
