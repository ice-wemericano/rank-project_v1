// Package scrubber 는 Lv6 "사후 스크러빙"을 담당한다.
//
// 인라인 방어(Lv0~5)는 요청 1건만 보고 즉시 판정하므로, 서로 다른 실제 IP 로 흩뿌리는
// 분산 공격(경로 B: 프록시 풀/클라우드)은 각 요청이 "정상 1회"처럼 보여 통과한다.
// 스크러버는 반대로 "집계 전체"를 주기적으로 다시 보고, 개별 요청으로는 안 보이던
// 협업 패턴(여러 IP가 같은 UA, 같은 서브넷에 IP 집중)을 찾아 조회수를 소급 차감한다.
//
// 즉 조회수는 view 시점에 "확정"이 아니라 "잠정"이고, 스크러버가 지난 뒤 "순 확정"이 된다.
// (현존 서비스가 승부처를 요청시점 → 집계이후로 옮긴 것과 같은 구조.)
//
// Lv8(ML 점수)·Lv10(평판/그래프 군집)은 이 파이프라인에 점수원을 추가하는 형태로 확장된다.
package scrubber

import (
	"net"
	"strconv"
	"time"

	"rank-project_v1/anomaly"
	"rank-project_v1/cluster"
	"rank-project_v1/db"
	"rank-project_v1/defense"
	"rank-project_v1/logs"
	"rank-project_v1/reputation"
)

// 스크러빙 파라미터 (실습하면서 조절해도 된다).
var (
	Window       = 60 * time.Minute // 재검사할 최근 구간
	UAMinIPs     = 5                // 같은 UA 를 공유하는 서로 다른 IP 가 이 수 이상이면 협업으로 판정
	SubnetMinIPs = 4                // 같은 서브넷(/24·/64)에 서로 다른 IP 가 이 수 이상이면 대역 집중으로 판정

	// Lv8 이상탐지 점수기와 임계값. 점수 >= AnomalyThreshold 이면 소급 차감한다.
	scorer           anomaly.Scorer = anomaly.Default()
	AnomalyThreshold                = 0.6

	// Lv10 그래프 군집: 연결 요소 크기가 이 수 이상이면 한 캠페인으로 보고 차감한다.
	ClusterMinSize = 4
)

// Start 는 interval 마다 한 번씩 스크러빙을 도는 goroutine 을 띄운다.
func Start(interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			if n := runOnce(); n > 0 {
				logs.Log("SCRUB", "소급 차감 "+strconv.Itoa(n)+"건")
			}
		}
	}()
}

// runOnce 는 한 번의 스크러빙 패스를 수행하고 차감된 총 건수를 돌려준다.
func runOnce() int {
	cands, err := db.CountedSince(Window)
	if err != nil {
		return 0
	}
	// 글별로 후보를 모은다.
	byPost := map[int][]db.ScrubCandidate{}
	for _, c := range cands {
		byPost[c.PostID] = append(byPost[c.PostID], c)
	}

	total := 0
	for postID, list := range byPost {
		lvl := defense.LevelFor(postID)
		// Lv6 이상에서만 사후 스크러빙을 적용한다.
		if lvl < 6 {
			continue
		}
		total += scrubPost(postID, list, lvl)
	}
	return total
}

// action 은 "어떤 이벤트들을 어떤 사유로 차감할지"에 대한 계획 1건.
type action struct {
	reason string
	ids    []int64
}

// scrubPost 는 한 글의 후보들에 lvl 에 맞는 규칙을 적용해 소급 차감한다.
func scrubPost(postID int, list []db.ScrubCandidate, lvl int) int {
	scrubbed := 0
	for _, a := range planScrub(list, lvl) {
		// 앞 규칙에서 이미 차감된 id 는 ScrubEvents 가 scrubbed=0 조건으로 건너뛴다(중복 차감 없음).
		if n, err := db.ScrubEvents(postID, a.ids, a.reason); err == nil {
			scrubbed += n
		}
	}
	return scrubbed
}

// planScrub 은 후보들에 레벨별 규칙을 적용해 "무엇을 어떤 사유로 차감할지" 계획을 세운다.
// DB 를 건드리지 않는 순수 함수라 단위 테스트가 쉽다.
// Lv6: UA 단일화·서브넷 집중 / Lv8+: 이상탐지 점수 / Lv10+: 그래프 군집·평판.
func planScrub(list []db.ScrubCandidate, lvl int) []action {
	var actions []action

	// 규칙 1: UA 단일화 — 같은 UA 를 서로 다른 IP 다수가 공유하면 프록시/봇 풀.
	uaIPs := map[string]map[string]bool{} // ua -> set(ip)
	uaIDs := map[string][]int64{}         // ua -> event ids
	for _, c := range list {
		if uaIPs[c.UserAgent] == nil {
			uaIPs[c.UserAgent] = map[string]bool{}
		}
		uaIPs[c.UserAgent][c.IP] = true
		uaIDs[c.UserAgent] = append(uaIDs[c.UserAgent], c.ID)
	}
	for ua, ips := range uaIPs {
		if len(ips) >= UAMinIPs {
			actions = append(actions, action{defense.ReasonScrubUAMono, uaIDs[ua]})
		}
	}

	// 규칙 2: 서브넷 집중 — 같은 /24(IPv4)·/64(IPv6)에 서로 다른 IP 다수면 데이터센터/프록시 대역.
	netIPs := map[string]map[string]bool{}
	netIDs := map[string][]int64{}
	for _, c := range list {
		s := subnetKey(c.IP)
		if s == "" {
			continue
		}
		if netIPs[s] == nil {
			netIPs[s] = map[string]bool{}
		}
		netIPs[s][c.IP] = true
		netIDs[s] = append(netIDs[s], c.ID)
	}
	for s, ips := range netIPs {
		if len(ips) >= SubnetMinIPs {
			actions = append(actions, action{defense.ReasonScrubSubnet, netIDs[s]})
		}
	}

	// Lv8+ / Lv10+ 는 공통으로 (ID·IP·UA·At) 형태의 이벤트가 필요하다.
	var evs []anomaly.Event
	if lvl >= 8 {
		evs = make([]anomaly.Event, len(list))
		for i, c := range list {
			evs[i] = anomaly.Event{ID: c.ID, IP: c.IP, UA: c.UserAgent, At: c.CreatedAt}
		}
	}

	// 규칙 3 (Lv8): 하드 규칙을 아슬아슬하게 피하는 협업 트래픽을 이상탐지 점수로 잡는다.
	if lvl >= 8 {
		if ids := anomaly.Flagged(scorer, evs, AnomalyThreshold); len(ids) > 0 {
			actions = append(actions, action{defense.ReasonScrubAnomaly, ids})
		}
	}

	// 규칙 4 (Lv10): 행동 그래프 군집 — 전이적으로 묶이는 한 캠페인을 통째로 차감.
	if lvl >= 10 {
		for _, ids := range cluster.Campaigns(evs, ClusterMinSize) {
			actions = append(actions, action{defense.ReasonScrubCluster, ids})
		}
		// 규칙 5 (Lv10): 평판 — 데이터센터/프록시 대역 IP 는 직접 차감.
		var repIDs []int64
		for _, c := range list {
			if reputation.IsBad(c.IP) {
				repIDs = append(repIDs, c.ID)
			}
		}
		if len(repIDs) > 0 {
			actions = append(actions, action{defense.ReasonScrubRep, repIDs})
		}
	}
	return actions
}

// subnetKey 는 IP 를 서브넷 키로 바꾼다(IPv4 는 /24, IPv6 는 /64). 파싱 실패면 "".
func subnetKey(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
