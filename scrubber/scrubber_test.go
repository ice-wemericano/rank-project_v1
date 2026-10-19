package scrubber

import (
	"testing"
	"time"

	"rank-project_v1/db"
	"rank-project_v1/defense"
)

// 계획에서 특정 사유로 차감될 id 집합을 모은다(순서/중복 무시).
func idsFor(actions []action, reason string) map[int64]bool {
	out := map[int64]bool{}
	for _, a := range actions {
		if a.reason == reason {
			for _, id := range a.ids {
				out[id] = true
			}
		}
	}
	return out
}

func cand(id int64, ip, ua string) db.ScrubCandidate {
	return db.ScrubCandidate{ID: id, PostID: 1, IP: ip, UserAgent: ua, CreatedAt: time.Now()}
}

// 경로 B(프록시 풀): 서로 다른 IP 다수가 같은 UA → UA 단일화로 전부 차감돼야 한다.
func TestPlanScrub_UAMonoculture(t *testing.T) {
	const ua = "Mozilla/5.0 ... Chrome/140.0.0.0"
	var list []db.ScrubCandidate
	for i := 0; i < UAMinIPs; i++ { // 임계값만큼의 서로 다른 IP
		list = append(list, cand(int64(i+1), "203.0.113."+itoa(i), ua))
	}
	got := idsFor(planScrub(list, 6), defense.ReasonScrubUAMono)
	if len(got) != UAMinIPs {
		t.Fatalf("UA 단일화: %d건 차감 기대, 실제 %d건", UAMinIPs, len(got))
	}
}

// 정상 트래픽: 서로 다른 UA·서로 다른 대역 → 아무것도 차감되면 안 된다.
func TestPlanScrub_DiverseTrafficSafe(t *testing.T) {
	list := []db.ScrubCandidate{
		cand(1, "203.0.113.10", "UA-A"),
		cand(2, "198.51.100.22", "UA-B"),
		cand(3, "192.0.2.33", "UA-C"),
		cand(4, "211.45.1.7", "UA-D"),
	}
	if actions := planScrub(list, 6); len(actions) != 0 {
		t.Fatalf("정상 트래픽인데 차감 계획 %d건 생김: %+v", len(actions), actions)
	}
}

// UA 를 매번 바꿔도(랜덤 UA) 같은 /24 에 IP 가 몰리면 서브넷 집중으로 잡혀야 한다.
func TestPlanScrub_SubnetConcentration(t *testing.T) {
	var list []db.ScrubCandidate
	for i := 0; i < SubnetMinIPs; i++ {
		list = append(list, cand(int64(i+1), "203.0.113."+itoa(i), "UA-"+itoa(i))) // 전부 203.0.113.0/24
	}
	got := idsFor(planScrub(list, 6), defense.ReasonScrubSubnet)
	if len(got) != SubnetMinIPs {
		t.Fatalf("서브넷 집중: %d건 차감 기대, 실제 %d건", SubnetMinIPs, len(got))
	}
}

// 임계값 미만이면 차감하지 않는다(오탐 방지).
func TestPlanScrub_BelowThreshold(t *testing.T) {
	const ua = "same-ua"
	var list []db.ScrubCandidate
	for i := 0; i < UAMinIPs-1; i++ { // 임계값보다 하나 적게
		list = append(list, cand(int64(i+1), "8.8.8."+itoa(i), ua)) // 8.8.8.0/24 집중도 임계값 미만이 되도록 UAMinIPs-1 < SubnetMinIPs? 아래 주석 참고
	}
	// UAMinIPs-1 개의 IP 가 같은 /24 이므로, SubnetMinIPs 이상이면 서브넷 규칙에 걸린다.
	// 이 테스트는 UA 규칙의 임계값만 검증하므로 대역을 흩어준다.
	list = nil
	for i := 0; i < UAMinIPs-1; i++ {
		list = append(list, cand(int64(i+1), itoa(i+1)+".0.0.1", ua)) // 전부 다른 /24
	}
	if got := idsFor(planScrub(list, 6), defense.ReasonScrubUAMono); len(got) != 0 {
		t.Fatalf("임계값 미만인데 UA 규칙 발동: %d건", len(got))
	}
}

// Lv8 이 Lv6 하드 규칙을 회피한 공격을 잡는지: 같은 UA 4개(UA<5), 2개 /24 에 2개씩(서브넷<4).
// useAnomaly=false(=Lv6) 면 아무것도 안 걸리고, true(=Lv8) 면 이상탐지로 전부 차감돼야 한다.
func TestPlanScrub_Lv8CatchesEvasion(t *testing.T) {
	list := []db.ScrubCandidate{
		cand(1, "203.0.113.1", "bot"),
		cand(2, "203.0.113.2", "bot"),
		cand(3, "198.51.100.1", "bot"),
		cand(4, "198.51.100.2", "bot"),
	}
	if a := planScrub(list, 6); len(a) != 0 {
		t.Fatalf("Lv6 하드 규칙은 이 회피형을 놓쳐야 하는데 %d건 계획됨", len(a))
	}
	got := idsFor(planScrub(list, 8), defense.ReasonScrubAnomaly)
	if len(got) != len(list) {
		t.Fatalf("Lv8 이상탐지가 회피형을 잡아야 함: %d건 기대, 실제 %d건", len(list), len(got))
	}
}

func TestSubnetKey(t *testing.T) {
	cases := map[string]string{
		"203.0.113.45":  "203.0.113.0/24",
		"203.0.113.200": "203.0.113.0/24",
		"8.8.4.4":       "8.8.4.0/24",
		"not-an-ip":     "",
	}
	for in, want := range cases {
		if got := subnetKey(in); got != want {
			t.Errorf("subnetKey(%q) = %q, want %q", in, got, want)
		}
	}
	// IPv6: 같은 /64 로 정규화돼야 한다.
	a := subnetKey("2001:db8:abcd:1::1")
	b := subnetKey("2001:db8:abcd:1::ffff")
	if a == "" || a != b {
		t.Errorf("IPv6 /64 정규화 실패: %q vs %q", a, b)
	}
}

// 테스트용 작은 정수→문자열(표준 strconv 대신 의존 최소화).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
