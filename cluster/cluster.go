// Package cluster 는 Lv10 "행동 그래프 군집"을 담는다.
//
// Lv6 하드 규칙은 속성 하나(UA 또는 서브넷)만 보고, Lv8 점수는 이벤트를 독립적으로 본다.
// cluster 는 이벤트를 노드로 두고 "공유 속성"으로 간선을 이어, 전이적으로 묶이는 무리를 찾는다.
// 공격자가 UA 를 여러 대역에 흩고 타이밍도 조금씩 어긋내 각 단일 신호를 피하더라도,
//
//	A ─(같은 UA·같은 /24)─ B ─(같은 /24·버스트)─ C ─(같은 UA·버스트)─ D
//
// 처럼 서로 다른 속성으로 사슬이 이어지면 하나의 연결 요소(=캠페인)로 드러난다.
// 반대로 정상 트래픽은 UA·대역·시간이 제각각이라 간선이 거의 없어 작은 조각으로 흩어진다.
package cluster

import (
	"time"

	"rank-project_v1/anomaly"
)

// Event 는 anomaly 패키지의 것을 그대로 쓴다(ID·IP·UA·At).
type Event = anomaly.Event

// LinkWindow 는 두 이벤트를 "같은 버스트"로 볼 시간 간격.
var LinkWindow = 10 * time.Second

// subnet24 는 IPv4 앞 3옥텟. IPv4 가 아니면 전체 문자열(IPv6 는 그 자체를 키로).
func subnet24(ip string) string {
	dots := 0
	for i := 0; i < len(ip); i++ {
		switch ip[i] {
		case '.':
			if dots++; dots == 3 {
				return ip[:i]
			}
		case ':':
			return ip
		}
	}
	return ip
}

// linked 는 두 이벤트가 "협업으로 의심되는 공유 속성"으로 이어지는지 본다.
// 서로 다른 축 두 개 이상이 겹칠 때만 간선을 둬서, 흔한 우연(그냥 같은 브라우저)만으로는 안 잇는다.
func linked(a, b Event) bool {
	sameUA := a.UA == b.UA
	sameNet := subnet24(a.IP) == subnet24(b.IP)
	d := a.At.Sub(b.At)
	if d < 0 {
		d = -d
	}
	sameBurst := d <= LinkWindow
	// (UA∧/24) or (/24∧버스트) or (UA∧버스트) — 축 2개 이상 동시 일치.
	return (sameUA && sameNet) || (sameNet && sameBurst) || (sameUA && sameBurst)
}

// Campaigns 는 크기가 minSize 이상인 연결 요소(=캠페인)들의 이벤트 id 묶음을 돌려준다.
func Campaigns(events []Event, minSize int) [][]int64 {
	n := len(events)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}

	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			if linked(events[i], events[j]) {
				union(i, j)
			}
		}
	}

	groups := map[int][]int64{}
	for i := 0; i < n; i++ {
		r := find(i)
		groups[r] = append(groups[r], events[i].ID)
	}

	var out [][]int64
	for _, ids := range groups {
		if len(ids) >= minSize {
			out = append(out, ids)
		}
	}
	return out
}
