package defense

import (
	"strconv"
	"testing"
	"time"
)

func setup(t *testing.T, lvl int) {
	t.Helper()
	InitSecret("test-secret")
	InitStore(NewMemoryStore())
	SetDefaultLevel(lvl)
	levelMu.Lock()
	postLevel = map[int]int{}
	levelMu.Unlock()
}

func browser(a Attempt) Attempt {
	a.UserAgent = "Mozilla/5.0 Chrome/140"
	a.Accept = "*/*"
	a.AcceptLang = "ko-KR"
	a.Host = "rank.example"
	a.Referer = "https://rank.example/post.html?id=1"
	return a
}

func solve(challenge string, bits int) string {
	for n := 0; ; n++ {
		if s := strconv.Itoa(n); CheckPoW(challenge, s, bits) {
			return s
		}
	}
}

// 쿠키를 매번 새로 받아와도 같은 IP 면 Lv2 에서 중복이어야 한다 (예전엔 ip+token 합친 키라 뚫렸음).
func TestLv2FreshCookieSameIPIsDuplicate(t *testing.T) {
	setup(t, 2)
	if d := Judge(Attempt{PostID: 1, IP: "1.1.1.1", Token: "a"}); !d.Counted {
		t.Fatalf("first should count: %+v", d)
	}
	if d := Judge(Attempt{PostID: 1, IP: "1.1.1.1", Token: "b"}); d.Counted {
		t.Fatalf("new cookie, same IP should be duplicate: %+v", d)
	}
}

// Lv2 는 XFF 를 믿고(의도된 취약점), Lv3 부터는 실제 IP 로 판정한다.
func TestXFFSpoofOnlyWorksUpToLv2(t *testing.T) {
	setup(t, 2)
	Judge(Attempt{PostID: 1, IP: "9.9.9.9", ClaimedIP: "1.0.0.1"})
	if d := Judge(Attempt{PostID: 1, IP: "9.9.9.9", ClaimedIP: "1.0.0.2"}); !d.Counted {
		t.Fatalf("Lv2 should trust spoofed XFF: %+v", d)
	}

	setup(t, 3)
	Judge(Attempt{PostID: 1, IP: "9.9.9.9", ClaimedIP: "1.0.0.1"})
	if d := Judge(Attempt{PostID: 1, IP: "9.9.9.9", ClaimedIP: "1.0.0.2"}); d.Counted || d.Reason != ReasonDuplicate {
		t.Fatalf("Lv3 should ignore XFF: %+v", d)
	}
}

func TestLv3RateLimitPerRealIP(t *testing.T) {
	setup(t, 3)
	var last Decision
	for i := 0; i <= RateMax; i++ {
		last = Judge(Attempt{PostID: 1, IP: "2.2.2.2", Token: "t" + strconv.Itoa(i)})
	}
	if last.Reason != ReasonRateLimited {
		t.Fatalf("expected rate limit, got %+v", last)
	}
}

func TestLv4RequiresBrowserHeaders(t *testing.T) {
	setup(t, 4)
	a := browser(Attempt{PostID: 1, IP: "3.3.3.3"})
	a.Referer = ""
	if d := Judge(a); d.Reason != ReasonBot {
		t.Fatalf("missing referer should be bot: %+v", d)
	}
	a = browser(Attempt{PostID: 1, IP: "3.3.3.3"})
	a.Referer = "https://evil.example/x"
	if d := Judge(a); d.Reason != ReasonBot {
		t.Fatalf("cross-origin referer should be bot: %+v", d)
	}
	if d := Judge(browser(Attempt{PostID: 1, IP: "3.3.3.4"})); !d.Counted {
		t.Fatalf("real browser headers should count: %+v", d)
	}
}

func TestLv5ProofBindingAndPoW(t *testing.T) {
	setup(t, 5)
	MinDwell = 0
	defer func() { MinDwell = 5 * time.Second }()

	tok, ch := IssueProof(1, "4.4.4.4", "owner")
	pow := solve(ch, PoWBits)

	// 다른 IP 에서 사용
	if d := Judge(browser(Attempt{PostID: 1, IP: "4.4.4.5", Token: "owner", ProofToken: tok, PoW: pow})); d.Reason != ReasonProofBind {
		t.Fatalf("other IP: %+v", d)
	}
	// 다른 쿠키로 사용
	if d := Judge(browser(Attempt{PostID: 1, IP: "4.4.4.4", Token: "other", ProofToken: tok, PoW: pow})); d.Reason != ReasonProofBind {
		t.Fatalf("other cookie: %+v", d)
	}
	// PoW 없음
	if d := Judge(browser(Attempt{PostID: 1, IP: "4.4.4.4", Token: "owner", ProofToken: tok})); d.Reason != ReasonBadPoW {
		t.Fatalf("no pow: %+v", d)
	}
	// 정상
	if d := Judge(browser(Attempt{PostID: 1, IP: "4.4.4.4", Token: "owner", ProofToken: tok, PoW: pow})); !d.Counted {
		t.Fatalf("valid proof should count: %+v", d)
	}
	// 재사용
	if d := Judge(browser(Attempt{PostID: 1, IP: "4.4.4.4", Token: "owner", ProofToken: tok, PoW: pow})); d.Counted {
		t.Fatalf("reuse should fail: %+v", d)
	}
}

func TestLv5DwellRequired(t *testing.T) {
	setup(t, 5)
	tok, ch := IssueProof(1, "5.5.5.5", "o")
	d := Judge(browser(Attempt{PostID: 1, IP: "5.5.5.5", Token: "o", ProofToken: tok, PoW: solve(ch, PoWBits)}))
	if d.Reason != ReasonDwellShort {
		t.Fatalf("no heartbeat should be dwell_too_short: %+v", d)
	}
}

func TestLevelsSurviveRestartAndReset(t *testing.T) {
	setup(t, 0)
	s := NewMemoryStore()
	InitStore(s)
	SetDefaultLevel(5)
	SetPostLevel(3, 2)
	Reset()

	levelMu.Lock()
	defaultLevel, postLevel = 0, map[int]int{}
	levelMu.Unlock()
	InitStore(s) // 재시작 흉내
	if DefaultLevel() != 5 || LevelFor(3) != 2 {
		t.Fatalf("levels not restored: default=%d post3=%d", DefaultLevel(), LevelFor(3))
	}
}
