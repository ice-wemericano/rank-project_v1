package defense

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ReasonCounted     = "counted"         // 정상 반영
	ReasonDuplicate   = "duplicate"       // 중복 조회
	ReasonRateLimited = "rate_limited"    // 요청속도 초과
	ReasonBot         = "bot"             // 봇 판정
	ReasonNoProof     = "no_proof"        // 열람증명 토큰 없음/불일치/만료
	ReasonDwellShort  = "dwell_too_short" // 체류시간 미달
)

var (
	DedupWindow = 30 * time.Minute // 같은 식별자가 같은 글을 다시 세기까지의 간격
	RateWindow  = 10 * time.Second // 요청속도 측정 구간
	RateMax     = 5                // RateWindow 동안 허용하는 최대 시도 수
	ProofTTL    = 5 * time.Minute  // 열람증명 토큰 유효시간
	MinDwell    = 3 * time.Second  // 열람증명: 최소 체류시간
)

type Attempt struct {
	PostID     int
	IP         string
	Token      string // 브라우저 식별용 쿠키 토큰 (없을 수 있음)
	UserAgent  string
	Accept     string
	ProofToken string // 열람증명 토큰 (Lv5)
	Now        time.Time
}

type Decision struct {
	Counted bool
	Reason  string
}

type proof struct {
	postID   int
	ip       string
	issuedAt time.Time
	used     bool
}

var (
	mu           sync.Mutex
	defaultLevel int                        // 게시글별 설정이 없을 때 적용되는 기본 레벨
	postLevel    = map[int]int{}            // 게시글(id) -> 방어 레벨 (개인별 난이도)
	lastHit      = map[string]time.Time{}   // 중복제거: 식별자 -> 마지막 반영시각
	hits         = map[string][]time.Time{} // 속도제한: 식별자 -> 최근 시도 시각들
	proofs       = map[string]*proof{}      // 열람증명 토큰 보관
)

func clamp(l int) int {
	if l < 0 {
		return 0
	}
	if l > 5 {
		return 5
	}
	return l
}

func SetDefaultLevel(l int) {
	mu.Lock()
	defaultLevel = clamp(l)
	mu.Unlock()
}

func SetPostLevel(postID, l int) {
	mu.Lock()
	postLevel[postID] = clamp(l)
	mu.Unlock()
}

func ClearPostLevel(postID int) {
	mu.Lock()
	delete(postLevel, postID)
	mu.Unlock()
}

func levelForLocked(postID int) int {
	if l, ok := postLevel[postID]; ok {
		return l
	}
	return defaultLevel
}

func LevelFor(postID int) int {
	mu.Lock()
	defer mu.Unlock()
	return levelForLocked(postID)
}

func DefaultLevel() int {
	mu.Lock()
	defer mu.Unlock()
	return defaultLevel
}

func IssueProof(postID int, ip string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	mu.Lock()
	proofs[tok] = &proof{postID: postID, ip: ip, issuedAt: time.Now()}
	mu.Unlock()
	return tok
}

func Judge(a Attempt) Decision {
	mu.Lock()
	defer mu.Unlock()
	lvl := levelForLocked(a.PostID)

	// Lv4+ : 봇 판별
	if lvl >= 4 && isBot(a) {
		return Decision{false, ReasonBot}
	}

	// Lv3+ : 요청속도 제한 (시도는 항상 기록하고, 초과면 거절)
	if lvl >= 3 {
		if rateLimited("ip:"+a.IP+"|t:"+a.Token, a.Now) {
			return Decision{false, ReasonRateLimited}
		}
	}

	// Lv5 : 열람증명 (토큰 유효성 + 최소 체류)
	if lvl >= 5 {
		p := proofs[a.ProofToken]
		if p == nil || p.used || p.postID != a.PostID || p.ip != a.IP ||
			a.Now.Sub(p.issuedAt) > ProofTTL {
			return Decision{false, ReasonNoProof}
		}
		if a.Now.Sub(p.issuedAt) < MinDwell {
			return Decision{false, ReasonDwellShort}
		}
		p.used = true // 일회용: 재사용 차단
	}

	// Lv1+ : 중복제거
	if lvl >= 1 {
		// Lv1 은 쿠키 토큰으로만 구분한다. 토큰이 없으면(쿠키 삭제) 구분 불가 → 통과 (의도된 우회 경로)
		if a.Token == "" && lvl < 2 {
			return Decision{true, ReasonCounted}
		}
		key := dedupKey(a, lvl)
		if t, ok := lastHit[key]; ok && a.Now.Sub(t) < DedupWindow {
			return Decision{false, ReasonDuplicate}
		}
		lastHit[key] = a.Now
	}

	return Decision{true, ReasonCounted}
}

func Reset() {
	mu.Lock()
	lastHit = map[string]time.Time{}
	hits = map[string][]time.Time{}
	proofs = map[string]*proof{}
	mu.Unlock()
}

func dedupKey(a Attempt, lvl int) string {
	key := "t:" + a.Token
	if lvl >= 2 { // Lv2 부터는 IP 도 식별자에 포함
		key += "|ip:" + a.IP
	}
	return key + "|p:" + strconv.Itoa(a.PostID)
}

func rateLimited(id string, now time.Time) bool {
	cut := now.Add(-RateWindow)
	kept := hits[id][:0]
	for _, t := range hits[id] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	hits[id] = kept
	return len(kept) > RateMax
}

func isBot(a Attempt) bool {
	ua := strings.ToLower(a.UserAgent)
	if ua == "" {
		return true
	}
	for _, m := range []string{"curl", "wget", "python", "go-http", "bot", "spider", "scrapy", "postman", "httpclient", "java/", "okhttp"} {
		if strings.Contains(ua, m) {
			return true
		}
	}

	return a.Accept == ""
}
