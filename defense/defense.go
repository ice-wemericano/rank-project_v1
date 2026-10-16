// Package defense 는 조회수 어뷰징 방어 로직을 담는다.
//
// 방어는 레벨 0~5 로 누적 적용된다. 관리자가 레벨을 올릴수록 방어가 겹겹이 쌓인다.
//
//	Lv0  방어 없음            - 요청마다 무조건 +1 (참가자 워밍업용)
//	Lv1  쿠키 토큰 중복제거    - 같은 브라우저는 일정 시간 1회만     (쿠키 삭제/시크릿창으로 우회)
//	Lv2  + IP 중복제거         - 같은 IP도 묶음                      (X-Forwarded-For 조작으로 우회 - 의도된 취약점)
//	Lv3  + 요청속도 제한       - IP·토큰당 짧은 시간 요청수 상한      (여러 IP / 천천히 보내기로 우회)
//	Lv4  + 봇 판별 휴리스틱     - UA/Accept 헤더 검사                 (정상 브라우저 헤더 위장으로 우회)
//	Lv5  + 열람증명            - 서명 토큰 + 서버측 heartbeat 누적     (토큰 위조 불가, 실제 체류 입증 필요)
//
// 상태(중복/속도/열람증명)는 Store 에 저장한다. Redis 를 쓰면 재시작·다중서버에서 유지된다.
package defense

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// 조회 시도에 대한 판정 사유 코드. view_events.reason 에 그대로 저장된다.
const (
	ReasonCounted     = "counted"         // 정상 반영
	ReasonDuplicate   = "duplicate"       // 중복 조회
	ReasonRateLimited = "rate_limited"    // 요청속도 초과
	ReasonBot         = "bot"             // 봇 판정
	ReasonNoProof     = "no_proof"        // 열람증명 토큰 없음/위조/만료
	ReasonDwellShort  = "dwell_too_short" // 체류시간 미달 (heartbeat 누적 부족)
)

// 방어 파라미터 (실습하면서 값을 조절해도 된다).
var (
	DedupWindow  = 30 * time.Minute // 같은 식별자가 같은 글을 다시 세기까지의 간격
	RateWindow   = 10 * time.Second // 요청속도 측정 구간
	RateMax      = 5                // RateWindow 동안 허용하는 최대 시도 수
	ProofTTL     = 5 * time.Minute  // 열람증명 토큰 유효시간
	MinDwell     = 3 * time.Second  // 열람증명: 최소 (누적) 체류시간
	HeartbeatGap = 5 * time.Second  // heartbeat 간격이 이보다 크면 연속 체류로 인정하지 않음
)

// store 는 방어 상태 저장소. InitStore 로 설정한다(기본은 메모리).
var store Store = NewMemoryStore()

// InitStore 는 상태 저장소를 교체한다(예: Redis).
func InitStore(s Store) { store = s }

type Attempt struct {
	PostID     int
	IP         string
	Token      string // 브라우저 식별용 쿠키 토큰 (서명 검증을 통과한 값; 없을 수 있음)
	UserAgent  string
	Accept     string
	ProofToken string // 열람증명 토큰 (Lv5)
	Now        time.Time
}

type Decision struct {
	Counted bool
	Reason  string
}

// ---------- 방어 레벨 (게시글별 + 기본) ----------

var (
	levelMu      sync.Mutex
	defaultLevel int
	postLevel    = map[int]int{}
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
	levelMu.Lock()
	defaultLevel = clamp(l)
	levelMu.Unlock()
}

func SetPostLevel(postID, l int) {
	levelMu.Lock()
	postLevel[postID] = clamp(l)
	levelMu.Unlock()
}

func ClearPostLevel(postID int) {
	levelMu.Lock()
	delete(postLevel, postID)
	levelMu.Unlock()
}

func LevelFor(postID int) int {
	levelMu.Lock()
	defer levelMu.Unlock()
	if l, ok := postLevel[postID]; ok {
		return l
	}
	return defaultLevel
}

func DefaultLevel() int {
	levelMu.Lock()
	defer levelMu.Unlock()
	return defaultLevel
}

// ---------- 열람증명 (Lv5) ----------

// IssueProof 는 서명된 열람증명 토큰을 발급하고 서버측 상태를 저장한다.
func IssueProof(postID int, ip string) string {
	token, nonce := IssueProofToken(postID, ip)
	now := time.Now()
	_ = store.PutProof(nonce, ProofState{
		PostID: postID, IP: ip, IssuedAt: now, LastBeat: now, ActiveMS: 0,
	}, ProofTTL)
	return token
}

// Heartbeat 는 글을 보고 있는 동안 주기적으로 호출된다. 서버가 실제 체류시간을 누적한다.
// 반환값은 토큰 유효 여부.
func Heartbeat(postID int, token, ip string) bool {
	p, ok := VerifyProofToken(token)
	if !ok || p.PostID != postID {
		return false
	}
	st, err := store.GetProof(p.Nonce)
	if err != nil || st == nil {
		return false
	}
	now := time.Now()
	// 연속 체류로 인정되는 간격(HeartbeatGap) 이내일 때만 누적한다.
	if gap := now.Sub(st.LastBeat); gap > 0 && gap <= HeartbeatGap {
		st.ActiveMS += gap.Milliseconds()
	}
	st.LastBeat = now
	_ = store.PutProof(p.Nonce, *st, ProofTTL)
	return true
}

// ---------- 판정 ----------

func Judge(a Attempt) Decision {
	lvl := LevelFor(a.PostID)

	// Lv4+ : 봇 판별
	if lvl >= 4 && isBot(a) {
		return Decision{false, ReasonBot}
	}

	// Lv3+ : 요청속도 제한
	if lvl >= 3 {
		if n, err := store.Incr("ip:"+a.IP+"|t:"+a.Token, RateWindow); err == nil && n > RateMax {
			return Decision{false, ReasonRateLimited}
		}
	}

	// Lv5 : 열람증명 (서명 검증 + heartbeat 누적 체류 + 일회성 소비)
	if lvl >= 5 {
		p, ok := VerifyProofToken(a.ProofToken)
		if !ok || p.PostID != a.PostID {
			return Decision{false, ReasonNoProof}
		}
		st, err := store.ConsumeProof(p.Nonce) // 원자적 get+delete: 재사용 차단
		if err != nil || st == nil {
			return Decision{false, ReasonNoProof}
		}
		if st.ActiveMS < MinDwell.Milliseconds() {
			return Decision{false, ReasonDwellShort}
		}
	}

	// Lv1+ : 중복제거
	if lvl >= 1 {
		key, canDedup := dedupKey(a, lvl)
		if !canDedup {
			// Lv1 에서 쿠키가 없으면 식별 불가 → 세지 못함(통과). 쿠키 삭제로 Lv1 을 뚫는 경로.
			return Decision{true, ReasonCounted}
		}
		first, err := store.FirstWithin(key, DedupWindow)
		if err == nil && !first {
			return Decision{false, ReasonDuplicate}
		}
	}

	return Decision{true, ReasonCounted}
}

// Reset 은 방어 상태를 초기화한다.
func Reset() { _ = store.Flush() }

// dedupKey 는 중복 판정에 쓸 식별자와, 식별 가능 여부를 돌려준다.
// a.Token 은 "클라이언트가 보낸(서명 검증을 통과한) 쿠키 값"이어야 한다.
func dedupKey(a Attempt, lvl int) (string, bool) {
	p := "|p:" + strconv.Itoa(a.PostID)
	if lvl < 2 {
		// Lv1: 쿠키 토큰으로만 식별. 토큰이 없으면 식별 불가.
		if a.Token == "" {
			return "", false
		}
		return "t:" + a.Token + p, true
	}
	// Lv2+: IP 를 기준으로 묶는다(+토큰이 있으면 함께). 쿠키를 지워도 같은 IP 면 묶인다.
	key := "ip:" + a.IP
	if a.Token != "" {
		key += "|t:" + a.Token
	}
	return key + p, true
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
	// 정상 브라우저는 Accept 헤더를 보낸다.
	return a.Accept == ""
}
