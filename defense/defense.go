// Package defense 는 조회수 어뷰징 방어 로직을 담는다.
//
// 방어는 레벨 0~5 로 누적 적용된다. 관리자가 레벨을 올릴수록 방어가 겹겹이 쌓인다.
//
//	Lv0  방어 없음            - 요청마다 무조건 +1 (참가자 워밍업용)
//	Lv1  쿠키 토큰 중복제거    - 같은 브라우저는 일정 시간 1회만     (쿠키 삭제/시크릿창으로 우회)
//	Lv2  + IP 중복제거         - IP·쿠키 중 하나라도 겹치면 중복      (X-Forwarded-For 조작으로 우회 - 의도된 취약점)
//	Lv3  + 실제 IP + 속도제한   - XFF 무시(실접속 IP), 24시간 중복창,  (실제로 다른 IP 가 여러 개 있어야 함)
//	                              IP당 짧은 시간 요청수 상한
//	Lv4  + 봇 판별 휴리스틱     - UA/Accept/Accept-Language/Referer   (정상 브라우저 헤더 위장으로 우회)
//	Lv5  + 열람증명            - 서명 토큰(IP·쿠키 바인딩) + 서버측   (토큰 위조·공유 불가, 실제 체류 +
//	                              heartbeat 누적 + 작업증명(PoW)        요청마다 연산비용 필요)
//
// 상태(중복/속도/열람증명)는 Store 에 저장한다. Redis 를 쓰면 재시작·다중서버에서 유지된다.
package defense

import (
	"crypto/sha256"
	"encoding/json"
	"net/url"
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
	ReasonProofBind   = "proof_mismatch"  // 열람증명이 다른 IP/쿠키에서 발급됨 (토큰 공유·탈취)
	ReasonBadPoW      = "bad_pow"         // 작업증명(PoW) 없음/틀림
)

// 방어 파라미터 (실습하면서 값을 조절해도 된다).
var (
	DedupWindow       = 30 * time.Minute // Lv1~2: 같은 식별자가 같은 글을 다시 세기까지의 간격
	StrictDedupWindow = 24 * time.Hour   // Lv3+: 실제 IP 기준 중복창 (하루 1회)
	RateWindow        = 10 * time.Second // 요청속도 측정 구간
	RateMax           = 5                // RateWindow 동안 IP당 허용하는 최대 시도 수
	ProofTTL          = 5 * time.Minute  // 열람증명 토큰 유효시간
	MinDwell          = 5 * time.Second  // 열람증명: 최소 (누적) 체류시간
	HeartbeatGap      = 3 * time.Second  // heartbeat 간격이 이보다 크면 연속 체류로 인정하지 않음
	PoWBits           = 18               // 작업증명 난이도 (선행 0 비트 수, 브라우저 기준 ~0.5초)
)

// store 는 방어 상태 저장소. InitStore 로 설정한다(기본은 메모리).
var store Store = NewMemoryStore()

// InitStore 는 상태 저장소를 교체한다(예: Redis). 저장된 방어 레벨이 있으면 불러온다.
func InitStore(s Store) {
	store = s
	loadLevels()
}

type Attempt struct {
	PostID     int
	IP         string // 실제 접속 IP (위조 불가)
	ClaimedIP  string // X-Forwarded-For 맨 앞 값 (클라이언트가 조작 가능 - Lv2 의도된 취약점)
	Token      string // 브라우저 식별용 쿠키 토큰 (서명 검증을 통과한 값; 없을 수 있음)
	UserAgent  string
	Accept     string
	AcceptLang string
	Referer    string
	Host       string // 요청 Host (Referer 동일 출처 확인용)
	ProofToken string // 열람증명 토큰 (Lv5)
	PoW        string // 작업증명 답 (Lv5)
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

type levelConfig struct {
	Default int         `json:"default"`
	Posts   map[int]int `json:"posts"`
}

// saveLevels 는 레벨 설정을 저장소에 남긴다(재배포·재시작해도 방어가 Lv0 으로 풀리지 않게). levelMu 보유 상태로 호출.
func saveLevels() {
	b, _ := json.Marshal(levelConfig{Default: defaultLevel, Posts: postLevel})
	_ = store.SaveLevels(b)
}

func loadLevels() {
	b, err := store.LoadLevels()
	if err != nil || len(b) == 0 {
		return
	}
	var c levelConfig
	if json.Unmarshal(b, &c) != nil {
		return
	}
	levelMu.Lock()
	defaultLevel = clamp(c.Default)
	postLevel = map[int]int{}
	for id, l := range c.Posts {
		postLevel[id] = clamp(l)
	}
	levelMu.Unlock()
}

func SetDefaultLevel(l int) {
	levelMu.Lock()
	defaultLevel = clamp(l)
	saveLevels()
	levelMu.Unlock()
}

func SetPostLevel(postID, l int) {
	levelMu.Lock()
	postLevel[postID] = clamp(l)
	saveLevels()
	levelMu.Unlock()
}

func ClearPostLevel(postID int) {
	levelMu.Lock()
	delete(postLevel, postID)
	saveLevels()
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
// 토큰은 발급받은 실제 IP 와 쿠키 토큰(owner)에 묶인다 → 다른 곳에서 쓰면 거부.
// 두 번째 반환값은 작업증명(PoW) 챌린지다.
func IssueProof(postID int, ip, owner string) (token, challenge string) {
	token, nonce := IssueProofToken(postID, ip, owner)
	now := time.Now()
	_ = store.PutProof(nonce, ProofState{
		PostID: postID, IP: ip, IssuedAt: now, LastBeat: now, ActiveMS: 0,
	}, ProofTTL)
	return token, nonce
}

// CheckPoW 는 sha256(challenge + ":" + answer) 의 선행 0 비트가 bits 이상인지 확인한다.
func CheckPoW(challenge, answer string, bits int) bool {
	if answer == "" || len(answer) > 20 {
		return false
	}
	sum := sha256.Sum256([]byte(challenge + ":" + answer))
	for i := 0; i < bits; i++ {
		if sum[i/8]&(0x80>>(i%8)) != 0 {
			return false
		}
	}
	return true
}

// Heartbeat 는 글을 보고 있는 동안 주기적으로 호출된다. 서버가 실제 체류시간을 누적한다.
// 반환값은 토큰 유효 여부.
func Heartbeat(postID int, token, ip string) bool {
	p, ok := VerifyProofToken(token)
	if !ok || p.PostID != postID || p.IP != ip {
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

	// Lv2 까지는 X-Forwarded-For 를 그대로 믿는다(의도된 취약점). Lv3 부터는 실제 접속 IP 만 쓴다.
	if lvl <= 2 && a.ClaimedIP != "" {
		a.IP = a.ClaimedIP
	}

	// Lv4+ : 봇 판별
	if lvl >= 4 && isBot(a) {
		return Decision{false, ReasonBot}
	}

	// Lv3+ : 요청속도 제한 (실제 IP 기준 - 쿠키를 바꿔도 같은 카운터)
	if lvl >= 3 {
		if n, err := store.Incr("ip:"+a.IP, RateWindow); err == nil && n > RateMax {
			return Decision{false, ReasonRateLimited}
		}
	}

	// Lv5 : 열람증명 (서명 검증 + IP·쿠키 바인딩 + PoW + heartbeat 누적 체류 + 일회성 소비)
	if lvl >= 5 {
		p, ok := VerifyProofToken(a.ProofToken)
		if !ok || p.PostID != a.PostID {
			return Decision{false, ReasonNoProof}
		}
		if p.IP != a.IP || p.Owner == "" || p.Owner != a.Token {
			return Decision{false, ReasonProofBind}
		}
		if !CheckPoW(p.Nonce, a.PoW, PoWBits) {
			return Decision{false, ReasonBadPoW}
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
		keys := dedupKeys(a, lvl)
		if len(keys) == 0 {
			// Lv1 에서 쿠키가 없으면 식별 불가 → 세지 못함(통과). 쿠키 삭제로 Lv1 을 뚫는 경로.
			return Decision{true, ReasonCounted}
		}
		window := DedupWindow
		if lvl >= 3 {
			window = StrictDedupWindow
		}
		// 식별자 중 하나라도 이미 본 적 있으면 중복. (모든 키를 표시해야 하므로 끝까지 돈다)
		dup := false
		for _, k := range keys {
			if first, err := store.FirstWithin(k, window); err == nil && !first {
				dup = true
			}
		}
		if dup {
			return Decision{false, ReasonDuplicate}
		}
	}

	return Decision{true, ReasonCounted}
}

// Reset 은 방어 상태를 초기화한다.
func Reset() { _ = store.Flush() }

// dedupKeys 는 중복 판정에 쓸 식별자들을 돌려준다(비어 있으면 식별 불가).
// a.Token 은 "클라이언트가 보낸(서명 검증을 통과한) 쿠키 값"이어야 한다.
func dedupKeys(a Attempt, lvl int) []string {
	p := "|p:" + strconv.Itoa(a.PostID)
	var keys []string
	if a.Token != "" {
		keys = append(keys, "t:"+a.Token+p)
	}
	if lvl >= 2 {
		// Lv2+: IP 와 쿠키를 "각각" 본다. 새 쿠키를 받아와도 같은 IP 면, IP 를 바꿔도 같은 쿠키면 중복.
		keys = append(keys, "ip:"+a.IP+p)
	}
	return keys
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
	// 정상 브라우저는 Accept / Accept-Language 를 보내고,
	// 글 페이지에서 fetch 하므로 같은 출처의 Referer 가 붙는다.
	if a.Accept == "" || a.AcceptLang == "" {
		return true
	}
	ref, err := url.Parse(a.Referer)
	return a.Referer == "" || err != nil || ref.Host != a.Host
}
