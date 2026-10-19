package service

import (
	"net/http"
	"time"

	"rank-project_v1/db"
	"rank-project_v1/defense"
)

// Posts 는 게시판 목록을 돌려준다.  GET /api/posts
func Posts(w http.ResponseWriter, r *http.Request) {
	posts, err := db.ListPosts()
	if err == db.ErrNoDB {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DB 연결 대기 중 (NAS)"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DB 연결 대기 중 (NAS)"})
		return
	}
	// 각 글에 현재 적용된 방어 레벨을 붙여준다.
	for i := range posts {
		posts[i].Level = defense.LevelFor(posts[i].ID)
	}
	writeJSON(w, http.StatusOK, posts)
}

// Open 은 글을 열 때 호출한다. 글 내용과 (Lv5용) 열람증명 토큰을 발급한다.
//
//	GET /api/posts/open?id=1
func Open(w http.ResponseWriter, r *http.Request) {
	id := atoiDefault(r.URL.Query().Get("id"), 0)
	if id == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id 필요"})
		return
	}

	// 정상 사용자에게 식별용 쿠키 발급 (Lv1 식별용). 열람증명은 이 쿠키에 묶인다.
	owner := ensureCookie(w, r)

	post, err := db.GetPost(id)
	if err == db.ErrNoDB {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DB 연결 대기 중 (NAS)"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "글 없음"})
		return
	}

	post.Level = defense.LevelFor(id)
	proof, challenge := defense.IssueProof(id, realIP(r), owner)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"post":          post,
		"proof_token":   proof,
		"min_dwell_ms":  defense.MinDwell.Milliseconds(),
		"pow_challenge": challenge,
		"pow_bits":      defense.PoWBits,
	})
}

// Heartbeat 는 글을 보고 있는 동안 주기적으로 호출된다(Lv5).
// 서버가 실제 체류시간을 누적한다. 클라이언트가 보낸 체류시간을 믿지 않는다.
//
//	GET /api/posts/heartbeat?id=1&pt=<proof_token>
func Heartbeat(w http.ResponseWriter, r *http.Request) {
	id := atoiDefault(r.URL.Query().Get("id"), 0)
	if id == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id 필요"})
		return
	}
	ok := defense.Heartbeat(id, r.URL.Query().Get("pt"), realIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": ok})
}

// RegisterKey 는 Lv7 디바이스 공개키를 현재 신원(owner 쿠키)에 묶어 서명한 dkey 쿠키를 발급한다.
//
//	POST /api/posts/register-key?pub=<SPKI base64url>
func RegisterKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST 필요"})
		return
	}
	pub := r.URL.Query().Get("pub")
	if pub == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "pub 필요"})
		return
	}
	owner := ensureCookie(w, r) // 식별용 쿠키 보장 + owner 확보
	dtoken := defense.IssueDeviceToken(owner, pub)
	http.SetCookie(w, &http.Cookie{
		Name:     deviceCookie,
		Value:    dtoken,
		Path:     "/",
		HttpOnly: false,
		MaxAge:   60 * 60 * 24,
	})
	writeJSON(w, http.StatusOK, map[string]string{"dkey": dtoken})
}

func View(w http.ResponseWriter, r *http.Request) {
	id := atoiDefault(r.URL.Query().Get("id"), 0)
	if id == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id 필요"})
		return
	}

	// 식별자는 "클라이언트가 보낸" 쿠키만 사용한다. 쿠키가 없으면 새로 발급하되,
	// 이번 요청의 식별자로는 쓰지 않는다(쿠키를 매번 지우면 Lv1 을 우회하게 됨).
	token := sentToken(r)
	ensureCookie(w, r)
	ip := realIP(r)
	now := time.Now()

	decision := defense.Judge(defense.Attempt{
		PostID:     id,
		IP:         ip,
		ClaimedIP:  claimedIP(r),
		Token:      token,
		UserAgent:  r.UserAgent(),
		Accept:     r.Header.Get("Accept"),
		AcceptLang: r.Header.Get("Accept-Language"),
		Referer:    r.Referer(),
		Host:       r.Host,
		ProofToken:  r.URL.Query().Get("pt"),
		PoW:         r.URL.Query().Get("pow"),
		DeviceToken: sentDeviceToken(r),
		DeviceSig:   r.URL.Query().Get("dsig"),
		Now:         now,
	})

	// 반영 결정 시 조회수 증가 (원자적 UPDATE)
	if decision.Counted {
		if err := db.IncrementView(id); err != nil {
			// 조회수 증가 실패 시 반영 취소하고 사유 기록
			decision = defense.Decision{Counted: false, Reason: "db_error"}
		}
	}

	// 모든 시도 기록 (DB 없으면 조용히 건너뜀 - 응답은 정상 진행)
	_ = db.InsertViewEvent(db.ViewEvent{
		PostID:    id,
		IP:        ip,
		Token:     token,
		UserAgent: r.UserAgent(),
		Reason:    decision.Reason,
		Counted:   decision.Counted,
		CreatedAt: now,
	})

	// Lv9: 응답 불투명화(섀도밴). 공격자에게 "왜 막혔는지" 오라클을 주지 않는다.
	// 진짜 판정(decision)은 위에서 이미 DB 에 그대로 기록했고, 조회수도 진짜 판정대로만 증가한다.
	// 공개 응답만 항상 "반영됨"처럼 보이게 가린다 → 공격자는 성공/실패를 구분하지 못한다.
	lvl := defense.LevelFor(id)
	counted, reason := decision.Counted, decision.Reason
	if lvl >= 9 {
		counted, reason = true, defense.ReasonCounted
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"counted": counted,
		"reason":  reason,
		"level":   lvl,
	})
}
