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

	// 쿠키 토큰 보장 (Lv1 식별용)
	browserToken(w, r)

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
	proof := defense.IssueProof(id, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"post":         post,
		"proof_token":  proof,
		"min_dwell_ms": defense.MinDwell.Milliseconds(),
	})
}

func View(w http.ResponseWriter, r *http.Request) {
	id := atoiDefault(r.URL.Query().Get("id"), 0)
	if id == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id 필요"})
		return
	}

	token := browserToken(w, r)
	ip := clientIP(r)
	now := time.Now()

	decision := defense.Judge(defense.Attempt{
		PostID:     id,
		IP:         ip,
		Token:      token,
		UserAgent:  r.UserAgent(),
		Accept:     r.Header.Get("Accept"),
		ProofToken: r.URL.Query().Get("pt"),
		Now:        now,
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"counted": decision.Counted,
		"reason":  decision.Reason,
		"level":   defense.LevelFor(id),
	})
}
