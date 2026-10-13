package service

import (
	"net/http"

	"rank-project_v1/db"
	"rank-project_v1/defense"
)

// Dashboard 는 게시판별 트래픽/반영/미반영 집계를 돌려준다.  GET /api/dashboard
func Dashboard(w http.ResponseWriter, r *http.Request) {
	stats, err := db.Dashboard()
	if err == db.ErrNoDB {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DB 연결 대기 중 (NAS)"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "DB 연결 대기 중 (NAS)"})
		return
	}
	// 각 게시글에 실제 적용되는 레벨을 붙여준다.
	for i := range stats {
		stats[i].Level = defense.LevelFor(stats[i].ID)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"default_level": defense.DefaultLevel(),
		"posts":         stats,
	})
}

func Level(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		l := atoiDefault(r.URL.Query().Get("level"), 0)
		if id := atoiDefault(r.URL.Query().Get("id"), 0); id > 0 {
			defense.SetPostLevel(id, l)
		} else {
			defense.SetDefaultLevel(l)
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"default_level": defense.DefaultLevel()})
}

// Reset 은 방어 상태와 DB의 조회수/이벤트를 초기화한다.  POST /api/admin/reset
func Reset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST 필요"})
		return
	}
	defense.Reset()
	if err := db.ResetStats(); err != nil && err != db.ErrNoDB {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
