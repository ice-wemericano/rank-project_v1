package router

import (
	"net/http"

	"rank-project_v1/service"
)

func Init() {
	// 게시판
	http.HandleFunc("/api/posts", service.Posts)                    // 목록
	http.HandleFunc("/api/posts/open", service.Open)                // 글 열기 + 열람증명 토큰 발급
	http.HandleFunc("/api/posts/heartbeat", service.Heartbeat)      // 열람 heartbeat (Lv5)
	http.HandleFunc("/api/posts/register-key", service.RegisterKey) // 디바이스 공개키 등록 (Lv7)
	http.HandleFunc("/api/posts/view", service.View)                // 조회수 증가 시도 (방어 로직)

	// 대시보드 / 관리
	http.HandleFunc("/api/dashboard", service.Dashboard) // 집계
	http.HandleFunc("/api/admin/level", service.Level)   // 방어 레벨 조회/변경
	http.HandleFunc("/api/admin/reset", service.Reset)   // 조회수/기록 초기화
}
