package main

import (
	"fmt"
	"net/http"
	"os"

	"rank-project_v1/db"
	"rank-project_v1/router"

	"github.com/joho/godotenv"
)

func main() {
	// 환경설정
	if err := godotenv.Load(); err != nil {
		panic("Failed to load .env")
	}

	// DB 연결 (NAS 다운 등으로 실패해도 서버는 뜬다 - degraded mode).
	// database/sql 풀은 지연 재연결하므로, NAS가 살아나면 자동으로 쿼리가 성공한다.
	if err := db.Init(); err != nil {
		fmt.Println("[WARN] DB 연결 실패 - 축소 모드로 시작합니다 (NAS 복구 시 자동 연결):", err)
	}
	if db.DB != nil {
		defer db.DB.Close()
	}

	// 라우터 초기화
	router.Init()

	// js 연결
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	port := os.Getenv("SERVER_PORT")

	fmt.Println("Server started on :" + port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		panic(err)
	}
}
