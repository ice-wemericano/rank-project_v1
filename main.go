package main

import (
	"net/http"
	"os"
	"strconv"

	"rank-project_v1/db"
	"rank-project_v1/defense"
	"rank-project_v1/logs"
	"rank-project_v1/router"

	"github.com/joho/godotenv"
)

func main() {
	// 환경설정 (.env 가 없으면 이미 주입된 환경변수 사용 - Docker --env-file 등)
	if err := godotenv.Load(); err != nil {
		logs.Log("MAIN", ".env 없음 - 프로세스 환경변수 사용")
	}

	// HMAC 서명 키 (쿠키/열람증명 토큰 서명용). 다중 서버면 같은 SECRET_KEY 를 공유해야 한다.
	if defense.InitSecret(os.Getenv("SECRET_KEY")) {
		logs.Log("MAIN", "서명 키: SECRET_KEY 사용")
	} else {
		logs.Log("MAIN", "[WARN] SECRET_KEY 없음 - 임시 키 생성(단일 서버 전용, 재시작 시 기존 쿠키/토큰 무효)")
	}

	// 방어 상태 저장소: REDIS_ADDR 가 있으면 Redis(재시작·다중서버 유지), 없으면 메모리.
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		rdb, _ := strconv.Atoi(os.Getenv("REDIS_DB"))
		if rs, err := defense.NewRedisStore(addr, os.Getenv("REDIS_PASSWORD"), rdb); err != nil {
			logs.Log("MAIN", "[WARN] Redis 연결 실패 - 메모리 저장소로 폴백: "+err.Error())
		} else {
			defense.InitStore(rs)
			logs.Log("MAIN", "방어 상태 저장소: Redis "+addr)
		}
	} else {
		logs.Log("MAIN", "방어 상태 저장소: 메모리 (REDIS_ADDR 설정 시 Redis 사용)")
	}

	// DB 연결 (NAS 다운 등으로 실패해도 서버는 뜬다 - degraded mode).
	// database/sql 풀은 지연 재연결하므로, NAS가 살아나면 자동으로 쿼리가 성공한다.
	if err := db.Init(); err != nil {
		logs.Log("MAIN", "[WARN] DB 연결 실패 - 축소 모드로 시작합니다 (NAS 복구 시 자동 연결): "+err.Error())
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

	logs.Log("MAIN", "Server started on :"+port)

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		panic(err)
	}
}
