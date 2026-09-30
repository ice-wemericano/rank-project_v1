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

	// DB 연결
	if err := db.Init(); err != nil {
		panic("DB connection failed: " + err.Error())
	}
	defer db.DB.Close()

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
