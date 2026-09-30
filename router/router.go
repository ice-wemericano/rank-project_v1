package router

import (
	"net/http"

	"rank-project_v1/service"
)

func Init() {
	http.HandleFunc("/api/test", service.Test)
}
