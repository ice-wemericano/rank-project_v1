package service

import (
	"encoding/json"
	"net/http"
)

func Test(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"success": true,
		"message": "API Connection Successful",
	}

	json.NewEncoder(w).Encode(response)
}
