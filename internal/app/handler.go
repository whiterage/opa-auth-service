package app

import (
	"encoding/json"
	"net/http"
)

func resourceHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "protected resource",
	})
}
