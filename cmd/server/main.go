package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"testsbertech/internal/authz"
	"testsbertech/policy"
)

func main() {
	authorizer, err := authz.New(context.Background(), policy.Source)
	if err != nil {
		log.Fatalf("initialize authorization: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /resource", resourceHandler)

	protected := authz.Middleware(authorizer, authz.MockJWTParser{})(mux)

	server := &http.Server{
		Addr:    ":8080",
		Handler: protected,
	}

	log.Printf("listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("run HTTP server: %v", err)
	}
}

func resourceHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message": "protected resource",
	})
}
