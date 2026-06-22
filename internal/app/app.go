package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"testsbertech/internal/authz"
)

func Run(ctx context.Context) error {
	policyPath := os.Getenv("POLICY_PATH")
	if policyPath == "" {
		policyPath = "policy/authz.rego"
	}

	authorizer, err := authz.NewFromFile(ctx, policyPath, func(err error) {
		log.Printf("policy hot-reload failed, keeping previous policy: %v", err)
	})
	if err != nil {
		return fmt.Errorf("initialize authorization: %w", err)
	}
	log.Printf("authorization policy loaded from %s; hot-reload enabled", policyPath)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /resource", resourceHandler)

	server := &http.Server{
		Addr: ":8080",
		Handler: authz.Middleware(
			authorizer,
			authz.MockJWTParser{},
		)(mux),
	}

	log.Printf("listening on %s", server.Addr)

	if err := server.ListenAndServe(); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("run HTTP server: %w", err)
	}

	return nil
}
