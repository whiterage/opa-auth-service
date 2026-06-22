package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type DecisionMaker interface {
	Allow(context.Context, Input) (bool, error)
}

type RoleParser interface {
	ParseRoles(string) ([]string, error)
}

func Middleware(decisions DecisionMaker, tokens RoleParser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				http.Error(w, "missing or invalid bearer token", http.StatusUnauthorized)
				return
			}

			roles, err := tokens.ParseRoles(token)
			if err != nil {
				http.Error(w, "invalid bearer token", http.StatusUnauthorized)
				return
			}

			allowed, err := decisions.Allow(r.Context(), Input{
				Method: r.Method,
				Path:   r.URL.Path,
				Roles:  roles,
			})
			if err != nil {
				http.Error(w, "authorization failed", http.StatusInternalServerError)
				return
			}
			if !allowed {
				writeJSONError(
					w,
					http.StatusForbidden,
					"forbidden",
					"access denied by authorization policy",
				)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}

	return parts[1], true
}
