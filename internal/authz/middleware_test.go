package authz_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"testsbertech/internal/authz"
	"testsbertech/policy"
)

func TestMiddleware(t *testing.T) {
	authorizer, err := authz.New(context.Background(), policy.Source)
	if err != nil {
		t.Fatalf("create authorizer: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := authz.Middleware(authorizer, authz.MockJWTParser{})(next)

	tests := []struct {
		name       string
		method     string
		roles      []string
		wantStatus int
	}{
		{
			name:       "reader may GET",
			method:     http.MethodGet,
			roles:      []string{"reader"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "guest may not GET",
			method:     http.MethodGet,
			roles:      []string{"guest"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "reader may not POST",
			method:     http.MethodPost,
			roles:      []string{"reader"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "admin may POST",
			method:     http.MethodPost,
			roles:      []string{"admin"},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(tt.method, "/resource", nil)
			request.Header.Set("Authorization", "Bearer "+mockJWT(tt.roles))
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body = %q", response.Code, tt.wantStatus, response.Body.String())
			}
		})
	}
}

func mockJWT(roles []string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"realm_access":{"roles":%s}}`, string(mustJSON(roles)),
	)))

	return header + "." + claims + ".mock-signature"
}

func mustJSON(roles []string) []byte {
	if len(roles) == 0 {
		return []byte("[]")
	}

	result := []byte{'['}
	for i, role := range roles {
		if i > 0 {
			result = append(result, ',')
		}
		result = fmt.Appendf(result, "%q", role)
	}
	return append(result, ']')
}
