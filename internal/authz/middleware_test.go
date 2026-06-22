package authz_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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
		wantError  string
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
			wantError:  "forbidden",
		},
		{
			name:       "reader may not POST",
			method:     http.MethodPost,
			roles:      []string{"reader"},
			wantStatus: http.StatusForbidden,
			wantError:  "forbidden",
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
			if tt.wantError != "" {
				var body struct {
					Error   string `json:"error"`
					Message string `json:"message"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatalf("decode error body: %v", err)
				}
				if body.Error != tt.wantError || body.Message == "" {
					t.Fatalf("error body = %#v, want error %q and non-empty message", body, tt.wantError)
				}
			}
		})
	}
}

func TestMiddlewareBuildsOPAInput(t *testing.T) {
	decision := &recordingDecision{allowed: true}
	handler := authz.Middleware(decision, staticRoleParser{"reader", "team-a"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	request := httptest.NewRequest(http.MethodPatch, "/resource?source=test", nil)
	request.Header.Set("Authorization", "Bearer mock.jwt.token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNoContent)
	}
	want := authz.Input{
		Method: http.MethodPatch,
		Path:   "/resource",
		Roles:  []string{"reader", "team-a"},
	}
	if !reflect.DeepEqual(decision.input, want) {
		t.Fatalf("OPA input = %#v, want %#v", decision.input, want)
	}
}

func TestMiddlewareRejectsMissingBearerToken(t *testing.T) {
	decision := &recordingDecision{allowed: true}
	handler := authz.Middleware(decision, staticRoleParser{"reader"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/resource", nil))

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if decision.called {
		t.Fatal("OPA decision was called without a bearer token")
	}
}

type recordingDecision struct {
	allowed bool
	called  bool
	input   authz.Input
}

func (d *recordingDecision) Allow(_ context.Context, input authz.Input) (bool, error) {
	d.called = true
	d.input = input
	return d.allowed, nil
}

type staticRoleParser []string

func (p staticRoleParser) ParseRoles(string) ([]string, error) {
	return p, nil
}

func mockJWT(roles []string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"realm_access": map[string]any{"roles": roles},
	})
	claims := base64.RawURLEncoding.EncodeToString(payload)

	return header + "." + claims + ".mock-signature"
}
