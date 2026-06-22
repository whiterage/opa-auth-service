package authz_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"testsbertech/internal/authz"
)

func TestPolicyHotReload(t *testing.T) {
	const denyReader = `package authz
import rego.v1
default allow := false
allow if { "admin" in input.roles }
`
	const allowReader = `package authz
import rego.v1
default allow := false
allow if { "reader" in input.roles }
`

	policyPath := filepath.Join(t.TempDir(), "authz.rego")
	if err := os.WriteFile(policyPath, []byte(denyReader), 0o600); err != nil {
		t.Fatalf("write initial policy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	authorizer, err := authz.NewFromFile(ctx, policyPath, func(err error) {
		t.Logf("reload error: %v", err)
	})
	if err != nil {
		t.Fatalf("create file authorizer: %v", err)
	}

	input := authz.Input{Method: "GET", Path: "/resource", Roles: []string{"reader"}}
	allowed, err := authorizer.Allow(ctx, input)
	if err != nil {
		t.Fatalf("evaluate initial policy: %v", err)
	}
	if allowed {
		t.Fatal("initial policy unexpectedly allowed reader")
	}

	if err := os.WriteFile(policyPath, []byte(allowReader), 0o600); err != nil {
		t.Fatalf("replace policy: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		allowed, err = authorizer.Allow(ctx, input)
		if err != nil {
			t.Fatalf("evaluate reloaded policy: %v", err)
		}
		if allowed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("updated policy was not loaded within two seconds")
}

func TestInvalidReloadKeepsPreviousPolicy(t *testing.T) {
	const validPolicy = `package authz
import rego.v1
default allow := false
allow if { "reader" in input.roles }
`
	const invalidPolicy = `package authz
allow if {
`

	ctx := context.Background()
	authorizer, err := authz.New(ctx, validPolicy)
	if err != nil {
		t.Fatalf("create authorizer: %v", err)
	}

	if err := authorizer.Reload(ctx, invalidPolicy); err == nil {
		t.Fatal("invalid policy reload unexpectedly succeeded")
	}

	allowed, err := authorizer.Allow(ctx, authz.Input{
		Method: "GET",
		Path:   "/resource",
		Roles:  []string{"reader"},
	})
	if err != nil {
		t.Fatalf("evaluate previous policy: %v", err)
	}
	if !allowed {
		t.Fatal("previous valid policy was not preserved")
	}
}
