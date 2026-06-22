package authz

import (
	"context"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/rego"
)

type Input struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Roles  []string `json:"roles"`
}

type Authorizer struct {
	mu    sync.RWMutex
	query rego.PreparedEvalQuery
}

func New(ctx context.Context, policy string) (*Authorizer, error) {
	query, err := prepare(ctx, policy)
	if err != nil {
		return nil, err
	}

	return &Authorizer{query: query}, nil
}

func (a *Authorizer) Reload(ctx context.Context, policy string) error {
	query, err := prepare(ctx, policy)
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.query = query
	a.mu.Unlock()

	return nil
}

func prepare(ctx context.Context, policy string) (rego.PreparedEvalQuery, error) {
	query, err := rego.New(
		rego.Query("data.authz.allow"),
		rego.Module("authz.rego", policy),
	).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, fmt.Errorf("prepare OPA query: %w", err)
	}

	return query, nil
}

func (a *Authorizer) Allow(ctx context.Context, input Input) (bool, error) {
	a.mu.RLock()
	query := a.query
	a.mu.RUnlock()

	results, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, fmt.Errorf("evaluate OPA query: %w", err)
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, nil
	}

	allowed, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, fmt.Errorf("OPA decision has type %T, want bool", results[0].Expressions[0].Value)
	}

	return allowed, nil
}
