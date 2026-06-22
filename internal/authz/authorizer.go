package authz

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

// Input — данные HTTP-запроса, которые политика использует для решения.
type Input struct {
	Method string   `json:"method"`
	Path   string   `json:"path"`
	Roles  []string `json:"roles"`
}

// Authorizer хранит подготовленный OPA-запрос. Его безопасно переиспользовать
// для разных HTTP-запросов; меняется только передаваемый input.
type Authorizer struct {
	query rego.PreparedEvalQuery
}

// New компилирует политику и вызывает PrepareForEval ровно один раз.
func New(ctx context.Context, policy string) (*Authorizer, error) {
	query, err := rego.New(
		rego.Query("data.authz.allow"),
		rego.Module("authz.rego", policy),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare OPA query: %w", err)
	}

	return &Authorizer{query: query}, nil
}

// Allow вычисляет подготовленный запрос с input конкретного HTTP-запроса.
func (a *Authorizer) Allow(ctx context.Context, input Input) (bool, error) {
	results, err := a.query.Eval(ctx, rego.EvalInput(input))
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
