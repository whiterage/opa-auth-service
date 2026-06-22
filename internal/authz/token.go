package authz

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidToken = errors.New("invalid token")

// MockJWTParser читает Keycloak-подобные claims, но намеренно не проверяет
// подпись JWT. Для production вместо него нужен валидатор подписи и claims.
type MockJWTParser struct{}

func (MockJWTParser) ParseRoles(token string) ([]string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want three JWT parts", ErrInvalidToken)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: decode claims: %v", ErrInvalidToken, err)
	}

	var claims struct {
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: decode claims JSON: %v", ErrInvalidToken, err)
	}

	return claims.RealmAccess.Roles, nil
}
