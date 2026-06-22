package policy

import _ "embed"

// Source содержит Rego-политику внутри скомпилированного Go-бинарника.
//
//go:embed authz.rego
var Source string
