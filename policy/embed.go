package policy

import _ "embed"

//go:embed authz.rego
var Source string
