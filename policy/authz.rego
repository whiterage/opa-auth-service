package authz

import rego.v1

default allow := false

# Администратору разрешён любой HTTP-метод.
allow if {
	"admin" in input.roles
}

# Читателю разрешены только GET-запросы.
allow if {
	input.method == "GET"
	"reader" in input.roles
}
