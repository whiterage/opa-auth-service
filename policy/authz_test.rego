package authz_test

import data.authz.allow

test_reader_can_get if {
	allow with input as {
		"method": "GET",
		"path": "/resource",
		"roles": ["reader"],
	}
}

test_reader_cannot_post if {
	not allow with input as {
		"method": "POST",
		"path": "/resource",
		"roles": ["reader"],
	}
}

test_admin_can_post if {
	allow with input as {
		"method": "POST",
		"path": "/resource",
		"roles": ["admin"],
	}
}

test_unknown_role_is_denied if {
	not allow with input as {
		"method": "GET",
		"path": "/resource",
		"roles": ["guest"],
	}
}
