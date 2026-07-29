# HTTP service authorized by OPA

A small Go service with one protected endpoint, `GET /resource`. The bearer JWT carries
Keycloak-shaped claims, and access is decided by an embedded Open Policy Agent instance
evaluating a Rego policy — not by application code.

## How a request is handled

1. The client sends `Authorization: Bearer <JWT>`.
2. `MockJWTParser` extracts roles from `realm_access.roles`.
3. The middleware builds the OPA input:

   ```json
   {
     "method": "GET",
     "path": "/resource",
     "roles": ["reader"]
   }
   ```

4. The prepared OPA query evaluates `data.authz.allow`.
5. If `allow == true`, the request reaches the handler; otherwise it gets a `403`.

`PrepareForEval` runs once at startup, and again only when the policy file changes. Between
changes, a single `PreparedEvalQuery` is reused across every HTTP request — the policy is not
recompiled inside the request path.

## Access policy

- `admin` can call any HTTP method.
- `reader` can call `GET` only.
- Everything else is denied by `default allow := false`.

The live policy loads from `policy/authz.rego`. The service watches the file and applies changes
without a restart. If an edited policy fails to compile, the error is logged and the last valid
version keeps serving requests.

## Running it

Requires Go 1.25 or newer.

```bash
go mod download
go run ./cmd/server
```

The service starts on `http://localhost:8080`.

It uses `policy/authz.rego` by default. Point it at a different file with an environment
variable:

```bash
POLICY_PATH=/absolute/path/to/authz.rego go run ./cmd/server
```

A request allowed by the `reader` role:

```bash
TOKEN='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsicmVhZGVyIl19fQ.mock-signature'

curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/resource
```

Expected status: `200 OK`.

A request denied for the `guest` role:

```bash
TOKEN='eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZ3Vlc3QiXX19.mock-signature'

curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/resource
```

Expected status: `403 Forbidden`, with a JSON body:

```json
{
  "error": "forbidden",
  "message": "access denied by authorization policy"
}
```

No bearer token gets a `401 Unauthorized`.

## Policy hot reload

Start the service, then edit and save `policy/authz.rego`. The watcher prepares a new OPA query
and swaps it in atomically — new requests are checked against the updated policy immediately,
with no restart.

`PrepareForEval` does run again on a hot reload, but only in response to the file change, never
on a per-request basis.

## Tests

Go tests for the middleware:

```bash
go test ./...
```

Testing the Rego policy itself needs the OPA CLI (on macOS: `brew install opa`), then:

```bash
opa test ./policy -v
```

## About the mock JWT

`MockJWTParser` decodes the JWT payload but does not verify the signature, issuer, audience, or
expiry. That's intentional scope, not an oversight — a mocked-claims parser is enough to
demonstrate OPA-driven authorization. A real deployment would verify the JWT against Keycloak's
public keys (JWKS) before ever handing roles to OPA.
