# AuthGate SDK for Go

[![Lint and Testing](https://github.com/go-authgate/sdk-go/actions/workflows/testing.yml/badge.svg)](https://github.com/go-authgate/sdk-go/actions/workflows/testing.yml)
[![CodeQL](https://github.com/go-authgate/sdk-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/go-authgate/sdk-go/actions/workflows/codeql.yml)
[![Trivy Security Scan](https://github.com/go-authgate/sdk-go/actions/workflows/security.yml/badge.svg)](https://github.com/go-authgate/sdk-go/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/go-authgate/sdk-go/branch/main/graph/badge.svg)](https://codecov.io/gh/go-authgate/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-authgate/sdk-go.svg)](https://pkg.go.dev/github.com/go-authgate/sdk-go)

Go SDK for [AuthGate](https://github.com/go-authgate).

## Installation

```bash
go get github.com/go-authgate/sdk-go
```

## Packages

| Package                     | Description                                                                                                |
| --------------------------- | ---------------------------------------------------------------------------------------------------------- |
| [credstore](credstore/)     | Secure credential storage with OS keyring integration and file-based fallback                              |
| [oauth](oauth/)             | OAuth 2.0 token client (Device Code, Auth Code, Client Credentials, Refresh, Revoke, Introspect, UserInfo) |
| [discovery](discovery/)     | OIDC auto-discovery from `/.well-known/openid-configuration` with caching                                  |
| [authflow](authflow/)       | CLI flow orchestration (Device Code polling, Auth Code + PKCE, auto-refresh TokenSource)                   |
| [middleware](middleware/)   | `net/http` Bearer token validation middleware (compatible with any Go HTTP framework)                      |
| [clientcreds](clientcreds/) | Thread-safe Client Credentials token source with auto-cache for M2M authentication                         |

### Package dependency graph

```txt
credstore (storage)     discovery (OIDC endpoint URLs)
    |                       |
    v                       v
    +------> oauth <--------+
             / | \
            /  |  \
           v   v   v
   authflow  middleware  clientcreds
```

## Development

```bash
# Run tests
make test

# Run linter
make lint

# Format code
make fmt
```

## License

See the [LICENSE](LICENSE) file for details.
