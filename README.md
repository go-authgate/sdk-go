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

| Package                   | Description                                                                    |
| ------------------------- | ------------------------------------------------------------------------------ |
| [tokenstore](tokenstore/) | Secure OAuth token storage with OS keyring integration and file-based fallback |

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
