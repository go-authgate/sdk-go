# AuthGate SDK for Go

[![Lint and Testing](https://github.com/go-authgate/sdk-go/actions/workflows/testing.yml/badge.svg)](https://github.com/go-authgate/sdk-go/actions/workflows/testing.yml)
[![CodeQL](https://github.com/go-authgate/sdk-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/go-authgate/sdk-go/actions/workflows/codeql.yml)
[![Trivy Security Scan](https://github.com/go-authgate/sdk-go/actions/workflows/security.yml/badge.svg)](https://github.com/go-authgate/sdk-go/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/go-authgate/sdk-go/branch/main/graph/badge.svg)](https://codecov.io/gh/go-authgate/sdk-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-authgate/sdk-go.svg)](https://pkg.go.dev/github.com/go-authgate/sdk-go)

Go SDK for [AuthGate](https://github.com/go-authgate) — secure OAuth token storage with OS keyring integration and file-based fallback.

## Features

- **OS Keyring Integration** — stores tokens in macOS Keychain, Linux Secret Service, or Windows Credential Manager
- **Automatic Fallback** — falls back to encrypted file-based storage when keyring is unavailable
- **Thread-Safe** — file locking with stale lock detection for concurrent access
- **Atomic Writes** — uses temp file + rename pattern to prevent corruption
- **Cross-Platform** — works on macOS, Linux, and Windows

## Installation

```bash
go get github.com/go-authgate/sdk-go
```

## Quick Start

```go
package main

import (
  "fmt"
  "time"

  "github.com/go-authgate/sdk-go/tokenstore"
)

func main() {
  // Create a secure store with keyring + file fallback
  kr := tokenstore.NewKeyringStore("my-app")
  file := tokenstore.NewFileStore("/tmp/my-app-tokens.json")
  store := tokenstore.NewSecureStore(kr, file)

  fmt.Println("Using backend:", store.String())

  // Save a token
  token := &tokenstore.Token{
    AccessToken:  "eyJhbGciOi...",
    RefreshToken: "dGhpcyBpcyBh...",
    TokenType:    "Bearer",
    ExpiresAt:    time.Now().Add(1 * time.Hour),
    ClientID:     "my-client-id",
  }

  if err := store.Save(token); err != nil {
    panic(err)
  }

  // Load a token
  loaded, err := store.Load("my-client-id")
  if err != nil {
    panic(err)
  }
  fmt.Println("Access token:", loaded.AccessToken)

  // Delete a token
  if err := store.Delete("my-client-id"); err != nil {
    panic(err)
  }
}
```

## Usage

### Store Interface

All stores implement the `Store` interface:

```go
type Store interface {
  Load(clientID string) (*Token, error)
  Save(storage *Token) error
  Delete(clientID string) error
  String() string
}
```

### Token

```go
type Token struct {
  AccessToken  string    `json:"access_token"`
  RefreshToken string    `json:"refresh_token"`
  TokenType    string    `json:"token_type"`
  ExpiresAt    time.Time `json:"expires_at"`
  ClientID     string    `json:"client_id"`
}
```

### FileStore

Stores tokens in a JSON file with file locking and atomic writes.

```go
store := tokenstore.NewFileStore("~/.config/my-app/tokens.json")
```

### KeyringStore

Stores tokens in the OS keyring. Implements the `Prober` interface to test keyring availability.

```go
store := tokenstore.NewKeyringStore("my-app")

// Check if keyring is available
if store.Probe() {
  fmt.Println("Keyring is available")
}
```

### SecureStore

A composite store that automatically selects the best available backend. If the keyring is available (tested via `Probe()`), it uses the keyring; otherwise, it falls back to file storage.

```go
kr := tokenstore.NewKeyringStore("my-app")
file := tokenstore.NewFileStore("/path/to/tokens.json")
store := tokenstore.NewSecureStore(kr, file)

if store.UseKeyring() {
  fmt.Println("Using OS keyring")
} else {
  fmt.Println("Using file storage")
}
```

### Error Handling

```go
import "errors"

token, err := store.Load("client-id")
if errors.Is(err, tokenstore.ErrNotFound) {
  // Token does not exist — trigger a new OAuth flow
}
```

| Error | Description |
|-------|-------------|
| `ErrNotFound` | No token found for the given client ID |
| `ErrNilToken` | A nil token was passed to `Save` |
| `ErrEmptyClientID` | Token has an empty `ClientID` field |

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
