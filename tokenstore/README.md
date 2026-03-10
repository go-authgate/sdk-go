# tokenstore

Secure storage for OAuth tokens and arbitrary credentials, with OS keyring integration and file-based fallback.

## Features

- **Generic Storage** — store `Token`, plain `string`, or any custom type
- **OS Keyring Integration** — stores data in macOS Keychain, Linux Secret Service, or Windows Credential Manager
- **Automatic Fallback** — falls back to file-based storage when keyring is unavailable
- **Thread-Safe** — file locking with stale lock detection for concurrent access
- **Atomic Writes** — uses temp file + rename pattern to prevent corruption
- **Cross-Platform** — works on macOS, Linux, and Windows

## Quick Start

```go
package main

import (
  "fmt"
  "time"

  "github.com/go-authgate/sdk-go/tokenstore"
)

func main() {
  // Create a secure store with keyring + file fallback (one-liner)
  store := tokenstore.DefaultTokenSecureStore("my-app", "/tmp/my-app-tokens.json")

  fmt.Println("Using backend:", store.String())

  // Save a token
  token := tokenstore.Token{
    AccessToken:  "eyJhbGciOi...",
    RefreshToken: "dGhpcyBpcyBh...",
    TokenType:    "Bearer",
    ExpiresAt:    time.Now().Add(1 * time.Hour),
    ClientID:     "my-client-id",
  }

  if err := store.Save(token.ClientID, token); err != nil {
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

All stores implement the generic `Store[T]` interface:

```go
type Store[T any] interface {
  Load(clientID string) (T, error)
  Save(clientID string, data T) error
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

### Token Helpers

Tokens provide convenience methods for checking validity:

```go
loaded, err := store.Load("my-client-id")
if err != nil {
  // handle error
}

// Check if token has expired
if loaded.IsExpired() {
  // refresh the token
}

// Check if token is usable (non-empty access token and not expired)
if loaded.IsValid() {
  // use the token
}
```

### Listing Tokens

`FileStore` implements the optional `Lister` interface:

```go
type Lister interface {
  List() ([]string, error)
}
```

Use a type assertion to check listing support at runtime:

```go
if lister, ok := store.(tokenstore.Lister); ok {
  ids, err := lister.List()
  if err != nil {
    panic(err)
  }
  fmt.Println("Stored client IDs:", ids) // sorted alphabetically
}
```

> Note: `*SecureStore` does **not** implement `Lister`. If you need listing, use `*FileStore` directly.

### FileStore

Stores data in a JSON file with file locking and atomic writes. Parent directories are created automatically.

```go
// Token store (convenience constructor)
store := tokenstore.NewTokenFileStore("~/.config/my-app/tokens.json")

// Plain string store
store := tokenstore.NewStringFileStore("~/.config/my-app/tokens.json")

// Custom type with JSON encoding
store := tokenstore.NewFileStore[MyCredentials]("~/.config/my-app/creds.json", tokenstore.JSONCodec[MyCredentials]{})
```

### KeyringStore

Stores data in the OS keyring. Implements the `Prober` interface to test keyring availability.

```go
// Token store (convenience constructor)
store := tokenstore.NewTokenKeyringStore("my-app")

// Plain string store
store := tokenstore.NewStringKeyringStore("my-app")

// Check if keyring is available
if store.Probe() {
  fmt.Println("Keyring is available")
}
```

### SecureStore

A composite store that automatically selects the best available backend. If the keyring is available (tested via `Probe()`), it uses the keyring; otherwise, it falls back to file storage.

```go
// Quick setup with defaults (Token)
store := tokenstore.DefaultTokenSecureStore("my-app", "/path/to/tokens.json")

// Or configure manually
kr := tokenstore.NewTokenKeyringStore("my-app")
file := tokenstore.NewTokenFileStore("/path/to/tokens.json")
store := tokenstore.NewSecureStore(kr, file)

if store.UseKeyring() {
  fmt.Println("Using OS keyring")
} else {
  fmt.Println("Using file storage")
}

// Generic setup with custom codec
store := tokenstore.DefaultSecureStore[MyCredentials]("my-app", "/path/to/creds.json", tokenstore.JSONCodec[MyCredentials]{})
```

### Codec

`Codec[T]` handles serialization between values and the strings stored in the backend:

```go
type Codec[T any] interface {
  Encode(v T) (string, error)
  Decode(s string) (T, error)
}
```

Built-in implementations:

| Codec          | Type     | Description                        |
| -------------- | -------- | ---------------------------------- |
| `JSONCodec[T]` | any      | Marshals/unmarshals T as JSON      |
| `StringCodec`  | `string` | Identity — stores the string as-is |

Custom codecs can be used for encryption, compression, or any other encoding:

```go
type EncryptedCodec struct{ key []byte }

func (c EncryptedCodec) Encode(v string) (string, error) { /* encrypt */ }
func (c EncryptedCodec) Decode(s string) (string, error) { /* decrypt */ }

store := tokenstore.NewFileStore[string]("/path/to/store.json", EncryptedCodec{key: myKey})
```

### Error Handling

```go
import "errors"

_, err := store.Load("client-id")
if errors.Is(err, tokenstore.ErrNotFound) {
  // Token does not exist — trigger a new OAuth flow
}
```

| Error              | Description                             |
| ------------------ | --------------------------------------- |
| `ErrNotFound`      | No data found for the given client ID   |
| `ErrEmptyClientID` | An empty client ID was passed to `Save` |

## Benchmarks

Tested on Apple M4 Pro, Go 1.24. KeyringStore uses an in-memory mock; real OS keyring performance will vary (typically a few hundred microseconds to a few milliseconds due to IPC overhead).

### FileStore vs KeyringStore

| Operation | FileStore           | KeyringStore (mock)  | Ratio |
| --------- | ------------------- | -------------------- | ----- |
| Save      | ~196 µs / 42 allocs | ~0.31 µs / 3 allocs  | ~630x |
| Load      | ~12 µs / 23 allocs  | ~0.85 µs / 10 allocs | ~14x  |
| Delete    | ~391 µs / 75 allocs | ~0.49 µs / 8 allocs  | ~800x |

FileStore is slower because every Save/Delete requires file lock acquisition, full JSON read-modify-write, and an atomic rename. Load is faster since it skips the file lock.

### FileStore scaling by number of stored clients

| Clients | Save latency | Allocs |
| ------- | ------------ | ------ |
| 1       | 196 µs       | 42     |
| 10      | 213 µs       | 126    |
| 50      | 310 µs       | 490    |

Allocations grow linearly because the entire data map is deserialized and re-serialized on each write.

Run benchmarks yourself:

```bash
go test ./tokenstore/... -bench=. -benchmem -count=3 -run=^$
```
