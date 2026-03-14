# discovery

OIDC auto-discovery client. Fetches and caches provider metadata from `/.well-known/openid-configuration`, so other packages don't need to manually configure endpoint URLs.

## Usage

```go
import "github.com/go-authgate/sdk-go/discovery"

disco, _ := discovery.NewClient("https://auth.example.com")
meta, _ := disco.Fetch(ctx)

fmt.Println(meta.Issuer)
fmt.Println(meta.TokenEndpoint)
fmt.Println(meta.ScopesSupported)

// Convert to oauth.Endpoints for use with the oauth package:
endpoints := meta.Endpoints()
client, _ := oauth.NewClient("client-id", endpoints)
```

## Options

| Option             | Description                                  |
| ------------------ | -------------------------------------------- |
| `WithHTTPClient()` | Set custom `*retry.Client` for HTTP requests |
| `WithCacheTTL()`   | Set cache duration (default: 1 hour)         |

## Types

- `Metadata` — full OIDC Provider Metadata (issuer, token_endpoint, authorization_endpoint, device_authorization_endpoint, scopes_supported, etc.)
- `Client` — discovery client with built-in caching

## Behavior

- Caches metadata for the configured TTL (default 1 hour)
- Thread-safe — multiple goroutines can call `Fetch()` concurrently
- Automatically derives `device_authorization_endpoint` and `introspection_endpoint` from the issuer URL if not explicitly advertised
