# oauth

OAuth 2.0 token client for AuthGate. Pure HTTP layer — no storage, polling, or UI.

## Usage

```go
import "github.com/go-authgate/sdk-go/oauth"

client, _ := oauth.NewClient("client-id", oauth.Endpoints{
    TokenURL:               "https://auth.example.com/oauth/token",
    DeviceAuthorizationURL: "https://auth.example.com/oauth/device/code",
})

// Or use discovery to populate endpoints automatically:
// client, _ := oauth.NewClient("client-id", meta.Endpoints())
```

### Device Code Flow

```go
auth, _ := client.RequestDeviceCode(ctx, []string{"read", "write"})
fmt.Printf("Open %s and enter code: %s\n", auth.VerificationURI, auth.UserCode)

token, _ := client.ExchangeDeviceCode(ctx, auth.DeviceCode)
```

### Authorization Code + PKCE

```go
token, _ := client.ExchangeAuthCode(ctx, code, redirectURI, codeVerifier)
```

### Client Credentials

```go
client, _ := oauth.NewClient("client-id", endpoints, oauth.WithClientSecret("secret"))
token, _ := client.ClientCredentials(ctx, []string{"read"})
```

### Refresh / Revoke / Introspect / UserInfo

```go
token, _ := client.RefreshToken(ctx, refreshToken)
client.Revoke(ctx, token.AccessToken)
result, _ := client.Introspect(ctx, token.AccessToken)
info, _ := client.UserInfo(ctx, token.AccessToken)
```

## Options

| Option               | Description                                  |
| -------------------- | -------------------------------------------- |
| `WithClientSecret()` | Set client secret (confidential clients)     |
| `WithHTTPClient()`   | Set custom `*retry.Client` for HTTP requests |

## Types

- `Token` — access_token, refresh_token, token_type, expires_in, scope, id_token
- `DeviceAuth` — device_code, user_code, verification_uri, interval
- `IntrospectionResult` — active, scope, client_id, username, exp, etc.
- `UserInfo` — sub, name, email, preferred_username, etc.
- `TokenInfo` — active, user_id, client_id, scope, subject_type
- `Error` — OAuth error code + description
- `Endpoints` — all endpoint URLs
