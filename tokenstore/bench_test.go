package tokenstore_test

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-authgate/sdk-go/tokenstore"
	"github.com/zalando/go-keyring"
)

func newTestToken(clientID string) *tokenstore.Token {
	return &tokenstore.Token{
		AccessToken:  "access-" + clientID,
		RefreshToken: "refresh-" + clientID,
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		ClientID:     clientID,
	}
}

// --- FileStore benchmarks ---

func BenchmarkFileStore_Save(b *testing.B) {
	store := tokenstore.NewFileStore(filepath.Join(b.TempDir(), "tokens.json"))
	tok := newTestToken("client-1")

	b.ResetTimer()
	for b.Loop() {
		if err := store.Save(tok); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileStore_Load(b *testing.B) {
	store := tokenstore.NewFileStore(filepath.Join(b.TempDir(), "tokens.json"))
	tok := newTestToken("client-1")
	if err := store.Save(tok); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		if _, err := store.Load("client-1"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileStore_Delete(b *testing.B) {
	dir := b.TempDir()
	store := tokenstore.NewFileStore(filepath.Join(dir, "tokens.json"))

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		id := fmt.Sprintf("client-%d", i)
		_ = store.Save(newTestToken(id))

		if err := store.Delete(id); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileStore_SaveMultipleClients(b *testing.B) {
	for _, n := range []int{1, 10, 50} {
		b.Run(fmt.Sprintf("clients=%d", n), func(b *testing.B) {
			store := tokenstore.NewFileStore(filepath.Join(b.TempDir(), "tokens.json"))
			// Pre-populate with n-1 clients
			for i := range n - 1 {
				if err := store.Save(newTestToken(fmt.Sprintf("pre-%d", i))); err != nil {
					b.Fatal(err)
				}
			}
			tok := newTestToken("bench-client")

			b.ResetTimer()
			for b.Loop() {
				if err := store.Save(tok); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// --- KeyringStore benchmarks (mock) ---

func BenchmarkKeyringStore_Save(b *testing.B) {
	keyring.MockInit()
	store := tokenstore.NewKeyringStore("bench-service")
	tok := newTestToken("client-1")

	b.ResetTimer()
	for b.Loop() {
		if err := store.Save(tok); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyringStore_Load(b *testing.B) {
	keyring.MockInit()
	store := tokenstore.NewKeyringStore("bench-service")
	tok := newTestToken("client-1")
	if err := store.Save(tok); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for b.Loop() {
		if _, err := store.Load("client-1"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyringStore_Delete(b *testing.B) {
	keyring.MockInit()
	store := tokenstore.NewKeyringStore("bench-service")

	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		id := fmt.Sprintf("client-%d", i)
		_ = store.Save(newTestToken(id))

		if err := store.Delete(id); err != nil {
			b.Fatal(err)
		}
	}
}
