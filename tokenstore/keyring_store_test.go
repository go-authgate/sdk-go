package tokenstore_test

import (
	"testing"
	"time"

	"github.com/go-authgate/sdk-go/tokenstore"
	"github.com/zalando/go-keyring"
)

func TestKeyringStore_SaveAndLoad(t *testing.T) {
	keyring.MockInit()
	store := tokenstore.NewKeyringStore("test-service")

	storage := &tokenstore.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour).Truncate(time.Second),
		ClientID:     "test-client",
	}

	if err := store.Save(storage); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("test-client")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.AccessToken != storage.AccessToken {
		t.Errorf("AccessToken = %v, want %v", loaded.AccessToken, storage.AccessToken)
	}
	if loaded.RefreshToken != storage.RefreshToken {
		t.Errorf("RefreshToken = %v, want %v", loaded.RefreshToken, storage.RefreshToken)
	}
	if loaded.ClientID != storage.ClientID {
		t.Errorf("ClientID = %v, want %v", loaded.ClientID, storage.ClientID)
	}
}

func TestKeyringStore_LoadNotFound(t *testing.T) {
	keyring.MockInit()
	store := tokenstore.NewKeyringStore("test-service")

	_, err := store.Load("nonexistent")
	if err != tokenstore.ErrNotFound {
		t.Errorf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestKeyringStore_Delete(t *testing.T) {
	keyring.MockInit()
	store := tokenstore.NewKeyringStore("test-service")

	storage := &tokenstore.Token{
		AccessToken: "test-token",
		ClientID:    "test-client",
	}
	if err := store.Save(storage); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if err := store.Delete("test-client"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err := store.Load("test-client")
	if err != tokenstore.ErrNotFound {
		t.Errorf("Load() after Delete() error = %v, want ErrNotFound", err)
	}
}

func TestKeyringStore_DeleteNonexistent(t *testing.T) {
	keyring.MockInit()
	store := tokenstore.NewKeyringStore("test-service")

	// Should not error when deleting nonexistent key
	if err := store.Delete("nonexistent"); err != nil {
		t.Errorf("Delete() error = %v, want nil", err)
	}
}

func TestKeyringStore_OverwriteExisting(t *testing.T) {
	keyring.MockInit()
	store := tokenstore.NewKeyringStore("test-service")

	storage1 := &tokenstore.Token{
		AccessToken: "token-v1",
		ClientID:    "test-client",
	}
	if err := store.Save(storage1); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	storage2 := &tokenstore.Token{
		AccessToken: "token-v2",
		ClientID:    "test-client",
	}
	if err := store.Save(storage2); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("test-client")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != "token-v2" {
		t.Errorf("AccessToken = %v, want token-v2", loaded.AccessToken)
	}
}

func TestKeyringStore_MultipleClients(t *testing.T) {
	keyring.MockInit()
	store := tokenstore.NewKeyringStore("test-service")

	for _, id := range []string{"client-1", "client-2"} {
		if err := store.Save(&tokenstore.Token{
			AccessToken: "token-" + id,
			ClientID:    id,
		}); err != nil {
			t.Fatalf("Save(%s) error = %v", id, err)
		}
	}

	for _, id := range []string{"client-1", "client-2"} {
		loaded, err := store.Load(id)
		if err != nil {
			t.Fatalf("Load(%s) error = %v", id, err)
		}
		expected := "token-" + id
		if loaded.AccessToken != expected {
			t.Errorf("Load(%s) AccessToken = %v, want %v", id, loaded.AccessToken, expected)
		}
	}
}

func TestKeyringStore_String(t *testing.T) {
	store := tokenstore.NewKeyringStore("my-service")
	expected := "keyring: my-service"
	if store.String() != expected {
		t.Errorf("String() = %v, want %v", store.String(), expected)
	}
}
