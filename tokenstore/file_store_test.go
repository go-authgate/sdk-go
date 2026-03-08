package tokenstore_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-authgate/sdk-go/tokenstore"
)

func TestFileStore_SaveAndLoad(t *testing.T) {
	tempDir := t.TempDir()
	store := tokenstore.NewFileStore(filepath.Join(tempDir, "tokens.json"))

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

func TestFileStore_LoadNotFound(t *testing.T) {
	tempDir := t.TempDir()
	store := tokenstore.NewFileStore(filepath.Join(tempDir, "tokens.json"))

	_, err := store.Load("nonexistent")
	if err != tokenstore.ErrNotFound {
		t.Errorf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestFileStore_LoadFromExistingFileNotFound(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "tokens.json")
	store := tokenstore.NewFileStore(filePath)

	// Save one client
	if err := store.Save(&tokenstore.Token{
		AccessToken: "token-1",
		ClientID:    "client-1",
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Load a different client
	_, err := store.Load("client-2")
	if err != tokenstore.ErrNotFound {
		t.Errorf("Load() error = %v, want ErrNotFound", err)
	}
}

func TestFileStore_Delete(t *testing.T) {
	tempDir := t.TempDir()
	store := tokenstore.NewFileStore(filepath.Join(tempDir, "tokens.json"))

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

func TestFileStore_DeleteNonexistent(t *testing.T) {
	tempDir := t.TempDir()
	store := tokenstore.NewFileStore(filepath.Join(tempDir, "tokens.json"))

	// Should not error when deleting from nonexistent file
	if err := store.Delete("nonexistent"); err != nil {
		t.Errorf("Delete() error = %v, want nil", err)
	}
}

func TestFileStore_DeletePreservesOtherClients(t *testing.T) {
	tempDir := t.TempDir()
	store := tokenstore.NewFileStore(filepath.Join(tempDir, "tokens.json"))

	// Save two clients
	for _, id := range []string{"client-1", "client-2"} {
		if err := store.Save(&tokenstore.Token{
			AccessToken: "token-" + id,
			ClientID:    id,
		}); err != nil {
			t.Fatalf("Save() error = %v", err)
		}
	}

	// Delete one
	if err := store.Delete("client-1"); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Other should still exist
	loaded, err := store.Load("client-2")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != "token-client-2" {
		t.Errorf("AccessToken = %v, want %v", loaded.AccessToken, "token-client-2")
	}
}

func TestFileStore_ConcurrentWrites(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "tokens.json")
	store := tokenstore.NewFileStore(filePath)

	const goroutines = 10
	var wg sync.WaitGroup

	wg.Add(goroutines)
	for i := range goroutines {
		go func(id int) {
			defer wg.Done()

			storage := &tokenstore.Token{
				AccessToken:  fmt.Sprintf("access-token-%d", id),
				RefreshToken: fmt.Sprintf("refresh-token-%d", id),
				TokenType:    "Bearer",
				ExpiresAt:    time.Now().Add(1 * time.Hour),
				ClientID:     fmt.Sprintf("client-%d", id),
			}

			if err := store.Save(storage); err != nil {
				t.Errorf("Goroutine %d: Save() error = %v", id, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all tokens were saved by loading each one
	for i := range goroutines {
		clientID := fmt.Sprintf("client-%d", i)
		loaded, err := store.Load(clientID)
		if err != nil {
			t.Errorf("Load(%s) error = %v", clientID, err)
			continue
		}
		expectedAccessToken := fmt.Sprintf("access-token-%d", i)
		if loaded.AccessToken != expectedAccessToken {
			t.Errorf(
				"Client %s: AccessToken = %v, want %v",
				clientID,
				loaded.AccessToken,
				expectedAccessToken,
			)
		}
	}

	// Verify no lock files remain
	lockPath := filePath + ".lock"
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Errorf("Lock file still exists after all saves completed")
	}
}

func TestFileStore_String(t *testing.T) {
	store := tokenstore.NewFileStore("/path/to/tokens.json")
	expected := "file: /path/to/tokens.json"
	if store.String() != expected {
		t.Errorf("String() = %v, want %v", store.String(), expected)
	}
}
