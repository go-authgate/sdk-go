package tokenstore

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// mockStore is a simple mock implementing Store for testing.
type mockStore struct {
	tokens map[string]*Token
	name   string
	err    error
}

func newMockStore(name string) *mockStore {
	return &mockStore{
		tokens: make(map[string]*Token),
		name:   name,
	}
}

func (m *mockStore) Load(clientID string) (*Token, error) {
	if m.err != nil {
		return nil, m.err
	}
	storage, ok := m.tokens[clientID]
	if !ok {
		return nil, ErrNotFound
	}
	return storage, nil
}

func (m *mockStore) Save(storage *Token) error {
	if m.err != nil {
		return m.err
	}
	m.tokens[storage.ClientID] = storage
	return nil
}

func (m *mockStore) Delete(clientID string) error {
	if m.err != nil {
		return m.err
	}
	delete(m.tokens, clientID)
	return nil
}

func (m *mockStore) String() string {
	return m.name
}

// mockProberStore implements both Store and Prober.
type mockProberStore struct {
	mockStore
	probeResult bool
}

func newMockProberStore(name string, probeResult bool) *mockProberStore {
	return &mockProberStore{
		mockStore:   mockStore{tokens: make(map[string]*Token), name: name},
		probeResult: probeResult,
	}
}

func (m *mockProberStore) Probe() bool {
	return m.probeResult
}

// mockListerStore implements Store and Lister.
type mockListerStore struct {
	mockStore
}

func newMockListerStore(name string) *mockListerStore {
	return &mockListerStore{
		mockStore: mockStore{tokens: make(map[string]*Token), name: name},
	}
}

func (m *mockListerStore) List() ([]string, error) {
	ids := make([]string, 0, len(m.tokens))
	for id := range m.tokens {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

func TestSecureStore_UsesKeyringWhenProbeSucceeds(t *testing.T) {
	kr := newMockProberStore("keyring: test", true)
	file := newMockStore("file: test")

	store := NewSecureStore(kr, file)

	storage := &Token{
		AccessToken: "test-token",
		ClientID:    "test-client",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	if err := store.Save(storage); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Should be in keyring, not file
	if _, ok := kr.tokens["test-client"]; !ok {
		t.Error("Token not found in keyring store")
	}
	if _, ok := file.tokens["test-client"]; ok {
		t.Error("Token should not be in file store")
	}

	loaded, err := store.Load("test-client")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.AccessToken != "test-token" {
		t.Errorf("AccessToken = %v, want test-token", loaded.AccessToken)
	}

	if store.String() != "keyring: test" {
		t.Errorf("String() = %v, want keyring: test", store.String())
	}

	if !store.UseKeyring() {
		t.Error("UseKeyring() = false, want true")
	}
}

func TestSecureStore_FallsBackToFileWhenProbeFails(t *testing.T) {
	kr := newMockProberStore("keyring: test", false)
	file := newMockStore("file: test")

	store := NewSecureStore(kr, file)

	storage := &Token{
		AccessToken: "test-token",
		ClientID:    "test-client",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	if err := store.Save(storage); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Should be in file, not keyring
	if _, ok := file.tokens["test-client"]; !ok {
		t.Error("Token not found in file store")
	}
	if _, ok := kr.tokens["test-client"]; ok {
		t.Error("Token should not be in keyring store")
	}

	if store.String() != "file: test" {
		t.Errorf("String() = %v, want file: test", store.String())
	}

	if store.UseKeyring() {
		t.Error("UseKeyring() = true, want false")
	}
}

func TestSecureStore_FallsBackWhenKrNotProber(t *testing.T) {
	// kr does not implement Prober, should fall back to file
	kr := newMockStore("keyring: test")
	file := newMockStore("file: test")

	store := NewSecureStore(kr, file)

	if store.String() != "file: test" {
		t.Errorf("String() = %v, want file: test", store.String())
	}
}

func TestDefaultSecureStore(t *testing.T) {
	store := DefaultSecureStore("test-service", t.TempDir()+"/tokens.json")
	if store == nil {
		t.Fatal("DefaultSecureStore() returned nil")
	}
}

func TestSecureStore_ListWithLister(t *testing.T) {
	file := newMockListerStore("file: test")
	file.tokens["bravo"] = &Token{ClientID: "bravo"}
	file.tokens["alpha"] = &Token{ClientID: "alpha"}

	kr := newMockProberStore("keyring: test", false)
	store := NewSecureStore(kr, file)

	ids, err := store.List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("List() returned %d items, want 2", len(ids))
	}
	if ids[0] != "alpha" || ids[1] != "bravo" {
		t.Errorf("List() = %v, want [alpha bravo]", ids)
	}
}

func TestSecureStore_ListNotSupported(t *testing.T) {
	kr := newMockProberStore("keyring: test", true)
	file := newMockStore("file: test")
	store := NewSecureStore(kr, file)

	_, err := store.List()
	if err == nil {
		t.Fatal("List() should return error when primary does not support listing")
	}
}

func TestSecureStore_Delete(t *testing.T) {
	kr := newMockProberStore("keyring: test", true)
	file := newMockStore("file: test")
	store := NewSecureStore(kr, file)

	storage := &Token{
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
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Load() after Delete() error = %v, want ErrNotFound", err)
	}
}
