package tokenstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// validateToken checks that storage is non-nil and has a non-empty ClientID.
func validateToken(storage *Token) error {
	if storage == nil {
		return ErrNilToken
	}
	if storage.ClientID == "" {
		return ErrEmptyClientID
	}
	return nil
}

// tokenStorageMap manages tokens for multiple clients.
type tokenStorageMap struct {
	Tokens map[string]*Token `json:"tokens"` // key = client_id
}

// FileStore stores tokens in a JSON file with file locking and atomic writes.
type FileStore struct {
	FilePath string
}

// NewFileStore creates a new FileStore.
func NewFileStore(filePath string) *FileStore {
	return &FileStore{FilePath: filePath}
}

// readStorageMap reads and unmarshals the token storage map from the file.
// Returns an empty initialized map if the file does not exist.
func (f *FileStore) readStorageMap() (tokenStorageMap, error) {
	var m tokenStorageMap
	data, err := os.ReadFile(f.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			m.Tokens = make(map[string]*Token)
			return m, nil
		}
		return m, fmt.Errorf("failed to read token file: %w", err)
	}

	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("failed to parse token file: %w", err)
	}
	if m.Tokens == nil {
		m.Tokens = make(map[string]*Token)
	}
	return m, nil
}

// ensureDir creates the parent directory of the token file if it does not exist.
func (f *FileStore) ensureDir() error {
	if err := os.MkdirAll(filepath.Dir(f.FilePath), 0o700); err != nil {
		return fmt.Errorf("failed to create token directory: %w", err)
	}
	return nil
}

// writeStorageMap marshals and atomically writes the token storage map to the file.
func (f *FileStore) writeStorageMap(m tokenStorageMap) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	tempFile := f.FilePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0o600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, f.FilePath); err != nil {
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// withFileLock acquires a file lock, runs fn, and releases the lock.
func (f *FileStore) withFileLock(fn func() error) error {
	lock, err := acquireFileLock(f.FilePath)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer lock.release() //nolint:errcheck // best-effort cleanup; lock file has stale detection

	return fn()
}

// Load loads tokens from the file for the given client ID.
func (f *FileStore) Load(clientID string) (*Token, error) {
	m, err := f.readStorageMap()
	if err != nil {
		return nil, err
	}

	storage, ok := m.Tokens[clientID]
	if !ok {
		return nil, ErrNotFound
	}

	return storage, nil
}

// Save saves tokens to the file, merging with existing tokens for other clients.
// Uses file locking to prevent race conditions.
// Automatically creates parent directories if they do not exist.
func (f *FileStore) Save(storage *Token) error {
	if err := validateToken(storage); err != nil {
		return err
	}

	if err := f.ensureDir(); err != nil {
		return err
	}

	return f.withFileLock(func() error {
		m, err := f.readStorageMap()
		if err != nil {
			return err
		}

		m.Tokens[storage.ClientID] = storage

		return f.writeStorageMap(m)
	})
}

// Delete removes tokens for the given client ID from the file.
func (f *FileStore) Delete(clientID string) error {
	return f.withFileLock(func() error {
		m, err := f.readStorageMap()
		if err != nil {
			return err
		}

		if _, ok := m.Tokens[clientID]; !ok {
			return nil
		}

		delete(m.Tokens, clientID)

		return f.writeStorageMap(m)
	})
}

// List returns all stored client IDs, sorted alphabetically.
func (f *FileStore) List() ([]string, error) {
	m, err := f.readStorageMap()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(m.Tokens))
	for id := range m.Tokens {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}

// String returns a description of this store.
func (f *FileStore) String() string {
	return "file: " + f.FilePath
}
