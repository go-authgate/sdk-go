package tokenstore

import (
	"encoding/json"
	"fmt"
	"os"
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

// Load loads tokens from the file for the given client ID.
func (f *FileStore) Load(clientID string) (*Token, error) {
	data, err := os.ReadFile(f.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	var storageMap tokenStorageMap
	if err := json.Unmarshal(data, &storageMap); err != nil {
		return nil, fmt.Errorf("failed to parse token file: %w", err)
	}

	if storageMap.Tokens == nil {
		return nil, ErrNotFound
	}

	storage, ok := storageMap.Tokens[clientID]
	if !ok {
		return nil, ErrNotFound
	}

	return storage, nil
}

// Save saves tokens to the file, merging with existing tokens for other clients.
// Uses file locking to prevent race conditions.
func (f *FileStore) Save(storage *Token) error {
	if err := validateToken(storage); err != nil {
		return err
	}

	// Acquire file lock to prevent concurrent access
	lock, err := acquireFileLock(f.FilePath)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		if releaseErr := lock.release(); releaseErr != nil {
			fmt.Fprintf(os.Stderr, "failed to release lock: %v\n", releaseErr)
		}
	}()

	// Load existing token map (inside lock to ensure consistency)
	var storageMap tokenStorageMap
	existingData, err := os.ReadFile(f.FilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read token file: %w", err)
		}
		storageMap.Tokens = make(map[string]*Token)
	} else {
		if unmarshalErr := json.Unmarshal(existingData, &storageMap); unmarshalErr != nil {
			return fmt.Errorf("failed to parse token file: %w", unmarshalErr)
		}
		if storageMap.Tokens == nil {
			storageMap.Tokens = make(map[string]*Token)
		}
	}

	storageMap.Tokens[storage.ClientID] = storage

	data, err := json.MarshalIndent(storageMap, "", "  ")
	if err != nil {
		return err
	}

	// Write to temp file first (atomic write pattern)
	tempFile := f.FilePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0o600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempFile, f.FilePath); err != nil {
		if removeErr := os.Remove(tempFile); removeErr != nil {
			return fmt.Errorf(
				"failed to rename temp file: %v; additionally failed to remove temp file: %w",
				err,
				removeErr,
			)
		}
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// Delete removes tokens for the given client ID from the file.
func (f *FileStore) Delete(clientID string) error {
	lock, err := acquireFileLock(f.FilePath)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() {
		if releaseErr := lock.release(); releaseErr != nil {
			fmt.Fprintf(os.Stderr, "failed to release lock: %v\n", releaseErr)
		}
	}()

	data, err := os.ReadFile(f.FilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var storageMap tokenStorageMap
	if err := json.Unmarshal(data, &storageMap); err != nil {
		return fmt.Errorf("failed to parse token file: %w", err)
	}

	if storageMap.Tokens == nil {
		return nil
	}

	delete(storageMap.Tokens, clientID)

	newData, err := json.MarshalIndent(storageMap, "", "  ")
	if err != nil {
		return err
	}

	tempFile := f.FilePath + ".tmp"
	if err := os.WriteFile(tempFile, newData, 0o600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, f.FilePath); err != nil {
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// String returns a description of this store.
func (f *FileStore) String() string {
	return "file: " + f.FilePath
}
