package tokenstore

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const probeUser = "__authgate_probe__"

// KeyringStore stores tokens in the OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager).
type KeyringStore struct {
	ServiceName string
}

// NewKeyringStore creates a new KeyringStore.
func NewKeyringStore(serviceName string) *KeyringStore {
	return &KeyringStore{ServiceName: serviceName}
}

// Probe tests whether the OS keyring is available by setting and deleting a test entry.
func (k *KeyringStore) Probe() bool {
	if err := keyring.Set(k.ServiceName, probeUser, "probe"); err != nil {
		return false
	}
	if err := keyring.Delete(k.ServiceName, probeUser); err != nil {
		return false
	}
	return true
}

// Load loads tokens from the keyring for the given client ID.
func (k *KeyringStore) Load(clientID string) (*Token, error) {
	data, err := keyring.Get(k.ServiceName, clientID)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to read from keyring: %w", err)
	}

	var storage Token
	if err := json.Unmarshal([]byte(data), &storage); err != nil {
		return nil, fmt.Errorf("failed to parse keyring data: %w", err)
	}

	return &storage, nil
}

// Save saves tokens to the keyring.
func (k *KeyringStore) Save(storage *Token) error {
	if err := validateToken(storage); err != nil {
		return err
	}

	data, err := json.Marshal(storage)
	if err != nil {
		return fmt.Errorf("failed to marshal token data: %w", err)
	}

	if err := keyring.Set(k.ServiceName, storage.ClientID, string(data)); err != nil {
		return fmt.Errorf("failed to save to keyring: %w", err)
	}

	return nil
}

// Delete removes tokens for the given client ID from the keyring.
func (k *KeyringStore) Delete(clientID string) error {
	err := keyring.Delete(k.ServiceName, clientID)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("failed to delete from keyring: %w", err)
	}
	return nil
}

// String returns a description of this store.
func (k *KeyringStore) String() string {
	return "keyring: " + k.ServiceName
}
