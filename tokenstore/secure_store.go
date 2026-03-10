package tokenstore

// Prober is an optional interface that a Store can implement to test
// whether its backend is available.
type Prober interface {
	Probe() bool
}

// DefaultSecureStore creates a SecureStore with sensible defaults.
func DefaultSecureStore(serviceName, filePath string) *SecureStore {
	kr := NewKeyringStore(serviceName)
	file := NewFileStore(filePath)
	return NewSecureStore(kr, file)
}

// SecureStore is a composite Store that tries the OS keyring first
// and falls back to file-based storage if the keyring is unavailable.
type SecureStore struct {
	primary    Store
	useKeyring bool
}

// NewSecureStore creates a SecureStore. If kr implements Prober and the probe
// succeeds, kr is used as the primary store. Otherwise, file is used as the
// fallback. The caller is responsible for logging when a fallback occurs
// (check the result with String() or compare the returned store's primary).
func NewSecureStore(kr, file Store) *SecureStore {
	if p, ok := kr.(Prober); ok && p.Probe() {
		return &SecureStore{primary: kr, useKeyring: true}
	}
	return &SecureStore{primary: file, useKeyring: false}
}

// UseKeyring reports whether the secure store is using the keyring backend.
func (s *SecureStore) UseKeyring() bool {
	return s.useKeyring
}

// Load loads tokens from the active store.
func (s *SecureStore) Load(clientID string) (*Token, error) {
	return s.primary.Load(clientID)
}

// Save saves tokens to the active store.
func (s *SecureStore) Save(storage *Token) error {
	return s.primary.Save(storage)
}

// Delete removes tokens from the active store.
func (s *SecureStore) Delete(clientID string) error {
	return s.primary.Delete(clientID)
}

// String returns a description of the active store.
func (s *SecureStore) String() string {
	return s.primary.String()
}
