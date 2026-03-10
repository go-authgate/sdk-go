package credstore

// Prober is an optional interface that a Store can implement to test
// whether its backend is available.
type Prober interface {
	Probe() bool
}

// DefaultSecureStore creates a SecureStore with the given codec and sensible defaults.
func DefaultSecureStore[T any](serviceName, filePath string, codec Codec[T]) *SecureStore[T] {
	kr := NewKeyringStore[T](serviceName, codec)
	file := NewFileStore[T](filePath, codec)
	return NewSecureStore[T](kr, file)
}

// SecureStore is a composite Store that tries the OS keyring first
// and falls back to file-based storage if the keyring is unavailable.
type SecureStore[T any] struct {
	primary    Store[T]
	useKeyring bool
}

// NewSecureStore creates a SecureStore. If kr implements Prober and the probe
// succeeds, kr is used as the primary store. Otherwise, file is used as the
// fallback. The caller is responsible for logging when a fallback occurs
// (check the result with String() or compare the returned store's primary).
func NewSecureStore[T any](kr, file Store[T]) *SecureStore[T] {
	if p, ok := kr.(Prober); ok && p.Probe() {
		return &SecureStore[T]{primary: kr, useKeyring: true}
	}
	return &SecureStore[T]{primary: file, useKeyring: false}
}

// UseKeyring reports whether the secure store is using the keyring backend.
func (s *SecureStore[T]) UseKeyring() bool {
	return s.useKeyring
}

// Load loads data from the active store.
func (s *SecureStore[T]) Load(clientID string) (T, error) {
	return s.primary.Load(clientID)
}

// Save saves data to the active store.
func (s *SecureStore[T]) Save(clientID string, data T) error {
	return s.primary.Save(clientID, data)
}

// Delete removes data from the active store.
func (s *SecureStore[T]) Delete(clientID string) error {
	return s.primary.Delete(clientID)
}

// String returns a description of the active store.
func (s *SecureStore[T]) String() string {
	return s.primary.String()
}
