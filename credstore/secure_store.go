package credstore

import "sync"

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
// Both stores are retained so that Refresh() can switch between them.
// All methods are safe for concurrent use.
type SecureStore[T any] struct {
	mu         sync.RWMutex
	primary    Store[T]
	kr         Store[T]
	file       Store[T]
	prober     Prober // nil if kr does not implement Prober
	useKeyring bool
}

// NewSecureStore creates a SecureStore. If kr implements Prober and the probe
// succeeds, kr is used as the primary store. Otherwise, file is used as the
// fallback. Both stores are retained for use by Refresh(). The caller is
// responsible for logging when a fallback occurs (check UseKeyring() or String()).
func NewSecureStore[T any](kr, file Store[T]) *SecureStore[T] {
	p, _ := kr.(Prober)
	if p != nil && p.Probe() {
		return &SecureStore[T]{primary: kr, kr: kr, file: file, prober: p, useKeyring: true}
	}
	return &SecureStore[T]{primary: file, kr: kr, file: file, prober: p, useKeyring: false}
}

// active returns the current primary store under a read lock.
// The lock is released before the caller uses the returned store,
// so long-running store operations do not block Refresh().
func (s *SecureStore[T]) active() Store[T] {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.primary
}

// Refresh re-probes the keyring backend and switches the active store if the
// availability has changed. It returns true if the active backend changed,
// false if it remained the same. No data is migrated between backends.
// Probe() is called outside the lock to avoid holding it during a potentially
// slow OS call.
func (s *SecureStore[T]) Refresh() bool {
	if s.prober == nil {
		return false
	}

	keyringAvailable := s.prober.Probe()

	s.mu.Lock()
	defer s.mu.Unlock()

	if keyringAvailable == s.useKeyring {
		return false
	}

	if keyringAvailable {
		s.primary = s.kr
		s.useKeyring = true
	} else {
		s.primary = s.file
		s.useKeyring = false
	}
	return true
}

// UseKeyring reports whether the secure store is using the keyring backend.
func (s *SecureStore[T]) UseKeyring() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.useKeyring
}

// Load loads data from the active store.
func (s *SecureStore[T]) Load(clientID string) (T, error) {
	return s.active().Load(clientID)
}

// Save saves data to the active store.
func (s *SecureStore[T]) Save(clientID string, data T) error {
	return s.active().Save(clientID, data)
}

// Delete removes data from the active store.
func (s *SecureStore[T]) Delete(clientID string) error {
	return s.active().Delete(clientID)
}

// String returns a description of the active store.
func (s *SecureStore[T]) String() string {
	return s.active().String()
}
