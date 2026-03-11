package credstore

import "sync"

// Prober is an optional interface that a Store can implement to test
// whether its backend is available.
type Prober interface {
	Probe() bool
}

// FallbackHandlerFunc is called when the active backend changes.
// backend is the newly-active store's String() description.
// Always called outside the mutex lock.
type FallbackHandlerFunc func(backend string)

// Diagnostics is a point-in-time snapshot of SecureStore state.
type Diagnostics struct {
	Backend    string // active store's String() description
	UseKeyring bool   // true if keyring is the active backend
	CanProbe   bool   // true if Refresh() can switch backends
}

// SecureStoreOption[T] is a functional option for NewSecureStore.
type SecureStoreOption[T any] func(*SecureStore[T])

// WithFallbackHandler registers fn as the backend-change callback.
// Passing nil is a no-op.
func WithFallbackHandler[T any](fn FallbackHandlerFunc) SecureStoreOption[T] {
	return func(s *SecureStore[T]) {
		s.onFallback = fn
	}
}

// DefaultSecureStore creates a SecureStore with the given codec and sensible defaults.
func DefaultSecureStore[T any](
	serviceName, filePath string,
	codec Codec[T],
	opts ...SecureStoreOption[T],
) *SecureStore[T] {
	return NewSecureStore[T](
		NewKeyringStore[T](serviceName, codec),
		NewFileStore[T](filePath, codec),
		opts...)
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
	onFallback FallbackHandlerFunc // optional; called outside the lock
}

// NewSecureStore creates a SecureStore. If kr implements Prober and the probe
// succeeds, kr is used as the primary store. Otherwise, file is used as the
// fallback. Both stores are retained for use by Refresh(). The onFallback
// callback (if set via WithFallbackHandler) is called when the file backend
// is selected at construction time.
func NewSecureStore[T any](kr, file Store[T], opts ...SecureStoreOption[T]) *SecureStore[T] {
	s := &SecureStore[T]{kr: kr, file: file}
	s.prober, _ = kr.(Prober)
	for _, opt := range opts {
		opt(s) // apply before probe so callback is registered first
	}
	if s.prober != nil && s.prober.Probe() {
		s.primary = kr
		s.useKeyring = true
		// no callback: keyring is the intended path, not a fallback
	} else {
		s.primary = file
		s.useKeyring = false
		if s.onFallback != nil {
			s.onFallback(file.String()) // safe: struct not yet shared
		}
	}
	return s
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
// slow OS call. The onFallback callback is called outside the lock to prevent
// deadlocks.
func (s *SecureStore[T]) Refresh() bool {
	if s.prober == nil {
		return false
	}

	keyringAvailable := s.prober.Probe() // outside the lock (slow OS call)

	s.mu.Lock()
	if keyringAvailable == s.useKeyring {
		s.mu.Unlock()
		return false
	}
	var newBackend string
	if keyringAvailable {
		s.primary, s.useKeyring = s.kr, true
		newBackend = s.kr.String()
	} else {
		s.primary, s.useKeyring = s.file, false
		newBackend = s.file.String()
	}
	cb := s.onFallback // capture under the lock
	s.mu.Unlock()      // release BEFORE calling callback (prevent deadlock)

	if cb != nil {
		cb(newBackend)
	}
	return true
}

// UseKeyring reports whether the secure store is using the keyring backend.
func (s *SecureStore[T]) UseKeyring() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.useKeyring
}

// Diagnostic returns a point-in-time snapshot of the SecureStore's backend state.
func (s *SecureStore[T]) Diagnostic() Diagnostics {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Diagnostics{
		Backend:    s.primary.String(),
		UseKeyring: s.useKeyring,
		CanProbe:   s.prober != nil,
	}
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
