package credstore

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAcquireAndRelease(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokens.json")

	lock, err := acquireFileLock(target)
	if err != nil {
		t.Fatalf("acquireFileLock() error: %v", err)
	}

	lockPath := target + ".lock"
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Error("lock file was not created")
	}

	if err := lock.release(); err != nil {
		t.Errorf("release() error: %v", err)
	}

	// The lock file is intentionally left on disk after release; advisory
	// locking is what protects access, not the file's existence.
	next, err := acquireFileLock(target)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	_ = next.release()
}

func TestConcurrentLocks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokens.json")

	const goroutines = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	concurrent := 0

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			lock, err := acquireFileLock(target)
			if err != nil {
				t.Errorf("goroutine %d: acquireFileLock() error: %v", idx, err)
				return
			}

			mu.Lock()
			concurrent++
			if concurrent > 1 {
				t.Errorf("goroutine %d: more than one lock holder at a time: %d", idx, concurrent)
			}
			mu.Unlock()

			mu.Lock()
			concurrent--
			mu.Unlock()

			_ = lock.release()
		}(i)
	}

	wg.Wait()
}

// TestAcquireOrphanedLockFile verifies that a leftover lock file from a
// crashed process does not block new acquirers. With kernel-level advisory
// locking (fcntl/LockFileEx), no process holds the lock once the crashed
// process is gone, so a new acquirer succeeds immediately.
func TestAcquireOrphanedLockFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tokens.json")
	lockPath := target + ".lock"

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	lock, err := acquireFileLock(target)
	if err != nil {
		t.Fatalf("acquireFileLock with orphaned file: %v", err)
	}
	_ = lock.release()
}
