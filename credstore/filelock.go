package credstore

import (
	"context"
	"fmt"
	"time"

	"github.com/gofrs/flock"
)

const (
	// lockAcquireTimeout caps how long acquireFileLock will wait for a peer
	// to release. The kernel releases advisory locks automatically on process
	// death, so this is only a safety net for genuinely stuck holders.
	lockAcquireTimeout = 30 * time.Second

	// lockRetryInterval controls the poll frequency while waiting for a lock.
	lockRetryInterval = 100 * time.Millisecond
)

// fileLock is an exclusive advisory lock on a sibling `.lock` file.
// The lock is backed by gofrs/flock, which uses fcntl on POSIX and
// LockFileEx on Windows — the kernel releases the lock automatically if the
// holder crashes, so no stale-lock heuristics are needed.
type fileLock struct {
	fl *flock.Flock
}

// acquireFileLock acquires an exclusive lock on `<filePath>.lock`. The lock
// file is created if missing and is left on disk after release (the file's
// presence is not what protects access — the advisory lock is). A stranded
// lock file from a crashed process does not block new acquirers because once
// no process holds the advisory lock, including after a crash, it becomes
// immediately available to be acquired again.
func acquireFileLock(filePath string) (*fileLock, error) {
	lockPath := filePath + ".lock"

	ctx, cancel := context.WithTimeout(context.Background(), lockAcquireTimeout)
	defer cancel()

	fl := flock.New(lockPath)
	locked, err := fl.TryLockContext(ctx, lockRetryInterval)
	if err != nil {
		return nil, fmt.Errorf("acquire lock %q: %w", lockPath, err)
	}
	if !locked {
		return nil, fmt.Errorf(
			"timeout waiting for file lock %q after %v", lockPath, lockAcquireTimeout,
		)
	}

	return &fileLock{fl: fl}, nil
}

// release drops the advisory lock. The lock file itself is left on disk.
func (l *fileLock) release() error {
	return l.fl.Unlock()
}
