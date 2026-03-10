package credstore

import (
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	lockMaxRetries   = 50
	lockRetryDelay   = 100 * time.Millisecond
	staleLockTimeout = 30 * time.Second
)

// fileLock represents a file lock.
type fileLock struct {
	lockFile *os.File
	lockPath string
}

// acquireFileLock acquires an exclusive lock on the token file.
// Uses a separate lock file to coordinate access across processes.
func acquireFileLock(filePath string) (*fileLock, error) {
	lockPath := filePath + ".lock"

	for range lockMaxRetries {
		lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			return &fileLock{
				lockFile: lockFile,
				lockPath: lockPath,
			}, nil
		}

		if os.IsExist(err) {
			if info, statErr := os.Stat(lockPath); statErr == nil {
				if time.Since(info.ModTime()) > staleLockTimeout {
					if remErr := os.Remove(lockPath); remErr != nil && !os.IsNotExist(remErr) {
						return nil, fmt.Errorf(
							"failed to remove stale lock file %s: %w",
							lockPath,
							remErr,
						)
					}
					continue
				}
			}
			time.Sleep(lockRetryDelay)
			continue
		}

		return nil, fmt.Errorf("failed to acquire file lock: %w", err)
	}

	return nil, fmt.Errorf(
		"timeout waiting for file lock after %v",
		time.Duration(lockMaxRetries)*lockRetryDelay,
	)
}

// release releases the file lock.
func (fl *fileLock) release() error {
	var closeErr error
	if fl.lockFile != nil {
		closeErr = fl.lockFile.Close()
	}
	removeErr := os.Remove(fl.lockPath)
	return errors.Join(closeErr, removeErr)
}
