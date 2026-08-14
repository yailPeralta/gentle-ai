//go:build windows

package reviewtransaction

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func publishLegacyAuthority(lock *storeLock, storeDir string, events []ChainBundleEvent, head string, mode authorityPublicationMode) error {
	if err := verifyWindowsPublicationLock(lock); err != nil {
		return err
	}
	eventsDir := filepath.Join(storeDir, "events")
	if err := os.MkdirAll(eventsDir, 0o755); err != nil {
		return &AuthorityPublicationNotStartedError{Cause: err}
	}
	for _, event := range events {
		path := filepath.Join(eventsDir, strings.TrimPrefix(event.Revision, "sha256:")+".json")
		if mode == authorityPublicationExisting {
			if err := verifyWindowsAuthority(path, event.Payload); err != nil {
				return err
			}
		} else if err := installContentAddressedFile(path, event.Payload); err != nil {
			return err
		}
	}
	if err := SyncReviewDirectory(eventsDir); err != nil {
		return &directorySyncError{path: eventsDir, cause: err}
	}
	headPath, payload := filepath.Join(storeDir, "HEAD"), []byte(head+"\n")
	if mode == authorityPublicationExisting {
		return verifyWindowsAuthority(headPath, payload)
	}
	return writeAtomic(headPath, payload, 0o644)
}

func publishCompactAuthority(lock *storeLock, store CompactStore, name string, payload []byte, mode authorityPublicationMode) error {
	if err := verifyWindowsPublicationLock(lock); err != nil {
		return err
	}
	path := filepath.Join(store.Dir, name)
	if mode == authorityPublicationExisting {
		return verifyWindowsAuthority(path, payload)
	}
	if mode == authorityPublicationImmutable {
		return publishImmutable(path, payload, 0o644)
	}
	return writeAtomic(path, payload, 0o644)
}

func verifyWindowsPublicationLock(lock *storeLock) error {
	file, err := secureOpenLocalStoreLock(lock.file.Name())
	if err != nil {
		return &UnsafeAuthorityPathError{Cause: err}
	}
	defer file.Close()
	held, heldErr := lock.file.Stat()
	found, foundErr := file.Stat()
	if heldErr != nil || foundErr != nil || !os.SameFile(held, found) {
		return &UnsafeAuthorityPathError{Cause: errors.New("authority lock identity changed")} // refusal:by-design world-action: a different lock object is a different mutation domain
	}
	return nil
}

func verifyWindowsAuthority(path string, payload []byte) error {
	file, err := os.Open(path)
	if err != nil {
		return &ImmutablePublicationConflictError{Cause: err}
	}
	defer file.Close()
	existing, err := io.ReadAll(io.LimitReader(file, int64(len(payload)+1)))
	if err != nil || !bytes.Equal(existing, payload) {
		return &ImmutablePublicationConflictError{Cause: errors.Join(err, errors.New("existing content differs"))} // refusal:by-design world-action: conflicting authority bytes require manual storage inspection
	}
	return SyncReviewDirectory(filepath.Dir(path))
}
