//go:build linux

package reviewtransaction

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyExactReplayBoundsExpectedEventBeforeChainLoad(t *testing.T) {
	store := Store{Dir: filepath.Join(t.TempDir(), "store")}
	tx := newTestTransaction(t, ModeOrdinary4R)
	mustNoError(t, tx.StartReview())
	record := Record{Operation: "review/start", Transaction: *tx}
	revision, err := store.Append("", record)
	mustNoError(t, err)
	mustNoError(t, os.Truncate(filepath.Join(store.Dir, "events", strings.TrimPrefix(revision, "sha256:")+".json"), 16<<20))
	_, err = store.Append("", record)
	if !errors.As(err, new(*ImmutablePublicationConflictError)) {
		t.Fatalf("oversized replay = %T %v", err, err)
	}
}

func TestCompactPublicationBindsLockDomainAndAcceptsRelativeStore(t *testing.T) {
	t.Run("swapped domain refuses", func(t *testing.T) {
		base := t.TempDir()
		version := filepath.Join(base, "v2")
		mustNoError(t, os.Mkdir(version, 0o755))
		lock, err := acquireLocalStoreLock(filepath.Join(version, "LOCK"))
		mustNoError(t, err)
		defer lock.release()
		mustNoError(t, os.Rename(version, filepath.Join(base, "moved")))
		mustNoError(t, os.Mkdir(version, 0o755))
		err = publishCompactAuthority(lock, CompactStore{Dir: filepath.Join(version, "lineage")}, compactStateFileName, []byte("state"), authorityPublicationReplace)
		if !errors.As(err, new(*UnsafeAuthorityPathError)) {
			t.Fatalf("swapped domain = %T %v", err, err)
		}
		if _, err := os.Stat(filepath.Join(version, "lineage", compactStateFileName)); !os.IsNotExist(err) {
			t.Fatalf("fresh domain mutated: %v", err)
		}
	})
	t.Run("relative", func(t *testing.T) {
		t.Chdir(t.TempDir())
		lock, err := acquireLocalStoreLock("LOCK")
		mustNoError(t, err)
		defer lock.release()
		mustNoError(t, publishCompactAuthority(lock, CompactStore{Dir: "lineage"}, compactStateFileName, []byte("state"), authorityPublicationReplace))
		if got, err := os.ReadFile(filepath.Join("lineage", compactStateFileName)); err != nil || string(got) != "state" {
			t.Fatalf("relative state = %q, %v", got, err)
		}
	})
}
