//go:build linux

package reviewtransaction

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestFDAuthorityRejectsSymlinkComponent(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "redirect")); err != nil {
		t.Fatal(err)
	}
	anchor, err := openAuthorityDirectory(root)
	mustNoError(t, err)
	defer anchor.close()
	_, err = anchor.ensure("redirect", "lineage")
	if !errors.Is(err, errUnsafeAuthorityComponent) {
		t.Fatalf("ensure through symlink error = %v, want unsafe component", err)
	}
	want := errors.New("transient open failure")
	err = authorityComponentError("component", want)
	if !errors.Is(err, want) || errors.Is(err, errUnsafeAuthorityComponent) {
		t.Fatalf("transient error identity = %v", err)
	}
}

func TestFDAuthoritySurvivesAnchorPathSwap(t *testing.T) {
	base := t.TempDir()
	root, moved, outside := filepath.Join(base, "root"), filepath.Join(base, "moved"), filepath.Join(base, "outside")
	for _, path := range []string{root, outside} {
		mustNoError(t, os.Mkdir(path, 0o755))
	}
	anchor, err := openAuthorityDirectory(root)
	mustNoError(t, err)
	defer anchor.close()
	mustNoError(t, os.Rename(root, moved))
	mustNoError(t, os.Symlink(outside, root))
	dir, err := anchor.ensure("authority", "lineage")
	mustNoError(t, err)
	defer dir.close()
	mustNoError(t, dir.replace("state", []byte("old"), 0o640))
	mustNoError(t, dir.replace("state", []byte("mutable"), 0o640))
	mustNoError(t, dir.publishImmutable("receipt", []byte("immutable"), 0o640))
	for name, want := range map[string]string{"state": "mutable", "receipt": "immutable"} {
		got, err := os.ReadFile(filepath.Join(moved, "authority", "lineage", name))
		if err != nil || string(got) != want {
			t.Fatalf("anchored %s = %q, %v; want %q", name, got, err, want)
		}
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("redirect target entries = %v, %v; want empty", entries, err)
	}
}

func TestFDAuthorityDirectoryCreationOrdering(t *testing.T) {
	for i, tt := range []struct {
		mkdirErr error
		openErr  error
	}{
		{},
		{openErr: unix.ENOENT},
		{openErr: unix.ENOENT, mkdirErr: unix.EEXIST},
	} {
		t.Run(string(rune('0'+i)), func(t *testing.T) {
			syncs := 0
			openCalls := 0
			ops := authorityDirectoryOps{
				open: func(string, int, uint32) (int, error) { return 10, nil },
				openat: func(_ int, name string, _ int, _ uint32) (int, error) {
					openCalls++
					if openCalls == 1 && tt.openErr != nil {
						return -1, tt.openErr
					}
					return 11, nil
				},
				mkdirat: func(int, string, uint32) error { return tt.mkdirErr },
				fsync:   func(int) error { syncs++; return nil },
				close:   func(int) error { return nil },
			}
			anchor, err := openAuthorityDirectoryWithOps("/", ops)
			mustNoError(t, err)
			dir, err := anchor.ensure("child")
			mustNoError(t, err)
			defer dir.close()
			defer anchor.close()
			if syncs != 1 {
				t.Fatal(syncs)
			}
		})
	}
}

func TestFDAuthorityRetriesParentSyncAfterFailure(t *testing.T) {
	anchor, err := openAuthorityDirectory(t.TempDir())
	mustNoError(t, err)
	defer anchor.close()
	want := errors.New("sync failed")
	calls := 0
	anchor.ops.fsync = func(fd int) error {
		calls++
		if calls == 1 {
			return want
		}
		return unix.Fsync(fd)
	}
	if _, err := anchor.ensure("child"); !errors.Is(err, want) {
		t.Fatalf("first ensure = %v", err)
	}
	dir, err := anchor.ensure("child")
	mustNoError(t, err)
	mustNoError(t, dir.close())
	if calls != 2 {
		t.Fatalf("parent sync calls = %d, want 2", calls)
	}
}

func TestFDAuthorityImmutableConflictCleansUp(t *testing.T) {
	root := t.TempDir()
	syncs := 0
	dir, err := openAuthorityDirectory(root)
	mustNoError(t, err)
	fd := dir.fd
	mustNoError(t, dir.publishImmutable("receipt", []byte("first"), 0o640))
	dir.ops.fsync = func(fd int) error { syncs++; return unix.Fsync(fd) }
	mustNoError(t, dir.publishImmutable("receipt", []byte("first"), 0o640))
	err = dir.publishImmutable("receipt", []byte("second"), 0o640)
	var conflict *ImmutablePublicationConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("conflict error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "receipt"))
	if err != nil || string(got) != "first" {
		t.Fatalf("receipt = %q, %v", got, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "receipt" {
		t.Fatalf("residue = %v, %v", entries, err)
	}
	if syncs != 2 {
		t.Fatalf("cleanup syncs = %d, want 2", syncs)
	}
	mustNoError(t, dir.close())
	if err := unix.Fsync(fd); !errors.Is(err, unix.EBADF) {
		t.Fatalf("fsync closed fd = %v, want EBADF", err)
	}
}

func TestFDAuthorityImmutableSpecialFilesReturnConflict(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "receipt")
			if kind == "fifo" {
				mustNoError(t, unix.Mkfifo(path, 0o600))
			} else {
				mustNoError(t, os.Symlink("missing", path))
			}
			dir, err := openAuthorityDirectory(root)
			mustNoError(t, err)
			defer dir.close()
			result := make(chan error, 1)
			go func() { result <- dir.publishImmutable("receipt", []byte("new"), 0o600) }()
			select {
			case err := <-result:
				var conflict *ImmutablePublicationConflictError
				if !errors.As(err, &conflict) {
					t.Fatalf("%s error = %v", kind, err)
				}
			case <-time.After(200 * time.Millisecond):
				if kind == "fifo" {
					fd, _ := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK, 0)
					_ = unix.Close(fd)
				}
				t.Fatalf("%s publication blocked", kind)
			}
		})
	}
}
func mustNoError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
