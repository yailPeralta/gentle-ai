//go:build android || darwin || dragonfly || freebsd || ios || linux || netbsd || openbsd

package reviewtransaction

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Readable descriptors are required for parent fsync; search-only ancestry fails closed.
const authorityDirectoryFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC

var errUnsafeAuthorityComponent = errors.New("unsafe authority path component") // refusal:by-design world-action: unsafe authority ancestry cannot be made safe by retrying the same path

type authorityDirectoryOps struct {
	open    func(string, int, uint32) (int, error)
	openat  func(int, string, int, uint32) (int, error)
	mkdirat func(int, string, uint32) error
	fsync   func(int) error
	close   func(int) error
}

type authorityDirectory struct {
	fd  int
	ops authorityDirectoryOps
}

func openAuthorityDirectory(path string) (*authorityDirectory, error) {
	return openAuthorityDirectoryWithOps(path, authorityDirectoryOps{unix.Open, unix.Openat, unix.Mkdirat, unix.Fsync, unix.Close})
}

func openAuthorityDirectoryWithOps(path string, ops authorityDirectoryOps) (*authorityDirectory, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := ops.open(string(filepath.Separator), authorityDirectoryFlags, 0)
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		next, openErr := ops.openat(fd, component, authorityDirectoryFlags|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			_ = ops.close(fd)
			return nil, authorityComponentError(component, openErr)
		}
		_ = ops.close(fd)
		fd = next
	}
	return &authorityDirectory{fd: fd, ops: ops}, nil
}

func authorityComponentError(component string, err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return fmt.Errorf("%w %q: %w", errUnsafeAuthorityComponent, component, err)
	}
	return fmt.Errorf("open authority component %q: %w", component, err)
}

func (dir *authorityDirectory) close() error { return dir.ops.close(dir.fd) }

func (dir *authorityDirectory) ensure(components ...string) (*authorityDirectory, error) {
	fd := dir.fd
	owned := false
	for _, component := range components {
		if component == "" || component == "." || component == ".." || filepath.Base(component) != component {
			if owned {
				_ = dir.ops.close(fd)
			}
			return nil, fmt.Errorf("%w %q", errUnsafeAuthorityComponent, component)
		}
		next, err := dir.ops.openat(fd, component, authorityDirectoryFlags|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ENOENT) {
			if mkdirErr := dir.ops.mkdirat(fd, component, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				if owned {
					_ = dir.ops.close(fd)
				}
				return nil, fmt.Errorf("create authority component %q: %w", component, mkdirErr)
			}
			next, err = dir.ops.openat(fd, component, authorityDirectoryFlags|unix.O_NOFOLLOW, 0)
		}
		if err != nil {
			if owned {
				_ = dir.ops.close(fd)
			}
			return nil, authorityComponentError(component, err)
		}
		if err := dir.ops.fsync(fd); err != nil {
			_ = dir.ops.close(next)
			if owned {
				_ = dir.ops.close(fd)
			}
			return nil, fmt.Errorf("sync authority parent for %q: %w", component, err)
		}
		if owned {
			_ = dir.ops.close(fd)
		}
		fd, owned = next, true
	}
	if !owned {
		return nil, fmt.Errorf("%w: authority directory requires at least one child component", errUnsafeAuthorityComponent)
	}
	return &authorityDirectory{fd: fd, ops: dir.ops}, nil
}

func (dir *authorityDirectory) replace(name string, payload []byte, mode os.FileMode) error {
	return dir.publish(name, payload, mode, false)
}

func (dir *authorityDirectory) publishImmutable(name string, payload []byte, mode os.FileMode) error {
	return dir.publish(name, payload, mode, true)
}

func (dir *authorityDirectory) publish(name string, payload []byte, mode os.FileMode, immutable bool) (resultErr error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("%w %q", errUnsafeAuthorityComponent, name)
	}
	tempName, temp, err := createAuthorityTemp(dir.fd)
	if err != nil {
		return err
	}
	tempLive := true
	defer func() {
		if tempLive {
			resultErr = errors.Join(resultErr, unix.Unlinkat(dir.fd, tempName, 0), dir.ops.fsync(dir.fd))
		}
	}()
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if immutable {
		err = unix.Linkat(dir.fd, tempName, dir.fd, name, 0)
	} else {
		err = unix.Renameat(dir.fd, tempName, dir.fd, name)
		if err == nil {
			tempLive = false
		}
	}
	if immutable && errors.Is(err, unix.EEXIST) {
		existing, readErr := readAuthorityFile(dir.fd, name, int64(len(payload)+1))
		if readErr != nil {
			return &ImmutablePublicationConflictError{Cause: readErr}
		}
		if !bytes.Equal(existing, payload) {
			return &ImmutablePublicationConflictError{Cause: fmt.Errorf("%w: existing content differs", os.ErrExist)}
		}
		err = nil
	}
	if err != nil {
		return err
	}
	if !immutable {
		if syncErr := dir.ops.fsync(dir.fd); syncErr != nil {
			return &directorySyncError{path: name, cause: syncErr}
		}
	}
	return nil
}

func createAuthorityTemp(dirFD int) (string, *os.File, error) {
	for range 10 {
		name := ".authority-" + rand.Text()
		fd, err := unix.Openat(dirFD, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return name, os.NewFile(uintptr(fd), name), nil
	}
	return "", nil, fmt.Errorf("%w: create authority temp file: exhausted unique names", os.ErrExist)
}

func readAuthorityFile(dirFD int, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: existing path is not a regular file", os.ErrInvalid)
	}
	return io.ReadAll(io.LimitReader(file, limit))
}
