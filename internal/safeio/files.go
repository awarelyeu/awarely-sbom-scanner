// Package safeio owns the filesystem boundary for untrusted inventory inputs.
package safeio

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

var ErrLimit = errors.New("input exceeds the supported size limit")

// ReadRegular never opens a final symlink, FIFO or device for reading. Root
// confines intermediate symlink resolution even if directories are renamed.
func ReadRegular(ctx context.Context, root *os.Root, name string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !singleRegularFile(info) {
		return nil, errors.New("input must be a regular file with one link, not a symlink or special file")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("cannot safely open input")
	}
	defer f.Close()
	info, err = f.Stat()
	if err != nil || !singleRegularFile(info) {
		return nil, errors.New("input changed or is not a regular file")
	}
	if info.Size() > limit {
		return nil, ErrLimit
	}
	b, err := io.ReadAll(io.LimitReader(contextReader{ctx, f}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrLimit
	}
	return b, ctx.Err()
}

func singleRegularFile(info os.FileInfo) bool {
	if !info.Mode().IsRegular() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// WriteNew publishes a fully written 0600 file with an atomic no-replace hard
// link. Neither a preexisting file nor a symlink at destination is replaced.
// The caller must select an output directory it controls; a malicious same-UID
// process with access to that directory is outside this protection boundary.
func WriteNew(path string, data []byte) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return errors.New("cannot open output directory")
	}
	defer root.Close()
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return errors.New("output must name a new file")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("cannot create output name")
	}
	tmp := ".awarely-scan-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return errors.New("cannot create private output file")
	}
	defer root.Remove(tmp)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return errors.New("cannot write output")
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return errors.New("cannot sync output")
	}
	if err = f.Close(); err != nil {
		return errors.New("cannot close output")
	}
	if err = root.Link(tmp, name); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("output already exists; choose a new filename")
		}
		return fmt.Errorf("cannot publish output atomically: %w", err)
	}
	return nil
}
