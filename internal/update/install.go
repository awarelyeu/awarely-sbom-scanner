package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

// A backup is addressed by the replacement binary's digest. Publishing it before
// the atomic executable rename gives that executable its matching rollback even
// if the process stops between the two writes. The current binary stays runnable.
type backup struct {
	Version         string `json:"version"`
	PreviousDigest  string `json:"previousDigest"`
	InstalledDigest string `json:"installedDigest"`
	Binary          []byte `json:"binary"`
}
type installation struct {
	name, dir, state string
	lock             *os.File
	root             *os.Root
}

func secureDirectory(dir string) error {
	for p := dir; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil {
			return e
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 || (int(st.Uid) != os.Geteuid() && st.Uid != 0) {
			return errors.New("installation path must have trusted, non-writable, real parent directories")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}
func openInstallation(executable string) (*installation, error) {
	if !filepath.IsAbs(executable) || filepath.Base(executable) != "awarely-scan" {
		return nil, errors.New("install the binary as awarely-scan in a directory you own")
	}
	dir := filepath.Dir(executable)
	if e := secureDirectory(dir); e != nil {
		return nil, e
	}
	di, e := os.Stat(dir)
	if e != nil {
		return nil, e
	}
	if int(di.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return nil, errors.New("installation directory must belong to this user; do not use sudo")
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	i := &installation{name: "awarely-scan", dir: dir, state: filepath.Join(dir, ".awarely-scan-update"), root: root}
	if e = root.Mkdir(".awarely-scan-update", 0700); e != nil && !errors.Is(e, os.ErrExist) {
		root.Close()
		return nil, e
	}
	info, e := root.Lstat(".awarely-scan-update")
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || int(info.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		root.Close()
		return nil, errors.New("update directory must be a private directory owned by this user")
	}
	f, e := root.OpenFile(".awarely-scan-update/lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		root.Close()
		return nil, e
	}
	info, e = f.Stat()
	if e != nil || !ownedFile(info) || info.Mode().Perm() != 0600 {
		f.Close()
		root.Close()
		return nil, errors.New("unsafe update lock")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		root.Close()
		return nil, errors.New("another update is running; retry after it finishes")
	}
	i.lock = f
	return i, nil
}
func ownedFile(info os.FileInfo) bool {
	if info == nil || !info.Mode().IsRegular() {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid() && st.Nlink == 1 && info.Mode().Perm()&0022 == 0 && info.Mode()&(os.ModeSetuid|os.ModeSetgid) == 0
}
func (i *installation) close() { i.lock.Close(); i.root.Close() }
func (i *installation) read(name string, limit int64) ([]byte, error) {
	f, e := i.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !ownedFile(info) || info.Size() < 1 || info.Size() > limit {
		return nil, errors.New("installed file is unsafe or exceeds size limit")
	}
	b := make([]byte, info.Size())
	n, e := f.ReadAt(b, 0)
	if e != nil || n != len(b) {
		return nil, errors.New("cannot read installed file")
	}
	return b, nil
}
func (i *installation) temp(b []byte, mode os.FileMode) (string, error) {
	f, e := os.CreateTemp(i.dir, ".awarely-stage-")
	if e != nil {
		return "", e
	}
	name := filepath.Base(f.Name())
	good := false
	defer func() {
		f.Close()
		if !good {
			i.root.Remove(name)
		}
	}()
	if _, e = f.Write(b); e != nil {
		return "", e
	}
	if e = f.Chmod(mode); e != nil {
		return "", e
	}
	if e = f.Sync(); e != nil {
		return "", e
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	good = true
	return name, nil
}
func (i *installation) replace(ctx context.Context, current, next []byte, from, to string, makeBackup bool) error {
	stage, e := i.temp(next, 0700)
	if e != nil {
		return e
	}
	defer i.root.Remove(stage)
	// The archive was authenticated before this startup test. No credentials or
	// user configuration are inherited by the candidate binary.
	probe, e := os.MkdirTemp(i.state, "probe-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(probe)
	got, e := binaryVersion(ctx, filepath.Join(i.dir, stage), probe)
	if e != nil || got != to {
		return errors.New("candidate startup/version check failed; installed binary unchanged")
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	latest, e := i.read(i.name, maxBinary)
	if e != nil || digest(latest) != digest(current) {
		return errors.New("installation changed while updating; retry")
	}
	newDigest := digest(next)
	if makeBackup {
		record := backup{Version: from, PreviousDigest: digest(current), InstalledDigest: newDigest, Binary: current}
		data, e := json.Marshal(record)
		if e != nil {
			return e
		}
		temp, e := i.temp(data, 0600)
		if e != nil {
			return e
		}
		defer i.root.Remove(temp)
		if e = i.root.Rename(temp, ".awarely-scan-update/"+newDigest+".json"); e != nil {
			return e
		}
		state, e := os.Open(i.state)
		if e != nil {
			return e
		}
		e = state.Sync()
		state.Close()
		if e != nil {
			return e
		}
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = i.root.Rename(stage, i.name); e != nil {
		return e
	}
	dir, e := os.Open(i.dir)
	if e == nil {
		e = dir.Sync()
		dir.Close()
	}
	if e != nil {
		return errors.New("binary replaced, but directory flush failed; inspect version before retrying")
	}
	if makeBackup {
		i.prune(newDigest + ".json")
	}
	return nil
}

var backupName = regexp.MustCompile(`^[a-f0-9]{64}\.json$`)

func (i *installation) prune(keep string) {
	entries, e := os.ReadDir(i.state)
	if e != nil {
		return
	}
	for _, entry := range entries {
		if entry.Name() != keep && backupName.MatchString(entry.Name()) {
			_ = i.root.Remove(".awarely-scan-update/" + entry.Name())
		}
	}
}
func (i *installation) previous(current []byte) (backup, error) {
	var b backup
	data, e := i.read(".awarely-scan-update/"+digest(current)+".json", 48<<20)
	if e != nil {
		return b, errors.New("no readable rollback backup for this binary")
	}
	if e = json.Unmarshal(data, &b); e != nil || !validVersion(b.Version) || len(b.Binary) > maxBinary || len(b.Binary) == 0 || b.InstalledDigest != digest(current) || b.PreviousDigest != digest(b.Binary) {
		return backup{}, errors.New("rollback backup failed validation")
	}
	return b, nil
}
func executablePath() (string, error) {
	exe, e := os.Executable()
	if e != nil {
		return "", e
	}
	info, e := os.Stat(exe)
	if e != nil {
		return "", e
	}
	running, e := os.Stat("/proc/self/exe")
	if e != nil || !os.SameFile(info, running) {
		return "", fmt.Errorf("running binary was moved or replaced; restart the scanner before updating")
	}
	return exe, nil
}
