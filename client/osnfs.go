package client

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-billy/v5"
	osfs "github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-billy/v5/util"
)

// rootRelPath trims leading slashes without cleaning ".." so os.Root rejects
// traversal escapes in osFS.Lstat, osFS.Readlink, and COS.withRoot.
func rootRelPath(name string) string {
	rel := strings.TrimLeft(filepath.ToSlash(name), "/")
	if rel == "" {
		return "."
	}
	return rel
}

func validTempPrefix(prefix string) bool {
	return !strings.ContainsAny(prefix, "/\\\x00") && (prefix == "" || filepath.IsLocal(prefix))
}

// namedFile wraps a billy.File so Name() returns the root-relative virtual
// path rather than BoundOS's host-absolute path, preserving round-tripping
// into Lstat/Remove (including go-nfs post-op attributes on NFSv3 CREATE).
type namedFile struct {
	billy.File
	name string
}

func (f *namedFile) Name() string {
	return f.name
}

// errFS is a fail-closed billy.Filesystem returned by NewOSFS on an empty or
// unresolvable root so it never delegates to BoundOS{baseDir: ""} (host "/").
type errFS struct{}

func (errFS) Create(string) (billy.File, error)                     { return nil, os.ErrInvalid }
func (errFS) Open(string) (billy.File, error)                       { return nil, os.ErrInvalid }
func (errFS) OpenFile(string, int, os.FileMode) (billy.File, error) { return nil, os.ErrInvalid }
func (errFS) Stat(string) (os.FileInfo, error)                      { return nil, os.ErrInvalid }
func (errFS) Rename(string, string) error                           { return os.ErrInvalid }
func (errFS) Remove(string) error                                   { return os.ErrInvalid }
func (errFS) Join(elem ...string) string                            { return filepath.Join(elem...) }
func (errFS) TempFile(string, string) (billy.File, error)           { return nil, os.ErrInvalid }
func (errFS) ReadDir(string) ([]os.FileInfo, error)                 { return nil, os.ErrInvalid }
func (errFS) MkdirAll(string, os.FileMode) error                    { return os.ErrInvalid }
func (errFS) Lstat(string) (os.FileInfo, error)                     { return nil, os.ErrInvalid }
func (errFS) Symlink(string, string) error                          { return os.ErrInvalid }
func (errFS) Readlink(string) (string, error)                       { return "", os.ErrInvalid }
func (errFS) Chroot(string) (billy.Filesystem, error)               { return nil, os.ErrInvalid }
func (errFS) Root() string                                          { return "" }

// osFS wraps BoundOS to harden host filesystem access:
//   - Lstat and Readlink use os.OpenRoot instead of BoundOS.insideBaseDirEval
//     (which breaks on Windows drive roots and wraps escapes as ErrNotExist).
//   - Open, OpenFile, Create, and TempFile normalize local relative paths and
//     return root-relative billy.File names via namedFile.
//   - TempFile uses util.TempFile via OpenFile instead of BoundOS.TempFile
//     (which falls back to host os.TempDir() on SecureJoin errors).
//   - Chroot returns os.ErrInvalid rather than downgrading to ChrootOS.
type osFS struct {
	billy.Filesystem
}

func (fs osFS) Lstat(filename string) (os.FileInfo, error) {
	r, err := os.OpenRoot(fs.Root())
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.Lstat(rootRelPath(filename))
}

func (fs osFS) Readlink(link string) (string, error) {
	r, err := os.OpenRoot(fs.Root())
	if err != nil {
		return "", err
	}
	defer r.Close()
	return r.Readlink(rootRelPath(link))
}

func (fs osFS) openNamed(filename string, fn func(string) (billy.File, error)) (billy.File, error) {
	rel := rootRelPath(cleanRelPath(filename))
	if !filepath.IsLocal(rel) {
		return nil, os.ErrPermission
	}
	f, err := fn(rel)
	if err != nil {
		return nil, err
	}
	return &namedFile{File: f, name: rel}, nil
}

func (fs osFS) Open(filename string) (billy.File, error) {
	return fs.openNamed(filename, fs.Filesystem.Open)
}

func (fs osFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	return fs.openNamed(filename, func(rel string) (billy.File, error) {
		return fs.Filesystem.OpenFile(rel, flag, perm)
	})
}

func (fs osFS) Create(filename string) (billy.File, error) {
	return fs.openNamed(filename, fs.Filesystem.Create)
}

func (fs osFS) TempFile(dir, prefix string) (billy.File, error) {
	if !validTempPrefix(prefix) {
		return nil, os.ErrInvalid
	}
	rel := rootRelPath(cleanRelPath(dir))
	fi, err := fs.Lstat(rel)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, os.ErrInvalid
	}
	return util.TempFile(fs, rel, prefix)
}

func (osFS) Chroot(string) (billy.Filesystem, error) {
	return nil, os.ErrInvalid
}

// NewOSFS returns a billy.Filesystem for a path. An empty root (or one whose
// absolute path cannot be resolved) fails closed rather than exporting CWD or
// host "/".
func NewOSFS(r string) billy.Filesystem {
	if r == "" {
		return errFS{}
	}
	r, err := filepath.Abs(r)
	if err != nil {
		return errFS{}
	}
	// Resolve symlinks in -root (e.g. /var -> /private/var on macOS) so
	// BoundOS matches the canonical directory path.
	if resolved, err := filepath.EvalSymlinks(r); err == nil {
		r = resolved
	}
	return osFS{osfs.New(r, osfs.WithBoundOS(), osfs.WithDeduplicatePath(false))}
}

// COS or OSFS + Change wraps a billy.FS to not fail the `Change` interface.
type COS struct {
	billy.Filesystem
}

func (fs COS) withRoot(name string, fn func(*os.Root, string) error) error {
	r, err := os.OpenRoot(fs.Root())
	if err != nil {
		return err
	}
	defer r.Close()
	return fn(r, rootRelPath(name))
}

// Chmod changes mode
func (fs COS) Chmod(name string, mode os.FileMode) error {
	return fs.withRoot(name, func(r *os.Root, rel string) error {
		return r.Chmod(rel, mode)
	})
}

// Lchown changes ownership. As in lchown(2), it does not
// follow a symlink.
func (fs COS) Lchown(name string, uid, gid int) error {
	return fs.withRoot(name, func(r *os.Root, rel string) error {
		return r.Lchown(rel, uid, gid)
	})
}

// Chown changes ownership
func (fs COS) Chown(name string, uid, gid int) error {
	return fs.withRoot(name, func(r *os.Root, rel string) error {
		return r.Chown(rel, uid, gid)
	})
}

// Chtimes changes access time
func (fs COS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return fs.withRoot(name, func(r *os.Root, rel string) error {
		return r.Chtimes(rel, atime, mtime)
	})
}

// canMutatePath reports whether p's parent directory is inside an exported
// subtree, so creating, removing, or renaming p will not modify a read-only
// ancestor directory.
func (a allowList) canMutatePath(p string) bool {
	p = cleanRelPath(p)
	return p != "/" && a.isExported(path.Dir(p))
}

// filterFS wraps a billy.Filesystem (and optional billy.Change) so that only
// paths in allow (and read-only traversal through their ancestor directories)
// are exposed. mu serializes symlink checks against mutating operations across
// concurrent NFS connections.
type filterFS struct {
	base  billy.Filesystem
	allow allowList
	mu    sync.RWMutex
}

var _ billy.Change = &filterFS{}

// NewFilterFS returns a billy.Filesystem restricted to paths in allow.
func NewFilterFS(fs billy.Filesystem, allow []string) billy.Filesystem {
	return &filterFS{
		base:  fs,
		allow: newAllowList(allow),
	}
}

// Join implements billy.Filesystem.Join.
func (fs *filterFS) Join(elem ...string) string {
	return fs.base.Join(elem...)
}

// Root implements billy.Filesystem.Root.
func (fs *filterFS) Root() string {
	return fs.base.Root()
}

func checkEntry(fi os.FileInfo, mode pathCheck) error {
	// Reject both symlinks and ModeIrregular (Windows NTFS junctions and
	// other surrogate reparse points).
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return os.ErrPermission
	}
	switch mode {
	case checkDir:
		if !fi.IsDir() {
			return os.ErrInvalid
		}
	case checkRegularOrDir:
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return os.ErrPermission
		}
	}
	return nil
}

// checkPath verifies that the exported root exists as a directory, that every
// non-mutable ancestor and mount root exists, that no intermediate path
// component of clean (normalized by cleanRelPath) is a symlink, reparse point,
// or non-directory, enforces mode on the final component, and returns the
// root-relative path:
//   - checkAncestors: allow the final component itself to be a symlink.
//   - checkNotSymlink: reject a symlink or irregular reparse-point leaf.
//   - checkRegularOrDir: also reject existing special files (FIFOs, sockets,
//     devices) so blocking opens cannot deadlock fs.mu.
//   - checkDir: require the final component to exist and be a directory.
func (fs *filterFS) checkPath(clean string, mode pathCheck) (string, error) {
	if strings.ContainsRune(clean, 0) {
		return "", os.ErrInvalid
	}
	rel := rootRelPath(clean)
	// Reject non-local paths (including Windows drive prefixes in any
	// component and reserved device names like CON/NUL that SecureJoin or
	// OpenFile would reinterpret).
	if !filepath.IsLocal(rel) {
		return "", os.ErrPermission
	}
	// Verify the root itself exists as a directory so a missing or invalid
	// root cannot be mistaken for a missing child leaf (and auto-created by
	// BoundOS when allow exports "/").
	rootInfo, err := fs.base.Lstat(".")
	if err != nil {
		return "", err
	}
	if err := checkEntry(rootInfo, checkDir); err != nil {
		return "", err
	}
	if rel == "." {
		return rel, nil
	}
	parts := strings.Split(rel, "/")
	limit := len(parts)
	if mode == checkAncestors {
		limit--
	}
	var prefix string
	for i, part := range parts[:limit] {
		prefix = path.Join(prefix, part)
		fi, err := fs.base.Lstat(prefix)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return "", err
			}
			if mode == checkDir || !fs.allow.canMutatePath("/"+prefix) {
				return "", err
			}
			return rel, nil
		}
		if i < len(parts)-1 {
			if checkEntry(fi, checkDir) != nil {
				return "", os.ErrPermission
			}
			continue
		}
		if err := checkEntry(fi, mode); err != nil {
			return "", err
		}
	}
	return rel, nil
}

func (fs *filterFS) resolveAllowed(filename string, mode pathCheck) (string, error) {
	clean := cleanRelPath(filename)
	if !fs.allow.isAllowed(clean) {
		return "", os.ErrNotExist
	}
	return fs.checkPath(clean, mode)
}

func (fs *filterFS) open(filename string, create bool, fn func(string) (billy.File, error)) (billy.File, error) {
	if create {
		fs.mu.Lock()
		defer fs.mu.Unlock()
	} else {
		fs.mu.RLock()
		defer fs.mu.RUnlock()
	}
	clean := cleanRelPath(filename)
	if create {
		if !fs.allow.canMutatePath(clean) {
			return nil, os.ErrPermission
		}
	} else {
		switch fs.allow.classify(clean) {
		case pathExported:
		case pathAncestor:
			return nil, os.ErrPermission
		default:
			return nil, os.ErrNotExist
		}
	}
	rel, err := fs.checkPath(clean, checkRegularOrDir)
	if err != nil {
		return nil, err
	}
	f, err := fn(rel)
	if err != nil {
		return nil, err
	}
	return &namedFile{File: f, name: rel}, nil
}

// resolveMutate checks that filename is mutable under an exported subtree and
// has no symlink components (BoundOS resolves leaf symlinks via securejoin in
// Remove, Rename, and Symlink too).
func (fs *filterFS) resolveMutate(filename string) (string, error) {
	clean := cleanRelPath(filename)
	if !fs.allow.canMutatePath(clean) {
		return "", os.ErrPermission
	}
	return fs.checkPath(clean, checkNotSymlink)
}

// Stat implements billy.Filesystem.Stat.
func (fs *filterFS) Stat(filename string) (os.FileInfo, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	rel, err := fs.resolveAllowed(filename, checkNotSymlink)
	if err != nil {
		return nil, err
	}
	return fs.base.Stat(rel)
}

// Lstat implements billy.Filesystem.Lstat.
func (fs *filterFS) Lstat(filename string) (os.FileInfo, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	rel, err := fs.resolveAllowed(filename, checkAncestors)
	if err != nil {
		return nil, err
	}
	return fs.base.Lstat(rel)
}

// ReadDir implements billy.Filesystem.ReadDir.
func (fs *filterFS) ReadDir(filename string) ([]os.FileInfo, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	clean := cleanRelPath(filename)
	state := fs.allow.classify(clean)
	if state == pathDisallowed {
		return nil, os.ErrNotExist
	}
	rel, err := fs.checkPath(clean, checkDir)
	if err != nil {
		return nil, err
	}
	entries, err := fs.base.ReadDir(rel)
	if err != nil || state == pathExported {
		return entries, err
	}
	var filtered []os.FileInfo
	for _, fi := range entries {
		if fs.allow.isAllowed(path.Join(clean, fi.Name())) {
			filtered = append(filtered, fi)
		}
	}
	return filtered, nil
}

// Readlink implements billy.Filesystem.Readlink.
func (fs *filterFS) Readlink(link string) (string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	rel, err := fs.resolveAllowed(link, checkAncestors)
	if err != nil {
		return "", err
	}
	return fs.base.Readlink(rel)
}

// Open implements billy.Filesystem.Open.
func (fs *filterFS) Open(filename string) (billy.File, error) {
	return fs.open(filename, false, fs.base.Open)
}

// OpenFile implements billy.Filesystem.OpenFile.
func (fs *filterFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	return fs.open(filename, flag&os.O_CREATE != 0, func(rel string) (billy.File, error) {
		return fs.base.OpenFile(rel, flag, perm)
	})
}

// Create implements billy.Filesystem.Create.
func (fs *filterFS) Create(filename string) (billy.File, error) {
	return fs.open(filename, true, fs.base.Create)
}

// MkdirAll implements billy.Filesystem.MkdirAll.
func (fs *filterFS) MkdirAll(filename string, perm os.FileMode) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	rel, err := fs.resolveMutate(filename)
	if err != nil {
		return err
	}
	return fs.base.MkdirAll(rel, perm)
}

// Remove implements billy.Filesystem.Remove.
func (fs *filterFS) Remove(filename string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	rel, err := fs.resolveMutate(filename)
	if err != nil {
		return err
	}
	return fs.base.Remove(rel)
}

// Rename implements billy.Filesystem.Rename.
func (fs *filterFS) Rename(oldpath, newpath string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	oldRel, err := fs.resolveMutate(oldpath)
	if err != nil {
		return err
	}
	newRel, err := fs.resolveMutate(newpath)
	if err != nil {
		return err
	}
	return fs.base.Rename(oldRel, newRel)
}

// Symlink implements billy.Filesystem.Symlink.
func (fs *filterFS) Symlink(target, link string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	rel, err := fs.resolveMutate(link)
	if err != nil {
		return err
	}
	return fs.base.Symlink(target, rel)
}

// TempFile implements billy.Filesystem.TempFile.
func (fs *filterFS) TempFile(dir, prefix string) (billy.File, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	clean := cleanRelPath(dir)
	if !fs.allow.isExported(clean) {
		return nil, os.ErrPermission
	}
	if !validTempPrefix(prefix) {
		return nil, os.ErrInvalid
	}
	rel, err := fs.checkPath(clean, checkDir)
	if err != nil {
		return nil, err
	}
	// Use util.TempFile via OpenFile instead of BoundOS.TempFile so a
	// SecureJoin error (e.g. ENAMETOOLONG) never falls back to host
	// os.TempDir().
	f, err := util.TempFile(fs.base, rel, prefix)
	if err != nil {
		return nil, err
	}
	return &namedFile{File: f, name: path.Join(rel, filepath.Base(f.Name()))}, nil
}

// Chroot implements billy.Filesystem.Chroot.
func (fs *filterFS) Chroot(_ string) (billy.Filesystem, error) {
	return nil, os.ErrInvalid
}

func (fs *filterFS) change(name string, mode pathCheck, fn func(billy.Change, string) error) error {
	c, ok := fs.base.(billy.Change)
	if !ok {
		return os.ErrPermission
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	clean := cleanRelPath(name)
	if !fs.allow.isExported(clean) {
		return os.ErrPermission
	}
	rel, err := fs.checkPath(clean, mode)
	if err != nil {
		return err
	}
	return fn(c, rel)
}

// Chmod implements billy.Change.Chmod.
func (fs *filterFS) Chmod(name string, mode os.FileMode) error {
	return fs.change(name, checkNotSymlink, func(c billy.Change, rel string) error {
		return c.Chmod(rel, mode)
	})
}

// Lchown implements billy.Change.Lchown.
func (fs *filterFS) Lchown(name string, uid, gid int) error {
	return fs.change(name, checkAncestors, func(c billy.Change, rel string) error {
		return c.Lchown(rel, uid, gid)
	})
}

// Chown implements billy.Change.Chown.
func (fs *filterFS) Chown(name string, uid, gid int) error {
	return fs.change(name, checkNotSymlink, func(c billy.Change, rel string) error {
		return c.Chown(rel, uid, gid)
	})
}

// Chtimes implements billy.Change.Chtimes.
func (fs *filterFS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return fs.change(name, checkNotSymlink, func(c billy.Change, rel string) error {
		return c.Chtimes(rel, atime, mtime)
	})
}
