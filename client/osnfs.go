package client

import (
	"os"
	"path"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5"
	osfs "github.com/go-git/go-billy/v5/osfs"
)

// NewOSFS returns a billy.FileSystem for a path.
func NewOSFS(r string) billy.Filesystem {
	bfs := osfs.New(r, osfs.WithBoundOS())
	return bfs
}

// COS or OSFS + Change wraps a billy.FS to not fail the `Change` interface.
type COS struct {
	billy.Filesystem
}

// Chmod changes mode
func (fs COS) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(fs.Join(fs.Root(), name), mode)
}

// Lchown changes ownership. As in lchown(2), it does not
// follow a symlink.
func (fs COS) Lchown(name string, uid, gid int) error {
	return os.Lchown(fs.Join(fs.Root(), name), uid, gid)
}

// Chown changes ownership
func (fs COS) Chown(name string, uid, gid int) error {
	return os.Chown(fs.Join(fs.Root(), name), uid, gid)
}

// Chtimes changes access time
func (fs COS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return os.Chtimes(fs.Join(fs.Root(), name), atime, mtime)
}

// FilterFS wraps a billy.Filesystem (and optional billy.Change) so that only
// paths in allow (and read-only traversal through their ancestor directories)
// are exposed.
type FilterFS struct {
	billy.Filesystem
	allow *allowList
}

var (
	_ billy.Filesystem = &FilterFS{}
	_ billy.Change     = &FilterFS{}
)

// NewFilterFS returns a billy.Filesystem restricted to paths in allow.
func NewFilterFS(fs billy.Filesystem, allow []string) billy.Filesystem {
	return &FilterFS{
		Filesystem: fs,
		allow:      newAllowList(allow),
	}
}

func relFSPath(p string) string {
	c := strings.TrimPrefix(cleanRelPath(p), "/")
	if c == "" {
		return "."
	}
	return c
}

// Stat implements billy.Filesystem.Stat.
func (fs *FilterFS) Stat(filename string) (os.FileInfo, error) {
	if !fs.allow.isAllowed(filename) {
		return nil, os.ErrNotExist
	}
	return fs.Filesystem.Stat(relFSPath(filename))
}

// Lstat implements billy.Filesystem.Lstat.
func (fs *FilterFS) Lstat(filename string) (os.FileInfo, error) {
	if !fs.allow.isAllowed(filename) {
		return nil, os.ErrNotExist
	}
	return fs.Filesystem.Lstat(relFSPath(filename))
}

// ReadDir implements billy.Filesystem.ReadDir.
func (fs *FilterFS) ReadDir(filename string) ([]os.FileInfo, error) {
	clean := cleanRelPath(filename)
	if fs.allow.isExported(clean) {
		return fs.Filesystem.ReadDir(relFSPath(clean))
	}
	if !fs.allow.isAncestor(clean) {
		return nil, os.ErrNotExist
	}
	entries, err := fs.Filesystem.ReadDir(relFSPath(clean))
	if err != nil {
		return nil, err
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
func (fs *FilterFS) Readlink(link string) (string, error) {
	if !fs.allow.isAllowed(link) {
		return "", os.ErrNotExist
	}
	return fs.Filesystem.Readlink(relFSPath(link))
}

// Open implements billy.Filesystem.Open.
func (fs *FilterFS) Open(filename string) (billy.File, error) {
	if !fs.allow.isExported(filename) {
		if fs.allow.isAncestor(filename) {
			return nil, os.ErrPermission
		}
		return nil, os.ErrNotExist
	}
	return fs.Filesystem.Open(relFSPath(filename))
}

// OpenFile implements billy.Filesystem.OpenFile.
func (fs *FilterFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	if !fs.allow.isExported(filename) {
		if fs.allow.isAncestor(filename) {
			return nil, os.ErrPermission
		}
		return nil, os.ErrNotExist
	}
	if flag&os.O_CREATE != 0 && !fs.allow.canRemovePath(filename) {
		return nil, os.ErrPermission
	}
	return fs.Filesystem.OpenFile(relFSPath(filename), flag, perm)
}

// Create implements billy.Filesystem.Create.
func (fs *FilterFS) Create(filename string) (billy.File, error) {
	if !fs.allow.canRemovePath(filename) {
		return nil, os.ErrPermission
	}
	return fs.Filesystem.Create(relFSPath(filename))
}

// MkdirAll implements billy.Filesystem.MkdirAll.
func (fs *FilterFS) MkdirAll(filename string, perm os.FileMode) error {
	if !fs.allow.canRemovePath(filename) {
		return os.ErrPermission
	}
	return fs.Filesystem.MkdirAll(relFSPath(filename), perm)
}

// Remove implements billy.Filesystem.Remove.
func (fs *FilterFS) Remove(filename string) error {
	if !fs.allow.canRemovePath(filename) {
		return os.ErrPermission
	}
	return fs.Filesystem.Remove(relFSPath(filename))
}

// Rename implements billy.Filesystem.Rename.
func (fs *FilterFS) Rename(oldpath, newpath string) error {
	if !fs.allow.canRemovePath(oldpath) || !fs.allow.canRemovePath(newpath) {
		return os.ErrPermission
	}
	return fs.Filesystem.Rename(relFSPath(oldpath), relFSPath(newpath))
}

// Symlink implements billy.Filesystem.Symlink.
func (fs *FilterFS) Symlink(target, link string) error {
	if !fs.allow.canRemovePath(link) {
		return os.ErrPermission
	}
	return fs.Filesystem.Symlink(target, relFSPath(link))
}

// TempFile implements billy.Filesystem.TempFile.
func (fs *FilterFS) TempFile(dir, prefix string) (billy.File, error) {
	if !fs.allow.isExported(dir) {
		return nil, os.ErrPermission
	}
	return fs.Filesystem.TempFile(relFSPath(dir), prefix)
}

// Chroot implements billy.Filesystem.Chroot.
func (fs *FilterFS) Chroot(_ string) (billy.Filesystem, error) {
	return nil, os.ErrInvalid
}

// Chmod implements billy.Change.Chmod.
func (fs *FilterFS) Chmod(name string, mode os.FileMode) error {
	if !fs.allow.isExported(name) {
		return os.ErrPermission
	}
	if c, ok := fs.Filesystem.(billy.Change); ok {
		return c.Chmod(relFSPath(name), mode)
	}
	return os.ErrPermission
}

// Lchown implements billy.Change.Lchown.
func (fs *FilterFS) Lchown(name string, uid, gid int) error {
	if !fs.allow.isExported(name) {
		return os.ErrPermission
	}
	if c, ok := fs.Filesystem.(billy.Change); ok {
		return c.Lchown(relFSPath(name), uid, gid)
	}
	return os.ErrPermission
}

// Chown implements billy.Change.Chown.
func (fs *FilterFS) Chown(name string, uid, gid int) error {
	if !fs.allow.isExported(name) {
		return os.ErrPermission
	}
	if c, ok := fs.Filesystem.(billy.Change); ok {
		return c.Chown(relFSPath(name), uid, gid)
	}
	return os.ErrPermission
}

// Chtimes implements billy.Change.Chtimes.
func (fs *FilterFS) Chtimes(name string, atime time.Time, mtime time.Time) error {
	if !fs.allow.isExported(name) {
		return os.ErrPermission
	}
	if c, ok := fs.Filesystem.(billy.Change); ok {
		return c.Chtimes(relFSPath(name), atime, mtime)
	}
	return os.ErrPermission
}
