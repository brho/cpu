// Copyright 2026 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"errors"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hugelgupf/p9/linux"
	"github.com/hugelgupf/p9/p9"
)

func cleanRelPath(p string) string {
	return path.Clean("/" + filepath.ToSlash(p))
}

type pathState uint8

const (
	pathDisallowed pathState = iota
	pathAncestor
	pathExported
)

type pathCheck uint8

const (
	checkAncestors pathCheck = iota
	checkNotSymlink
	checkDir
	checkRegularOrDir
)

// allowList classifies paths relative to the exported root into three states:
//   - exported: the path equals or is beneath an explicitly allowed entry.
//   - ancestor: "/" (always at least an ancestor so an empty allow list mounts
//     cleanly) or a strict parent directory of at least one allowed entry,
//     allowing read-only traversal, stat, and filtered directory listing.
//   - disallowed: all other paths.
type allowList []string

func newAllowList(paths []string) allowList {
	cleaned := make([]string, 0, len(paths))
	for _, p := range paths {
		if len(p) == 0 {
			continue
		}
		cleaned = append(cleaned, cleanRelPath(p))
	}
	slices.Sort(cleaned)
	return slices.Compact(cleaned)
}

func (a allowList) classify(p string) pathState {
	p = cleanRelPath(p)
	ancestor := p == "/"
	prefix := p + "/"
	for _, allowed := range a {
		if allowed == "/" || p == allowed || strings.HasPrefix(p, allowed+"/") {
			return pathExported
		}
		if !ancestor && strings.HasPrefix(allowed, prefix) {
			ancestor = true
		}
	}
	if ancestor {
		return pathAncestor
	}
	return pathDisallowed
}

func (a allowList) isExported(p string) bool {
	return a.classify(p) == pathExported
}

func (a allowList) isAllowed(p string) bool {
	return a.classify(p) != pathDisallowed
}

func validComponent(name string) bool {
	return len(name) > 0 && name != "." && name != ".." && !strings.ContainsAny(name, `/\`)
}

type filter9PAttacher struct {
	p9.Attacher
	allow allowList
	mu    sync.RWMutex
}

// NewFilter9P wraps a p9.Attacher so that only paths in allow (and read-only
// traversal through their ancestor directories) are exposed to the client.
func NewFilter9P(a p9.Attacher, allow []string) p9.Attacher {
	return &filter9PAttacher{
		Attacher: a,
		allow:    newAllowList(allow),
	}
}

// filter9PRoot holds an independent cloned root fid used by checkPath to
// re-verify intermediate components from "/" without calling Attach again.
type filter9PRoot struct {
	file p9.File
	refs atomic.Int64
}

// Attach implements p9.Attacher.Attach.
func (a *filter9PAttacher) Attach() (p9.File, error) {
	f, err := a.Attacher.Attach()
	if err != nil {
		return nil, err
	}
	_, checkRoot, err := f.Walk(nil)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	r := &filter9PRoot{file: checkRoot}
	r.refs.Store(1)
	return &filter9PFile{
		File:     f,
		attacher: a,
		root:     r,
		relPath:  "/",
	}, nil
}

type filter9PFile struct {
	p9.File
	attacher *filter9PAttacher
	root     *filter9PRoot
	relPath  string
	opened   atomic.Bool
	closed   atomic.Bool
}

func (f *filter9PFile) wrapChild(nf p9.File, relPath string, opened bool) *filter9PFile {
	f.root.refs.Add(1)
	child := &filter9PFile{
		File:     nf,
		attacher: f.attacher,
		root:     f.root,
		relPath:  relPath,
	}
	if opened {
		child.opened.Store(true)
	}
	return child
}

// Close implements p9.File.Close.
func (f *filter9PFile) Close() error {
	err := f.File.Close()
	if f.closed.CompareAndSwap(false, true) && f.root.refs.Add(-1) == 0 {
		f.attacher.mu.Lock()
		_ = f.root.file.Close()
		f.attacher.mu.Unlock()
	}
	return err
}

func fileTypeOf(f p9.File) (p9.FileMode, error) {
	_, valid, attr, err := f.GetAttr(p9.AttrMask{Mode: true})
	if err != nil {
		return 0, err
	}
	if !valid.Mode {
		return 0, os.ErrPermission
	}
	return attr.Mode.FileType(), nil
}

// checkPath walks from the attached root one component at a time to ensure no
// intermediate component of f.relPath is a symlink (closing stale-fid symlink
// replacement escapes). Depending on mode, it also verifies the leaf type.
// Callers must hold f.attacher.mu (RLock or Lock).
func (f *filter9PFile) checkPath(mode pathCheck) error {
	var parts []string
	if trimmed := strings.TrimPrefix(f.relPath, "/"); trimmed != "" {
		parts = strings.Split(trimmed, "/")
	}
	if mode == checkAncestors && len(parts) <= 1 {
		return nil
	}

	limit := len(parts)
	if mode == checkAncestors {
		limit--
	}
	cur := f.root.file
	defer func() {
		if cur != f.root.file {
			_ = cur.Close()
		}
	}()

	var leafQID p9.QIDType
	for i := range limit {
		qids, nf, err := cur.Walk([]string{parts[i]})
		if err != nil {
			return err
		}
		if cur != f.root.file {
			_ = cur.Close()
		}
		cur = nf
		if len(qids) != 1 {
			return os.ErrInvalid
		}
		leafQID = qids[0].Type
		if i < len(parts)-1 && leafQID != p9.TypeDir {
			return os.ErrPermission
		}
	}
	if mode == checkAncestors {
		return nil
	}
	if mode == checkRegularOrDir || len(parts) == 0 {
		// Inspect the full FileMode for checkRegularOrDir because p9
		// maps block devices to TypeRegular, and for "/" because no
		// Walk QID was produced.
		ft, err := fileTypeOf(cur)
		if err != nil {
			return err
		}
		if mode == checkRegularOrDir {
			if ft != p9.ModeRegular && ft != p9.ModeDirectory {
				return os.ErrPermission
			}
			return nil
		}
		leafQID = ft.QIDType()
	}
	switch mode {
	case checkDir:
		if leafQID != p9.TypeDir {
			return linux.ENOTDIR
		}
	case checkNotSymlink:
		if leafQID == p9.TypeSymlink {
			return os.ErrPermission
		}
	}
	return nil
}

func (f *filter9PFile) checkMutateDir(name string) error {
	if !validComponent(name) || !f.attacher.allow.isExported(f.relPath) {
		return os.ErrPermission
	}
	return f.checkPath(checkDir)
}

func (f *filter9PFile) checkMutateFile() error {
	if !f.attacher.allow.isExported(f.relPath) {
		return os.ErrPermission
	}
	return f.checkPath(checkNotSymlink)
}

func (f *filter9PFile) checkReadMeta() error {
	switch f.attacher.allow.classify(f.relPath) {
	case pathExported:
		return f.checkPath(checkNotSymlink)
	case pathAncestor:
		return f.checkPath(checkDir)
	default:
		return os.ErrPermission
	}
}

// WalkGetAttr forces Walk+GetAttr fallback so returned files stay wrapped.
func (f *filter9PFile) WalkGetAttr(names []string) ([]p9.QID, p9.File, p9.AttrMask, p9.Attr, error) {
	return p9.DefaultWalkGetAttr{}.WalkGetAttr(names)
}

// GetAttr implements p9.File.GetAttr.
func (f *filter9PFile) GetAttr(req p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	// An opened fid already passed Open/Create checks and localfs uses
	// fstat on the open FD, preserving POSIX fstat after unlink.
	// Path-based methods (SetAttr, *Xattr) must not copy this bypass.
	if f.opened.Load() {
		return f.File.GetAttr(req)
	}
	f.attacher.mu.RLock()
	defer f.attacher.mu.RUnlock()
	if err := f.checkPath(checkAncestors); err != nil {
		return p9.QID{}, p9.AttrMask{}, p9.Attr{}, err
	}
	return f.File.GetAttr(req)
}

// Readlink implements p9.File.Readlink.
func (f *filter9PFile) Readlink() (string, error) {
	f.attacher.mu.RLock()
	defer f.attacher.mu.RUnlock()
	if err := f.checkPath(checkAncestors); err != nil {
		return "", err
	}
	return f.File.Readlink()
}

// Walk implements p9.File.Walk.
func (f *filter9PFile) Walk(names []string) ([]p9.QID, p9.File, error) {
	f.attacher.mu.RLock()
	defer f.attacher.mu.RUnlock()

	if len(names) == 0 {
		qids, nf, err := f.File.Walk(nil)
		if err != nil {
			return nil, nil, err
		}
		return qids, f.wrapChild(nf, f.relPath, false), nil
	}

	curPath := f.relPath
	walkNames := make([]string, len(names))
	for i, name := range names {
		if name != ".." && !validComponent(name) {
			return nil, nil, os.ErrInvalid
		}
		if curPath == "/" && name == ".." {
			walkNames[i] = "."
			continue
		}
		next := path.Join(curPath, name)
		if !f.attacher.allow.isAllowed(next) {
			return nil, nil, os.ErrNotExist
		}
		walkNames[i] = name
		curPath = next
	}

	// Never traverse out of a non-directory or stale fid behind a symlink.
	if err := f.checkPath(checkDir); err != nil {
		return nil, nil, err
	}

	// Walk one component at a time so an intermediate symlink is never
	// followed by the backing p9.File (e.g. localfs.Local.Walk).
	qids := make([]p9.QID, 0, len(walkNames))
	cur := f.File
	for i, name := range walkNames {
		stepQIDs, nf, err := cur.Walk([]string{name})
		if cur != f.File {
			_ = cur.Close()
		}
		if err != nil {
			return nil, nil, err
		}
		if len(stepQIDs) != 1 {
			_ = nf.Close()
			return nil, nil, os.ErrInvalid
		}
		if i < len(walkNames)-1 && stepQIDs[0].Type != p9.TypeDir {
			_ = nf.Close()
			return nil, nil, linux.ENOTDIR
		}
		qids = append(qids, stepQIDs[0])
		cur = nf
	}
	return qids, f.wrapChild(cur, curPath, false), nil
}

// Open implements p9.File.Open.
func (f *filter9PFile) Open(mode p9.OpenFlags) (p9.QID, uint32, error) {
	f.attacher.mu.RLock()
	defer f.attacher.mu.RUnlock()
	switch f.attacher.allow.classify(f.relPath) {
	case pathExported:
		// Reject symlinks and special files (FIFOs, sockets, devices)
		// before opening so a blocking open(2) cannot hold attacher.mu
		// and deadlock the 9P server.
		if err := f.checkPath(checkRegularOrDir); err != nil {
			return p9.QID{}, 0, err
		}
	case pathAncestor:
		const writeFlags = p9DotlCreate | p9DotlTrunc | p9DotlAppend
		if mode.Mode() != p9.ReadOnly || mode&writeFlags != 0 {
			return p9.QID{}, 0, os.ErrPermission
		}
		if err := f.checkPath(checkDir); err != nil {
			return p9.QID{}, 0, err
		}
	default:
		return p9.QID{}, 0, os.ErrPermission
	}
	qid, iounit, err := f.File.Open(mode)
	if err != nil {
		return p9.QID{}, 0, err
	}
	f.opened.Store(true)
	return qid, iounit, nil
}

// Readdir implements p9.File.Readdir.
func (f *filter9PFile) Readdir(offset uint64, count uint32) (p9.Dirents, error) {
	f.attacher.mu.RLock()
	defer f.attacher.mu.RUnlock()
	if err := f.checkPath(checkDir); err != nil {
		return nil, err
	}
	switch f.attacher.allow.classify(f.relPath) {
	case pathExported:
		return f.File.Readdir(offset, count)
	case pathAncestor:
		var filtered p9.Dirents
		for {
			ents, err := f.File.Readdir(offset, math.MaxInt32)
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			for _, de := range ents {
				if !f.attacher.allow.isAllowed(path.Join(f.relPath, de.Name)) {
					continue
				}
				if uint64(len(filtered)) >= uint64(count) {
					return filtered, nil
				}
				filtered = append(filtered, de)
			}
			if len(filtered) > 0 || len(ents) == 0 || errors.Is(err, io.EOF) {
				return filtered, err
			}
			nextOffset := ents[len(ents)-1].Offset
			if nextOffset <= offset {
				return filtered, nil
			}
			offset = nextOffset
		}
	default:
		return nil, os.ErrPermission
	}
}

// Create implements p9.File.Create.
func (f *filter9PFile) Create(name string, mode p9.OpenFlags, permissions p9.FileMode, uid p9.UID, gid p9.GID) (p9.File, p9.QID, uint32, error) {
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateDir(name); err != nil {
		return nil, p9.QID{}, 0, err
	}
	nf, qid, iounit, err := f.File.Create(name, mode, permissions, uid, gid)
	if err != nil {
		return nil, p9.QID{}, 0, err
	}
	return f.wrapChild(nf, path.Join(f.relPath, name), true), qid, iounit, nil
}

// Mkdir implements p9.File.Mkdir.
func (f *filter9PFile) Mkdir(name string, permissions p9.FileMode, uid p9.UID, gid p9.GID) (p9.QID, error) {
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateDir(name); err != nil {
		return p9.QID{}, err
	}
	return f.File.Mkdir(name, permissions, uid, gid)
}

// Symlink implements p9.File.Symlink.
func (f *filter9PFile) Symlink(oldname string, newname string, uid p9.UID, gid p9.GID) (p9.QID, error) {
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateDir(newname); err != nil {
		return p9.QID{}, err
	}
	return f.File.Symlink(oldname, newname, uid, gid)
}

// Link implements p9.File.Link.
func (f *filter9PFile) Link(target p9.File, newname string) error {
	tf, ok := target.(*filter9PFile)
	if !ok {
		return os.ErrInvalid
	}
	if tf.attacher != f.attacher {
		return linux.EXDEV
	}
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateDir(newname); err != nil {
		return err
	}
	// Reject non-exported targets, symlinks (link(2) on macOS follows
	// symlinks), and stale targets behind replaced intermediate symlinks.
	if err := tf.checkMutateFile(); err != nil {
		return err
	}
	return f.File.Link(tf.File, newname)
}

// Mknod implements p9.File.Mknod.
func (f *filter9PFile) Mknod(name string, mode p9.FileMode, major uint32, minor uint32, uid p9.UID, gid p9.GID) (p9.QID, error) {
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateDir(name); err != nil {
		return p9.QID{}, err
	}
	return f.File.Mknod(name, mode, major, minor, uid, gid)
}

// Rename returns ENOSYS; p9.Server uses RenameAt.
func (f *filter9PFile) Rename(directory p9.File, name string) error {
	return linux.ENOSYS
}

// RenameAt implements p9.File.RenameAt.
func (f *filter9PFile) RenameAt(oldName string, newDir p9.File, newName string) error {
	nd, ok := newDir.(*filter9PFile)
	if !ok {
		return os.ErrInvalid
	}
	if nd.attacher != f.attacher {
		return linux.EXDEV
	}
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateDir(oldName); err != nil {
		return err
	}
	if err := nd.checkMutateDir(newName); err != nil {
		return err
	}
	return f.File.RenameAt(oldName, nd.File, newName)
}

// UnlinkAt implements p9.File.UnlinkAt.
func (f *filter9PFile) UnlinkAt(name string, flags uint32) error {
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateDir(name); err != nil {
		return err
	}
	return f.File.UnlinkAt(name, flags)
}

// Renamed implements p9.File.Renamed.
func (f *filter9PFile) Renamed(parent p9.File, newName string) {
	if pf, ok := parent.(*filter9PFile); ok && pf.attacher == f.attacher {
		f.attacher.mu.Lock()
		f.relPath = cleanRelPath(path.Join(pf.relPath, newName))
		f.File.Renamed(pf.File, newName)
		f.attacher.mu.Unlock()
	}
}

// SetAttr implements p9.File.SetAttr.
func (f *filter9PFile) SetAttr(valid p9.SetAttrMask, attr p9.SetAttr) error {
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateFile(); err != nil {
		return err
	}
	return f.File.SetAttr(valid, attr)
}

// GetXattr implements p9.File.GetXattr.
func (f *filter9PFile) GetXattr(attr string) ([]byte, error) {
	f.attacher.mu.RLock()
	defer f.attacher.mu.RUnlock()
	if err := f.checkReadMeta(); err != nil {
		return nil, err
	}
	return f.File.GetXattr(attr)
}

// ListXattrs implements p9.File.ListXattrs.
func (f *filter9PFile) ListXattrs() ([]string, error) {
	f.attacher.mu.RLock()
	defer f.attacher.mu.RUnlock()
	if err := f.checkReadMeta(); err != nil {
		return nil, err
	}
	return f.File.ListXattrs()
}

// SetXattr implements p9.File.SetXattr.
func (f *filter9PFile) SetXattr(attr string, data []byte, flags p9.XattrFlags) error {
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateFile(); err != nil {
		return err
	}
	return f.File.SetXattr(attr, data, flags)
}

// RemoveXattr implements p9.File.RemoveXattr.
func (f *filter9PFile) RemoveXattr(attr string) error {
	f.attacher.mu.Lock()
	defer f.attacher.mu.Unlock()
	if err := f.checkMutateFile(); err != nil {
		return err
	}
	return f.File.RemoveXattr(attr)
}
