// Copyright 2026 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"os"

	"github.com/hugelgupf/p9/fsimpl/localfs"
	"github.com/hugelgupf/p9/linux"
	"github.com/hugelgupf/p9/p9"
)

const (
	// 9P2000.L wire open flags (Linux include/net/9p/9p.h).
	p9DotlTrunc  p9.OpenFlags = 0o0001000
	p9DotlAppend p9.OpenFlags = 0o0002000
	p9DotlDSync  p9.OpenFlags = 0o0010000
	p9DotlSync   p9.OpenFlags = 0o4000000
)

// translateOpenFlags converts 9P2000.L wire open flags (which always use
// Linux x86_64 bit positions) to host os.OpenFile flags so localfs does not
// pass foreign bits on non-x86 Linux, macOS, FreeBSD, or Windows.
func translateOpenFlags(mode p9.OpenFlags) p9.OpenFlags {
	flags := mode.OSFlags() | translatePlatformOpenFlags(mode)
	if mode&p9DotlAppend != 0 {
		flags |= os.O_APPEND
	}
	if mode&p9DotlTrunc != 0 {
		flags |= os.O_TRUNC
	}
	if mode&(p9DotlSync|p9DotlDSync) != 0 {
		flags |= os.O_SYNC
	}
	return p9.OpenFlags(flags)
}

type cpu9PAttacher string

// NewCPU9P returns a p9.Attacher for root using localfs. An empty root fails
// closed on Attach rather than exporting "/". Note that upstream
// localfs.Attacher.Attach clears the process umask to 0 on Unix.
func NewCPU9P(root string) p9.Attacher {
	return cpu9PAttacher(root)
}

func (a cpu9PAttacher) Attach() (p9.File, error) {
	if a == "" {
		return nil, os.ErrInvalid
	}
	f, err := localfs.Attacher(string(a)).Attach()
	if err != nil {
		return nil, err
	}
	return &cpu9PFile{File: f}, nil
}

type cpu9PFile struct {
	p9.File
}

func (f *cpu9PFile) Walk(names []string) ([]p9.QID, p9.File, error) {
	qids, nf, err := f.File.Walk(names)
	if err != nil {
		return nil, nil, err
	}
	return qids, &cpu9PFile{File: nf}, nil
}

// WalkGetAttr forces fallback to Walk+GetAttr so returned files stay wrapped.
func (f *cpu9PFile) WalkGetAttr(names []string) ([]p9.QID, p9.File, p9.AttrMask, p9.Attr, error) {
	return p9.DefaultWalkGetAttr{}.WalkGetAttr(names)
}

func (f *cpu9PFile) Open(mode p9.OpenFlags) (p9.QID, uint32, error) {
	return f.File.Open(translateOpenFlags(mode))
}

func (f *cpu9PFile) Create(name string, mode p9.OpenFlags, permissions p9.FileMode, uid p9.UID, gid p9.GID) (p9.File, p9.QID, uint32, error) {
	nf, qid, iounit, err := f.File.Create(name, translateOpenFlags(mode), permissions, uid, gid)
	if err != nil {
		return nil, p9.QID{}, 0, err
	}
	return &cpu9PFile{File: nf}, qid, iounit, nil
}

func (f *cpu9PFile) Link(target p9.File, newName string) error {
	tf, ok := target.(*cpu9PFile)
	if !ok {
		return linux.EXDEV
	}
	return f.File.Link(tf.File, newName)
}

func (f *cpu9PFile) RenameAt(oldName string, newDir p9.File, newName string) error {
	nd, ok := newDir.(*cpu9PFile)
	if !ok {
		return linux.EXDEV
	}
	return f.File.RenameAt(oldName, nd.File, newName)
}

func (f *cpu9PFile) Renamed(parent p9.File, newName string) {
	if pf, ok := parent.(*cpu9PFile); ok {
		f.File.Renamed(pf.File, newName)
	}
}
