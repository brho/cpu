// Copyright 2026 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/hugelgupf/p9/fsimpl/templatefs"
	"github.com/hugelgupf/p9/linux"
	"github.com/hugelgupf/p9/p9"
)

func setupFilterTestTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dirs := []string{
		"home/user",
		"b/bin",
		"b/other",
		"etc",
	}
	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", d, err)
		}
	}
	files := map[string]string{
		"home/user/hello.txt": "hello world",
		"b/bin/ls":            "binary-ls",
		"b/other/secret":      "other-secret",
		"etc/shadow":          "root-secret",
		"topsecret":           "top-secret",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%q): %v", rel, err)
		}
	}
	return root
}

func attachFilter9P(t *testing.T, allow []string) (string, p9.File) {
	t.Helper()
	preserveUmask(t)
	rootDir := setupFilterTestTree(t)
	root, err := NewFilter9P(NewCPU9P(rootDir), allow).Attach()
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() {
		_ = root.Close()
	})
	return rootDir, root
}

func TestFilter9PEmptyAllow(t *testing.T) {
	_, root := attachFilter9P(t, nil)

	// Empty Walk clones the root ancestor fid.
	_, rootCopy, err := root.Walk(nil)
	if err != nil {
		t.Fatalf("Walk(nil): %v", err)
	}
	defer rootCopy.Close()

	// Walking ".." at "/" stays at "/".
	_, dotdotRoot, err := root.Walk([]string{".."})
	if err != nil {
		t.Fatalf("Walk([\"..\"]): %v", err)
	}
	defer dotdotRoot.Close()

	// Walking to any child fails when nothing is exported.
	for _, name := range []string{"home", "etc", "topsecret"} {
		if _, _, err := root.Walk([]string{name}); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Walk([%q]) = %v, want os.ErrNotExist", name, err)
		}
	}

	// Root can be opened read-only and Readdir returns no entries.
	if _, _, err := root.Open(p9.ReadOnly); err != nil {
		t.Fatalf("root.Open(ReadOnly): %v", err)
	}
	dirents, err := root.Readdir(0, 64)
	if err != nil {
		t.Fatalf("root.Readdir: %v", err)
	}
	if len(dirents) != 0 {
		t.Errorf("root.Readdir with empty allow list returned %v, want empty", dirents)
	}
}

func TestFilter9P(t *testing.T) {
	allow := []string{"/home", "/b/bin"}

	t.Run("walk_and_readdir", func(t *testing.T) {
		_, root := attachFilter9P(t, allow)

		// Disallowed paths return os.ErrNotExist on Walk.
		for _, names := range [][]string{
			{"etc"},
			{"etc", "shadow"},
			{"topsecret"},
			{"b", "other"},
			{"b", "other", "secret"},
			{"home", "..", "etc"},
			{"..", "etc"},
		} {
			if _, _, err := root.Walk(names); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Walk(%v) = %v, want os.ErrNotExist", names, err)
			}
		}

		// Walking ".." from "/" or from "/home" lands on "/" as an
		// ancestor (not exported).
		for _, names := range [][]string{{".."}, {"home", ".."}} {
			_, anc, err := root.Walk(names)
			if err != nil {
				t.Fatalf("Walk(%v): %v", names, err)
			}
			if _, err := anc.Mkdir("escaped", 0o755, p9.NoUID, p9.NoGID); !errors.Is(err, os.ErrPermission) {
				t.Errorf("Walk(%v).Mkdir = %v, want os.ErrPermission", names, err)
			}
			_ = anc.Close()
		}

		// Readdir on "/" only exposes "b" and "home" (paginated).
		_, rootReader, err := root.Walk(nil)
		if err != nil {
			t.Fatalf("Walk(nil): %v", err)
		}
		defer rootReader.Close()
		if _, _, err := rootReader.Open(p9.ReadOnly); err != nil {
			t.Fatalf("rootReader.Open(ReadOnly): %v", err)
		}
		var rootNames []string
		var offset uint64
		for {
			ents, err := rootReader.Readdir(offset, 1)
			if err != nil {
				t.Fatalf("rootReader.Readdir(%d, 1): %v", offset, err)
			}
			if len(ents) == 0 {
				break
			}
			for _, e := range ents {
				rootNames = append(rootNames, e.Name)
				offset = e.Offset
			}
		}
		slices.Sort(rootNames)
		if want := []string{"b", "home"}; !slices.Equal(rootNames, want) {
			t.Errorf("paginated Readdir(/) = %v, want %v", rootNames, want)
		}

		// Readdir on ancestor "/b" only exposes "bin", hiding "other".
		_, bDir, err := root.Walk([]string{"b"})
		if err != nil {
			t.Fatalf("Walk([\"b\"]): %v", err)
		}
		defer bDir.Close()
		if _, _, err := bDir.Open(p9.ReadOnly); err != nil {
			t.Fatalf("bDir.Open(ReadOnly): %v", err)
		}
		bEnts, err := bDir.Readdir(0, 64)
		if err != nil {
			t.Fatalf("bDir.Readdir: %v", err)
		}
		if len(bEnts) != 1 || bEnts[0].Name != "bin" {
			t.Errorf("bDir.Readdir = %v, want [bin]", bEnts)
		}
	})

	t.Run("ancestor_readonly", func(t *testing.T) {
		_, root := attachFilter9P(t, allow)
		_, bDir, err := root.Walk([]string{"b"})
		if err != nil {
			t.Fatalf("Walk([\"b\"]): %v", err)
		}
		defer bDir.Close()

		if _, _, err := bDir.Open(p9.ReadWrite); !errors.Is(err, os.ErrPermission) {
			t.Errorf("bDir.Open(ReadWrite) = %v, want os.ErrPermission", err)
		}
		if _, _, _, err := bDir.Create("evil", p9.ReadWrite, 0o644, p9.NoUID, p9.NoGID); !errors.Is(err, os.ErrPermission) {
			t.Errorf("bDir.Create = %v, want os.ErrPermission", err)
		}
		if _, err := bDir.Mkdir("evil", 0o755, p9.NoUID, p9.NoGID); !errors.Is(err, os.ErrPermission) {
			t.Errorf("bDir.Mkdir = %v, want os.ErrPermission", err)
		}
		if _, err := bDir.Symlink("target", "link", p9.NoUID, p9.NoGID); !errors.Is(err, os.ErrPermission) {
			t.Errorf("bDir.Symlink = %v, want os.ErrPermission", err)
		}
		if err := bDir.SetAttr(p9.SetAttrMask{Permissions: true}, p9.SetAttr{Permissions: 0o777}); !errors.Is(err, os.ErrPermission) {
			t.Errorf("bDir.SetAttr = %v, want os.ErrPermission", err)
		}
		if err := bDir.SetXattr("user.test", []byte("x"), 0); !errors.Is(err, os.ErrPermission) {
			t.Errorf("bDir.SetXattr = %v, want os.ErrPermission", err)
		}
		if err := bDir.RemoveXattr("user.test"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("bDir.RemoveXattr = %v, want os.ErrPermission", err)
		}
		// Unlinking an exported mount root from its non-exported parent
		// must fail.
		if err := bDir.UnlinkAt("bin", 0); !errors.Is(err, os.ErrPermission) {
			t.Errorf("bDir.UnlinkAt(\"bin\") = %v, want os.ErrPermission", err)
		}
		if err := root.UnlinkAt("home", 0); !errors.Is(err, os.ErrPermission) {
			t.Errorf("root.UnlinkAt(\"home\") = %v, want os.ErrPermission", err)
		}
	})

	t.Run("ancestor_nondir", func(t *testing.T) {
		// Non-directory files at a pathAncestor path cannot be opened
		// or read.
		_, ancRoot := attachFilter9P(t, []string{"/etc/shadow/sub"})
		_, shadowAnc, err := ancRoot.Walk([]string{"etc", "shadow"})
		if err != nil {
			t.Fatalf("Walk([etc shadow]): %v", err)
		}
		defer shadowAnc.Close()
		if _, _, err := shadowAnc.Open(p9.ReadOnly); !errors.Is(err, linux.ENOTDIR) {
			t.Errorf("shadowAnc.Open(ReadOnly) = %v, want linux.ENOTDIR", err)
		}
		if _, err := shadowAnc.GetXattr("user.test"); !errors.Is(err, linux.ENOTDIR) {
			t.Errorf("shadowAnc.GetXattr = %v, want linux.ENOTDIR", err)
		}
		if _, err := shadowAnc.ListXattrs(); !errors.Is(err, linux.ENOTDIR) {
			t.Errorf("shadowAnc.ListXattrs = %v, want linux.ENOTDIR", err)
		}
	})

	t.Run("symlinks", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks require Unix")
		}
		rootDir, root := attachFilter9P(t, allow)
		_, homeDir, err := root.Walk([]string{"home"})
		if err != nil {
			t.Fatalf("Walk([\"home\"]): %v", err)
		}
		defer homeDir.Close()

		// Symlinks inside exported subtrees cannot escape via Walk,
		// Open, SetAttr, Link, Readdir, or *Xattr.
		if _, err := homeDir.Symlink("../etc", "sym_etc", p9.NoUID, p9.NoGID); err != nil {
			t.Fatalf("homeDir.Symlink(sym_etc): %v", err)
		}
		if _, err := homeDir.Symlink("../etc/shadow", "sym_shadow", p9.NoUID, p9.NoGID); err != nil {
			t.Fatalf("homeDir.Symlink(sym_shadow): %v", err)
		}
		if _, f, err := homeDir.Walk([]string{"sym_etc", "shadow"}); err == nil {
			_ = f.Close()
			t.Errorf("homeDir.Walk through symlink succeeded, want error")
		}
		_, symEtc, err := homeDir.Walk([]string{"sym_etc"})
		if err != nil {
			t.Fatalf("homeDir.Walk([sym_etc]): %v", err)
		}
		defer symEtc.Close()
		if _, f, err := symEtc.Walk([]string{"shadow"}); err == nil {
			_ = f.Close()
			t.Errorf("symEtc.Walk([shadow]) succeeded, want error")
		}
		if _, err := symEtc.Readdir(0, 64); err == nil {
			t.Errorf("symEtc.Readdir succeeded, want error")
		}
		if _, err := symEtc.Mkdir("escaped", 0o755, p9.NoUID, p9.NoGID); err == nil {
			t.Errorf("symEtc.Mkdir succeeded, want error")
		}

		_, symShadow, err := homeDir.Walk([]string{"sym_shadow"})
		if err != nil {
			t.Fatalf("homeDir.Walk([sym_shadow]): %v", err)
		}
		defer symShadow.Close()
		if _, _, err := symShadow.Open(p9.ReadOnly); !errors.Is(err, os.ErrPermission) {
			t.Errorf("symShadow.Open = %v, want os.ErrPermission", err)
		}
		if err := symShadow.SetAttr(p9.SetAttrMask{Size: true}, p9.SetAttr{Size: 0}); !errors.Is(err, os.ErrPermission) {
			t.Errorf("symShadow.SetAttr(Size) = %v, want os.ErrPermission", err)
		}
		if err := homeDir.Link(symShadow, "hardlink_shadow"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("homeDir.Link(symShadow) = %v, want os.ErrPermission", err)
		}
		if _, err := symShadow.GetXattr("user.test"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("symShadow.GetXattr = %v, want os.ErrPermission", err)
		}
		if _, err := symShadow.ListXattrs(); !errors.Is(err, os.ErrPermission) {
			t.Errorf("symShadow.ListXattrs = %v, want os.ErrPermission", err)
		}
		if err := symShadow.SetXattr("user.test", []byte("x"), 0); !errors.Is(err, os.ErrPermission) {
			t.Errorf("symShadow.SetXattr = %v, want os.ErrPermission", err)
		}
		if err := symShadow.RemoveXattr("user.test"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("symShadow.RemoveXattr = %v, want os.ErrPermission", err)
		}
		if got, err := os.ReadFile(filepath.Join(rootDir, "etc/shadow")); err != nil || string(got) != "root-secret" {
			t.Fatalf("etc/shadow modified: (%q, %v)", got, err)
		}
	})

	t.Run("exported_crud", func(t *testing.T) {
		_, root := attachFilter9P(t, allow)
		_, homeDir, err := root.Walk([]string{"home"})
		if err != nil {
			t.Fatalf("Walk([\"home\"]): %v", err)
		}
		defer homeDir.Close()

		// Rename returns linux.ENOSYS (p9.Server uses RenameAt).
		if err := homeDir.Rename(root, "moved"); !errors.Is(err, linux.ENOSYS) {
			t.Errorf("homeDir.Rename = %v, want linux.ENOSYS", err)
		}
		// Backslash path separators are rejected in Walk and mutators.
		if _, _, err := root.Walk([]string{`..\..\etc`}); !errors.Is(err, os.ErrInvalid) {
			t.Errorf("Walk backslash = %v, want os.ErrInvalid", err)
		}
		if _, _, _, err := homeDir.Create(`..\etc\evil`, p9.ReadWrite, 0o644, p9.NoUID, p9.NoGID); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Create backslash = %v, want os.ErrPermission", err)
		}

		// Create, write, read, rename, and unlink inside "/home".
		nf, _, _, err := homeDir.Create("created.txt", p9.ReadWrite, 0o644, p9.NoUID, p9.NoGID)
		if err != nil {
			t.Fatalf("homeDir.Create: %v", err)
		}
		if _, err := nf.WriteAt([]byte("payload"), 0); err != nil {
			_ = nf.Close()
			t.Fatalf("nf.WriteAt: %v", err)
		}
		buf := make([]byte, 7)
		if n, err := nf.ReadAt(buf, 0); err != nil || n != 7 || string(buf) != "payload" {
			_ = nf.Close()
			t.Fatalf("nf.ReadAt = (%d, %q, %v), want (7, \"payload\", nil)", n, buf, err)
		}
		// Close before RenameAt/UnlinkAt so Windows does not fail with
		// ERROR_SHARING_VIOLATION.
		if err := nf.Close(); err != nil {
			t.Fatalf("nf.Close: %v", err)
		}
		if err := homeDir.RenameAt("created.txt", homeDir, "renamed.txt"); err != nil {
			t.Fatalf("homeDir.RenameAt: %v", err)
		}
		if err := homeDir.RenameAt("renamed.txt", root, "escaped.txt"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("RenameAt to ancestor root = %v, want os.ErrPermission", err)
		}
		if err := homeDir.UnlinkAt("renamed.txt", 0); err != nil {
			t.Fatalf("homeDir.UnlinkAt: %v", err)
		}
	})
}

type eofReaddirFile struct {
	templatefs.NoopFile
	ents     p9.Dirents
	maxChunk uint64
}

func (f *eofReaddirFile) Walk(names []string) ([]p9.QID, p9.File, error) {
	if len(names) == 0 {
		return nil, f, nil
	}
	return nil, nil, os.ErrNotExist
}

func (f *eofReaddirFile) GetAttr(req p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	return p9.QID{Type: p9.TypeDir}, req, p9.Attr{Mode: p9.ModeDirectory | 0o755}, nil
}

func (f *eofReaddirFile) Readdir(offset uint64, count uint32) (p9.Dirents, error) {
	if offset >= uint64(len(f.ents)) {
		return nil, io.EOF
	}
	limit := uint64(count)
	if f.maxChunk > 0 && limit > f.maxChunk {
		limit = f.maxChunk
	}
	end := min(offset+limit, uint64(len(f.ents)))
	if end == uint64(len(f.ents)) {
		return f.ents[offset:end], io.EOF
	}
	return f.ents[offset:end], nil
}

type funcAttacher func() (p9.File, error)

func (fn funcAttacher) Attach() (p9.File, error) { return fn() }

func TestFilter9PReaddirEOF(t *testing.T) {
	backing := &eofReaddirFile{
		ents: p9.Dirents{
			{Name: "etc", Offset: 1},
			{Name: "tmp", Offset: 2},
			{Name: "b", Offset: 3},
			{Name: "home", Offset: 4},
		},
		// Chunk size of 2 means the first chunk has only disallowed
		// entries, verifying Readdir loops instead of returning EOF.
		maxChunk: 2,
	}
	f, err := NewFilter9P(funcAttacher(func() (p9.File, error) { return backing, nil }), []string{"/home", "/b/bin"}).Attach()
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer f.Close()

	// Paginated read with count=1 returns the first allowed entry without
	// io.EOF so the caller keeps reading.
	got1, err := f.Readdir(0, 1)
	if err != nil {
		t.Fatalf("Readdir(0, 1) err = %v, want nil", err)
	}
	if len(got1) != 1 || got1[0].Name != "b" {
		t.Fatalf("Readdir(0, 1) = %v, want [b]", got1)
	}

	// Next page returns the remaining allowed entry along with io.EOF.
	got2, err := f.Readdir(got1[0].Offset, 10)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Readdir(%d, 10) err = %v, want io.EOF", got1[0].Offset, err)
	}
	if len(got2) != 1 || got2[0].Name != "home" {
		t.Fatalf("Readdir(%d, 10) = %v, want [home]", got1[0].Offset, got2)
	}
}

type fakeModeFile struct {
	templatefs.NoopFile
	children map[string]*fakeModeFile
	mode     p9.FileMode
	opened   bool
}

func (f *fakeModeFile) Walk(names []string) ([]p9.QID, p9.File, error) {
	if len(names) == 0 {
		return nil, f, nil
	}
	var qids []p9.QID
	cur := f
	for _, name := range names {
		next, ok := cur.children[name]
		if !ok {
			return nil, nil, os.ErrNotExist
		}
		qids = append(qids, p9.QID{Type: next.mode.QIDType()})
		cur = next
	}
	return qids, cur, nil
}

func (f *fakeModeFile) GetAttr(req p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	return p9.QID{Type: f.mode.QIDType()}, req, p9.Attr{Mode: f.mode}, nil
}

func (f *fakeModeFile) Open(_ p9.OpenFlags) (p9.QID, uint32, error) {
	f.opened = true
	return p9.QID{Type: f.mode.QIDType()}, 4096, nil
}

func TestFilter9PRejectsSpecialFiles(t *testing.T) {
	fifo := &fakeModeFile{mode: p9.ModeNamedPipe | 0o644}
	// Block devices map to p9.TypeRegular in QIDType(), verifying
	// checkRegularOrDir inspects FileMode rather than QID.Type alone.
	blk := &fakeModeFile{mode: p9.ModeBlockDevice | 0o600}
	chr := &fakeModeFile{mode: p9.ModeCharacterDevice | 0o600}
	sock := &fakeModeFile{mode: p9.ModeSocket | 0o600}
	reg := &fakeModeFile{mode: p9.ModeRegular | 0o644}
	tree := &fakeModeFile{
		mode: p9.ModeDirectory | 0o755,
		children: map[string]*fakeModeFile{
			"home": {
				mode: p9.ModeDirectory | 0o755,
				children: map[string]*fakeModeFile{
					"fifo": fifo,
					"blk":  blk,
					"chr":  chr,
					"sock": sock,
					"reg":  reg,
				},
			},
		},
	}

	root, err := NewFilter9P(funcAttacher(func() (p9.File, error) { return tree, nil }), []string{"/home"}).Attach()
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	defer root.Close()

	for name, target := range map[string]*fakeModeFile{
		"fifo": fifo,
		"blk":  blk,
		"chr":  chr,
		"sock": sock,
	} {
		_, f, err := root.Walk([]string{"home", name})
		if err != nil {
			t.Fatalf("Walk([home %s]): %v", name, err)
		}
		if _, _, err := f.Open(p9.ReadOnly); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Open(/home/%s) = %v, want os.ErrPermission", name, err)
		}
		if target.opened {
			t.Errorf("backing Open called on special file %q", name)
		}
		_ = f.Close()
	}

	_, rf, err := root.Walk([]string{"home", "reg"})
	if err != nil {
		t.Fatalf("Walk([home reg]): %v", err)
	}
	defer rf.Close()
	if _, _, err := rf.Open(p9.ReadOnly); err != nil {
		t.Errorf("Open(/home/reg): %v", err)
	}
}
