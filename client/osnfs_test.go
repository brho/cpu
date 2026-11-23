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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5"
)

func TestFilterFS(t *testing.T) {
	allow := []string{"/home", "/b/bin"}

	t.Run("stat_and_readdir", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		fs := NewFilterFS(COS{Filesystem: NewOSFS(rootDir)}, allow)

		for _, okPath := range []string{"/", "/b", "/b/bin", "/b/bin/ls", "/home", "/home/user/hello.txt"} {
			if _, err := fs.Stat(okPath); err != nil {
				t.Errorf("Stat(%q): %v", okPath, err)
			}
			if _, err := fs.Lstat(okPath); err != nil {
				t.Errorf("Lstat(%q): %v", okPath, err)
			}
		}
		for _, badPath := range []string{"/etc", "/etc/shadow", "/topsecret", "/b/other", "/b/other/secret"} {
			if _, err := fs.Stat(badPath); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Stat(%q) = %v, want os.ErrNotExist", badPath, err)
			}
			if _, err := fs.Lstat(badPath); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Lstat(%q) = %v, want os.ErrNotExist", badPath, err)
			}
		}

		rootEnts, err := fs.ReadDir("/")
		if err != nil {
			t.Fatalf("ReadDir(/): %v", err)
		}
		var names []string
		for _, e := range rootEnts {
			names = append(names, e.Name())
		}
		slices.Sort(names)
		if want := []string{"b", "home"}; !slices.Equal(names, want) {
			t.Errorf("ReadDir(/) = %v, want %v", names, want)
		}

		bEnts, err := fs.ReadDir("/b")
		if err != nil {
			t.Fatalf("ReadDir(/b): %v", err)
		}
		if len(bEnts) != 1 || bEnts[0].Name() != "bin" {
			t.Errorf("ReadDir(/b) = %v, want [bin]", bEnts)
		}
		if _, err := fs.ReadDir("/etc"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("ReadDir(/etc) = %v, want os.ErrNotExist", err)
		}
		if _, err := fs.Open("/etc/shadow"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Open(/etc/shadow) = %v, want os.ErrNotExist", err)
		}
		if _, err := fs.Open("/b"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Open(/b) = %v, want os.ErrPermission", err)
		}
	})

	t.Run("mutations_and_crud", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		fs := NewFilterFS(COS{Filesystem: NewOSFS(rootDir)}, allow)

		// Mutations on ancestors, disallowed paths, or mount roots
		// fail.
		if _, err := fs.Create("/evil"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Create(/evil) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.OpenFile("/evil", os.O_CREATE|os.O_RDWR, 0o644); !errors.Is(err, os.ErrPermission) {
			t.Errorf("OpenFile(/evil, O_CREATE) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.Create("/home"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Create(/home) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.OpenFile("/home", os.O_CREATE|os.O_RDWR, 0o644); !errors.Is(err, os.ErrPermission) {
			t.Errorf("OpenFile(/home, O_CREATE) = %v, want os.ErrPermission", err)
		}
		if err := fs.MkdirAll("/b/newdir", 0o755); !errors.Is(err, os.ErrPermission) {
			t.Errorf("MkdirAll(/b/newdir) = %v, want os.ErrPermission", err)
		}
		if err := fs.Remove("/home"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Remove(/home) = %v, want os.ErrPermission", err)
		}
		if err := fs.Rename("/home", "/home/moved"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Rename(/home, /home/moved) = %v, want os.ErrPermission", err)
		}
		if err := fs.Symlink("/home/user/hello.txt", "/b/link"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Symlink(/b/link) = %v, want os.ErrPermission", err)
		}
		chg := fs.(billy.Change)
		if err := chg.Chmod("/b", 0o777); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Chmod(/b) = %v, want os.ErrPermission", err)
		}
		if err := chg.Chtimes("/b", time.Now(), time.Now()); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Chtimes(/b) = %v, want os.ErrPermission", err)
		}

		// Operations inside exported "/home" succeed.
		f, err := fs.Open("/home/user/hello.txt")
		if err != nil {
			t.Fatalf("Open(/home/user/hello.txt): %v", err)
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil || string(data) != "hello world" {
			t.Fatalf("ReadAll = (%q, %v), want (\"hello world\", nil)", data, err)
		}

		nf, err := fs.Create("/home/user/new.txt")
		if err != nil {
			t.Fatalf("Create(/home/user/new.txt): %v", err)
		}
		if got := nf.Name(); got != "home/user/new.txt" {
			t.Errorf("Create().Name() = %q, want %q", got, "home/user/new.txt")
		}
		if _, err := fs.Lstat(nf.Name()); err != nil {
			t.Errorf("Lstat(Create().Name()): %v", err)
		}
		if _, err := nf.Write([]byte("nfs-test")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		nf.Close()

		if err := chg.Chmod("/home/user/new.txt", 0o600); err != nil {
			t.Fatalf("Chmod(/home/user/new.txt): %v", err)
		}
		if err := fs.Rename("/home/user/new.txt", "/home/user/renamed.txt"); err != nil {
			t.Fatalf("Rename: %v", err)
		}
		if err := fs.Remove("/home/user/renamed.txt"); err != nil {
			t.Fatalf("Remove: %v", err)
		}
	})

	t.Run("missing_mount_roots", func(t *testing.T) {
		// Missing mount roots and ancestors cannot be auto-created by
		// BoundOS.
		rootDir := setupFilterTestTree(t)
		missingFS := NewFilterFS(COS{Filesystem: NewOSFS(rootDir)}, []string{"/home", "/lib64", "/a/b/c"})
		if _, err := missingFS.Create("/lib64/evil.txt"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Create(/lib64/evil.txt) = %v, want os.ErrNotExist", err)
		}
		if _, err := missingFS.OpenFile("/lib64/evil.txt", os.O_CREATE|os.O_RDWR, 0o644); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("OpenFile(/lib64/evil.txt, O_CREATE) = %v, want os.ErrNotExist", err)
		}
		if err := missingFS.MkdirAll("/a/b/c/sub", 0o755); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("MkdirAll(/a/b/c/sub) = %v, want os.ErrNotExist", err)
		}
		if err := missingFS.Symlink("x", "/lib64/link"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Symlink(/lib64/link) = %v, want os.ErrNotExist", err)
		}
		if err := missingFS.Rename("/home/user/hello.txt", "/lib64/moved"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Rename to /lib64/moved = %v, want os.ErrNotExist", err)
		}
		if _, err := missingFS.TempFile("/lib64", "tmp"); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("TempFile(/lib64) = %v, want os.ErrNotExist", err)
		}
		for _, absent := range []string{"lib64", "a"} {
			if _, err := os.Stat(filepath.Join(rootDir, absent)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%q was created inside read-only ancestor /", absent)
			}
		}
	})

	t.Run("tempfile_confinement", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		fs := NewFilterFS(COS{Filesystem: NewOSFS(rootDir)}, allow)

		// Missing directory or NUL byte must not let BoundOS.abs fall
		// back to "" (host os.TempDir()).
		for _, badDir := range []string{
			"/home/missing",
			"/home/missing/a\x00b",
			"/home/user/hello.txt",
		} {
			if f, err := fs.TempFile(badDir, "pwn"); err == nil {
				_ = f.Close()
				t.Errorf("TempFile(%q) succeeded, want error", badDir)
			}
		}
		for _, badPrefix := range []string{"../pwn", "a\x00b"} {
			if f, err := fs.TempFile("/home", badPrefix); !errors.Is(err, os.ErrInvalid) {
				if f != nil {
					_ = f.Close()
				}
				t.Errorf("TempFile(/home, %q) = %v, want os.ErrInvalid", badPrefix, err)
			}
		}
		tf, err := fs.TempFile("/home", "ok-")
		if err != nil {
			t.Fatalf("TempFile(/home, ok-): %v", err)
		}
		name := tf.Name()
		_ = tf.Close()
		if err := fs.Remove(name); err != nil {
			t.Errorf("Remove(%q): %v", name, err)
		}

		// Direct NewOSFS TempFile/Create return root-relative names
		// that round-trip cleanly into Lstat and Remove.
		directOS := NewOSFS(rootDir)
		dtf, err := directOS.TempFile("home", "direct-")
		if err != nil {
			t.Fatalf("directOS.TempFile(home): %v", err)
		}
		dname := dtf.Name()
		_ = dtf.Close()
		if _, err := directOS.Lstat(dname); err != nil {
			t.Errorf("directOS.Lstat(%q): %v", dname, err)
		}
		if err := directOS.Remove(dname); err != nil {
			t.Errorf("directOS.Remove(%q): %v", dname, err)
		}
		if f, err := directOS.TempFile("home", "../bad"); !errors.Is(err, os.ErrInvalid) {
			if f != nil {
				_ = f.Close()
			}
			t.Errorf("directOS.TempFile(bad prefix) = %v, want os.ErrInvalid", err)
		}

		// Exceeding PATH_MAX via nested directories (created through
		// os.OpenRoot so the setup works on macOS/FreeBSD PATH_MAX=1024
		// as well as Linux PATH_MAX=4096) must fail closed rather than
		// falling back to host TempDir.
		if runtime.GOOS != "windows" {
			seg := strings.Repeat("a", 200)
			deepRel := "home/" + strings.Repeat(seg+"/", 22) + "leaf"
			r, err := os.OpenRoot(rootDir)
			if err != nil {
				t.Fatalf("os.OpenRoot: %v", err)
			}
			defer r.Close()
			if err := r.MkdirAll(deepRel, 0o755); err != nil {
				t.Fatalf("r.MkdirAll(deepRel): %v", err)
			}
			const sentinel = "cpu-test-deep-escape-"
			if f, err := fs.TempFile("/"+deepRel, sentinel); err == nil {
				_ = f.Close()
				t.Errorf("TempFile(deepRel) succeeded, want error")
			}
			matches, _ := filepath.Glob(filepath.Join(os.TempDir(), sentinel+"*"))
			for _, m := range matches {
				_ = os.Remove(m)
				t.Errorf("TempFile(deepRel) escaped into host TempDir: %q", m)
			}
		}
	})

	t.Run("dedup_prefix", func(t *testing.T) {
		// BoundOS path deduplication must not strip -root prefix to
		// bypass allow. Use osFS.Root() (without volume name on
		// Windows) so macOS /var -> /private/var and Windows drive
		// letters both exercise BoundOS.abs deduplication.
		dedupRoot := filepath.Join(t.TempDir(), "sub")
		if err := os.MkdirAll(filepath.Join(dedupRoot, "etc"), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dedupRoot, "etc/shadow"), []byte("secret"), 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		osFS := NewOSFS(dedupRoot)
		resolvedRoot := osFS.Root()
		dupPrefix := resolvedRoot[len(filepath.VolumeName(resolvedRoot)):]
		dedupFS := NewFilterFS(COS{Filesystem: osFS}, []string{dupPrefix})
		if f, err := dedupFS.Open(filepath.Join(dupPrefix, "etc/shadow")); err == nil {
			_ = f.Close()
			t.Errorf("Open via duplicated -root prefix succeeded, want error")
		}
	})

	t.Run("symlinks_and_cos", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlinks require Unix")
		}
		rootDir := setupFilterTestTree(t)
		baseFS := COS{Filesystem: NewOSFS(rootDir)}
		fs := NewFilterFS(baseFS, allow)
		chg := fs.(billy.Change)

		outsideDir := t.TempDir()
		outsideFile := filepath.Join(outsideDir, "outside.txt")
		if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
			t.Fatalf("WriteFile(outside): %v", err)
		}
		if err := fs.Symlink("../etc/shadow", "/home/esc"); err != nil {
			t.Fatalf("Symlink(esc): %v", err)
		}
		if err := fs.Symlink("..", "/home/up"); err != nil {
			t.Fatalf("Symlink(up): %v", err)
		}
		if err := fs.Symlink(outsideFile, "/home/abs"); err != nil {
			t.Fatalf("Symlink(abs): %v", err)
		}

		// Non-following operations on the symlink itself are permitted.
		if fi, err := fs.Lstat("/home/esc"); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("Lstat(/home/esc) = (%v, %v), want symlink", fi, err)
		}
		if target, err := fs.Readlink("/home/esc"); err != nil || target != "../etc/shadow" {
			t.Errorf("Readlink(/home/esc) = (%q, %v), want (../etc/shadow, nil)", target, err)
		}

		// Following a symlink leaf or traversing an intermediate
		// symlink fails.
		if _, err := fs.Open("/home/esc"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Open(/home/esc) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.OpenFile("/home/esc", os.O_RDONLY, 0); !errors.Is(err, os.ErrPermission) {
			t.Errorf("OpenFile(/home/esc) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.Stat("/home/esc"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Stat(/home/esc) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.Create("/home/esc"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Create(/home/esc) = %v, want os.ErrPermission", err)
		}
		if err := chg.Chmod("/home/esc", 0o777); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Chmod(/home/esc) = %v, want os.ErrPermission", err)
		}
		if err := chg.Chtimes("/home/esc", time.Now(), time.Now()); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Chtimes(/home/esc) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.ReadDir("/home/up"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("ReadDir(/home/up) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.Lstat("/home/up/etc/shadow"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Lstat(/home/up/etc/shadow) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.Open("/home/up/etc/shadow"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Open(/home/up/etc/shadow) = %v, want os.ErrPermission", err)
		}
		if err := fs.Remove("/home/up/etc/shadow"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Remove(/home/up/etc/shadow) = %v, want os.ErrPermission", err)
		}
		if err := fs.Rename("/home/up/etc/shadow", "/home/stolen"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Rename(/home/up/etc/shadow) = %v, want os.ErrPermission", err)
		}
		if err := fs.Symlink("x", "/home/up/etc/pwn"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Symlink(/home/up/etc/pwn) = %v, want os.ErrPermission", err)
		}
		if _, err := fs.TempFile("/home/up", "pwn"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("TempFile(/home/up) = %v, want os.ErrPermission", err)
		}

		// COS directly (e.g. under -unsafe-export) confines
		// Chmod/Chtimes to -root.
		if err := baseFS.Chmod("/home/abs", 0o777); err == nil {
			t.Errorf("COS.Chmod(/home/abs) succeeded, want error")
		}
		fi, err := os.Stat(outsideFile)
		if err != nil {
			t.Fatalf("os.Stat(%q): %v", outsideFile, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("outsideFile mode = %o, want 0600", fi.Mode().Perm())
		}

		// BoundOS resolves leaf symlinks in Remove/Rename/Symlink via
		// securejoin, so filterFS rejects them to protect targets.
		if err := fs.Remove("/home/esc"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Remove(/home/esc) = %v, want os.ErrPermission", err)
		}
		if err := fs.Rename("/home/esc", "/home/stolen"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Rename(/home/esc, /home/stolen) = %v, want os.ErrPermission", err)
		}
		if err := fs.Symlink("x", "/home/esc"); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Symlink onto existing symlink /home/esc = %v, want os.ErrPermission", err)
		}
		if got, err := os.ReadFile(filepath.Join(rootDir, "etc/shadow")); err != nil || string(got) != "root-secret" {
			t.Fatalf("etc/shadow modified or deleted: (%q, %v)", got, err)
		}
	})
}

func TestNewNFSFS(t *testing.T) {
	rootDir := setupFilterTestTree(t)

	// Empty -root fails closed across NewOSFS, NewFilterFS, and newNFSFS.
	if _, err := newNFSFS("", "", "/home", false); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("newNFSFS(empty dir) = %v, want os.ErrInvalid", err)
	}
	emptyOS := NewOSFS("")
	if _, err := emptyOS.Lstat("."); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("NewOSFS(\"\").Lstat(.) = %v, want os.ErrInvalid", err)
	}
	if f, err := emptyOS.Open("etc/hosts"); !errors.Is(err, os.ErrInvalid) {
		if f != nil {
			_ = f.Close()
		}
		t.Errorf("NewOSFS(\"\").Open(etc/hosts) = %v, want os.ErrInvalid", err)
	}
	if _, err := emptyOS.Stat("etc/hosts"); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("NewOSFS(\"\").Stat(etc/hosts) = %v, want os.ErrInvalid", err)
	}
	if _, err := emptyOS.ReadDir("."); !errors.Is(err, os.ErrInvalid) {
		t.Errorf("NewOSFS(\"\").ReadDir(.) = %v, want os.ErrInvalid", err)
	}
	emptyFiltered := NewFilterFS(COS{Filesystem: emptyOS}, []string{"/"})
	if f, err := emptyFiltered.Open("/etc/hosts"); !errors.Is(err, os.ErrInvalid) {
		if f != nil {
			_ = f.Close()
		}
		t.Errorf("NewFilterFS(NewOSFS(\"\")).Open(/etc/hosts) = %v, want os.ErrInvalid", err)
	}

	// Missing -root fails closed and is never auto-created on the host.
	missingRoot := filepath.Join(t.TempDir(), "doesnotexist")
	if _, err := newNFSFS("", missingRoot, "/", false); err == nil {
		t.Errorf("newNFSFS(missingRoot) succeeded, want error")
	}
	missingFiltered := NewFilterFS(COS{Filesystem: NewOSFS(missingRoot)}, []string{"/"})
	if f, err := missingFiltered.Create("/pwn.txt"); err == nil {
		_ = f.Close()
		t.Errorf("Create on missing -root succeeded, want error")
	}
	if _, err := os.Stat(missingRoot); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing -root %q was created on host", missingRoot)
	}

	// Invalid -namespace fails before constructing the export.
	if _, err := newNFSFS("", rootDir, "/lib=:/bin", false); !errors.Is(err, strconv.ErrSyntax) {
		t.Errorf("newNFSFS(invalid namespace) = %v, want strconv.ErrSyntax", err)
	}

	// Safe default restricts exports to -namespace while preserving Root().
	safeFS, err := newNFSFS("", rootDir, "/home:/bin=/b/bin", false)
	if err != nil {
		t.Fatalf("newNFSFS(safe): %v", err)
	}
	if _, err := safeFS.Stat("home/user/hello.txt"); err != nil {
		t.Errorf("safeFS.Stat(home/user/hello.txt): %v", err)
	}
	if _, err := safeFS.Stat("etc/shadow"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("safeFS.Stat(etc/shadow) = %v, want os.ErrNotExist", err)
	}
	if want := NewOSFS(rootDir).Root(); safeFS.Root() != want {
		t.Errorf("safeFS.Root() = %q, want %q", safeFS.Root(), want)
	}

	// UnsafeExport bypasses filtering and exposes the entire -root tree,
	// while Create().Name() still round-trips cleanly into Lstat (used by
	// go-nfs post-op attributes on NFSv3 CREATE).
	unsafeFS, err := newNFSFS("", rootDir, "/home", true)
	if err != nil {
		t.Fatalf("newNFSFS(unsafe): %v", err)
	}
	if _, err := unsafeFS.Stat("etc/shadow"); err != nil {
		t.Errorf("unsafeFS.Stat(etc/shadow): %v", err)
	}
	uf, err := unsafeFS.Create("home/user/unsafe_new.txt")
	if err != nil {
		t.Fatalf("unsafeFS.Create: %v", err)
	}
	uname := uf.Name()
	_ = uf.Close()
	if _, err := unsafeFS.Lstat(uname); err != nil {
		t.Errorf("unsafeFS.Lstat(%q): %v", uname, err)
	}
	if err := unsafeFS.Remove(uname); err != nil {
		t.Errorf("unsafeFS.Remove(%q): %v", uname, err)
	}

	// Relative dir (".") works alongside volume-qualified paths.
	t.Chdir(rootDir)
	relFS, err := newNFSFS("", ".", "/home", false)
	if err != nil {
		t.Fatalf("newNFSFS(relative): %v", err)
	}
	if _, err := relFS.Stat("home/user/hello.txt"); err != nil {
		t.Errorf("relFS.Stat(home/user/hello.txt): %v", err)
	}
}

type fakeSpecialFileInfo struct {
	name string
	mode os.FileMode
}

func (f fakeSpecialFileInfo) Name() string       { return f.name }
func (f fakeSpecialFileInfo) Size() int64        { return 0 }
func (f fakeSpecialFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeSpecialFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeSpecialFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeSpecialFileInfo) Sys() any           { return nil }

type specialFileFS struct {
	billy.Filesystem
	special map[string]os.FileMode
	opened  bool
}

func (s *specialFileFS) Lstat(filename string) (os.FileInfo, error) {
	if mode, ok := s.special[filename]; ok {
		return fakeSpecialFileInfo{name: filepath.Base(filename), mode: mode}, nil
	}
	return s.Filesystem.Lstat(filename)
}

func (s *specialFileFS) Open(filename string) (billy.File, error) {
	s.opened = true
	return s.Filesystem.Open(filename)
}

func (s *specialFileFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	s.opened = true
	return s.Filesystem.OpenFile(filename, flag, perm)
}

func (s *specialFileFS) Create(filename string) (billy.File, error) {
	s.opened = true
	return s.Filesystem.Create(filename)
}

func TestFilterFSRejectsSpecialFiles(t *testing.T) {
	rootDir := setupFilterTestTree(t)
	backing := &specialFileFS{
		Filesystem: COS{Filesystem: NewOSFS(rootDir)},
		special: map[string]os.FileMode{
			"home/myfifo": os.ModeNamedPipe | 0o644,
			"home/mydev":  os.ModeDevice | os.ModeCharDevice | 0o600,
			// Windows NTFS directory junctions report ModeIrregular
			// with ModeSymlink == 0 and IsDir() == false.
			"home/junc": os.ModeIrregular,
		},
	}
	fs := NewFilterFS(backing, []string{"/home"})

	for _, p := range []string{"/home/myfifo", "/home/mydev", "/home/junc"} {
		if _, err := fs.Open(p); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Open(%q) = %v, want os.ErrPermission", p, err)
		}
		if _, err := fs.OpenFile(p, os.O_RDWR|os.O_CREATE, 0o644); !errors.Is(err, os.ErrPermission) {
			t.Errorf("OpenFile(%q) = %v, want os.ErrPermission", p, err)
		}
		if _, err := fs.Create(p); !errors.Is(err, os.ErrPermission) {
			t.Errorf("Create(%q) = %v, want os.ErrPermission", p, err)
		}
	}
	if _, err := fs.Stat("/home/junc"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Stat(/home/junc) = %v, want os.ErrPermission", err)
	}
	if _, err := fs.ReadDir("/home/junc"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("ReadDir(/home/junc) = %v, want os.ErrPermission", err)
	}
	if _, err := fs.Open("/home/junc/secret"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Open(/home/junc/secret) = %v, want os.ErrPermission", err)
	}
	if _, err := fs.Create("/home/junc/pwn"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Create(/home/junc/pwn) = %v, want os.ErrPermission", err)
	}
	if _, err := fs.Lstat("/home/junc/secret"); !errors.Is(err, os.ErrPermission) {
		t.Errorf("Lstat(/home/junc/secret) = %v, want os.ErrPermission", err)
	}
	if backing.opened {
		t.Errorf("backing Open/OpenFile/Create called on special/irregular file")
	}
}
