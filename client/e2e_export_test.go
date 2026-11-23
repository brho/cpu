// Copyright 2026 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package client

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/google/uuid"
	"github.com/hugelgupf/p9/linux"
	"github.com/hugelgupf/p9/p9"
	nfs "github.com/willscott/go-nfs"
	nfsc "github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"
	nfshelper "github.com/willscott/go-nfs/helpers"
	"golang.org/x/sys/unix"
)

func startP9WirePair(t *testing.T, attacher p9.Attacher) p9.File {
	t.Helper()
	preserveUmask(t)
	serverConn, clientConn := net.Pipe()
	srv := p9.NewServer(attacher)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Handle(serverConn, serverConn)
	}()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
		<-done
	})
	cl, err := p9.NewClient(clientConn)
	if err != nil {
		t.Fatalf("p9.NewClient: %v", err)
	}
	root, err := cl.Attach("")
	if err != nil {
		t.Fatalf("cl.Attach: %v", err)
	}
	t.Cleanup(func() {
		_ = root.Close()
	})
	return root
}

func readAllP9Dir(t *testing.T, root p9.File, path []string) []string {
	t.Helper()
	_, dir, err := root.Walk(path)
	if err != nil {
		t.Fatalf("Walk(%v): %v", path, err)
	}
	defer dir.Close()
	if _, _, err := dir.Open(p9.ReadOnly); err != nil {
		t.Fatalf("Open(%v, ReadOnly): %v", path, err)
	}
	var names []string
	var offset uint64
	for {
		ents, err := dir.Readdir(offset, 64)
		if err != nil {
			t.Fatalf("Readdir(%v, %d): %v", path, offset, err)
		}
		if len(ents) == 0 {
			break
		}
		for _, e := range ents {
			names = append(names, e.Name)
			offset = e.Offset
		}
	}
	slices.Sort(names)
	return names
}

func readP9File(t *testing.T, root p9.File, path []string) string {
	t.Helper()
	_, f, err := root.Walk(path)
	if err != nil {
		t.Fatalf("Walk(%v): %v", path, err)
	}
	defer f.Close()
	if _, _, err := f.Open(p9.ReadOnly); err != nil {
		t.Fatalf("Open(%v): %v", path, err)
	}
	buf := make([]byte, 4096)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ReadAt(%v): %v", path, err)
	}
	return string(buf[:n])
}

func TestEndToEnd9PExport(t *testing.T) {
	remotes, err := ParseBindRemotes("/home:/bin=/b/bin")
	if err != nil {
		t.Fatalf("ParseBindRemotes: %v", err)
	}

	t.Run("namespace_filtering", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		root := startP9WirePair(t, NewFilter9P(NewCPU9P(rootDir), remotes))

		// Allowed files in /home and /b/bin are readable over 9P.
		if got := readP9File(t, root, []string{"home", "user", "hello.txt"}); got != "hello world" {
			t.Errorf("read /home/user/hello.txt = %q, want %q", got, "hello world")
		}
		if got := readP9File(t, root, []string{"b", "bin", "ls"}); got != "binary-ls" {
			t.Errorf("read /b/bin/ls = %q, want %q", got, "binary-ls")
		}

		// Readdir on ancestor "/" and "/b" exposes only allowed
		// children.
		if got, want := readAllP9Dir(t, root, nil), []string{"b", "home"}; !slices.Equal(got, want) {
			t.Errorf("Readdir(/) = %v, want %v", got, want)
		}
		if got, want := readAllP9Dir(t, root, []string{"b"}), []string{"bin"}; !slices.Equal(got, want) {
			t.Errorf("Readdir(/b) = %v, want %v", got, want)
		}

		// Disallowed paths cannot be walked to over the 9P wire.
		for _, bad := range [][]string{
			{"etc"},
			{"etc", "shadow"},
			{"topsecret"},
			{"b", "other"},
			{"b", "other", "secret"},
		} {
			if _, f, err := root.Walk(bad); err == nil {
				_ = f.Close()
				t.Errorf("Walk(%v) succeeded over 9P wire, want error", bad)
			}
		}

		// Mutations on ancestor directories are rejected with EACCES.
		_, bDir, err := root.Walk([]string{"b"})
		if err != nil {
			t.Fatalf("Walk([b]): %v", err)
		}
		defer bDir.Close()
		if _, _, _, err := bDir.Create("evil", p9.ReadWrite, 0o644, p9.NoUID, p9.NoGID); !errors.Is(err, linux.EACCES) {
			t.Errorf("bDir.Create = %v, want EACCES", err)
		}
		if _, err := bDir.Mkdir("evil", 0o755, p9.NoUID, p9.NoGID); !errors.Is(err, linux.EACCES) {
			t.Errorf("bDir.Mkdir = %v, want EACCES", err)
		}
		if err := bDir.UnlinkAt("bin", 0); !errors.Is(err, linux.EACCES) {
			t.Errorf("bDir.UnlinkAt(bin) = %v, want EACCES", err)
		}
		if err := root.UnlinkAt("home", 0); !errors.Is(err, linux.EACCES) {
			t.Errorf("root.UnlinkAt(home) = %v, want EACCES", err)
		}

		// Creating and writing inside exported "/home" succeeds.
		// clientFile.Create mutates homeDir in place; defer closes nf.
		_, homeDir, err := root.Walk([]string{"home"})
		if err != nil {
			t.Fatalf("Walk([home]): %v", err)
		}
		defer homeDir.Close()
		nf, _, _, err := homeDir.Create("wire.txt", p9.ReadWrite, 0o644, p9.NoUID, p9.NoGID)
		if err != nil {
			t.Fatalf("Create(wire.txt): %v", err)
		}
		if _, err := nf.WriteAt([]byte("wire-data"), 0); err != nil {
			t.Fatalf("WriteAt: %v", err)
		}
		if got := readP9File(t, root, []string{"home", "wire.txt"}); got != "wire-data" {
			t.Errorf("read /home/wire.txt = %q, want %q", got, "wire-data")
		}
	})

	t.Run("symlink_escape", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		root := startP9WirePair(t, NewFilter9P(NewCPU9P(rootDir), remotes))
		_, homeDir, err := root.Walk([]string{"home"})
		if err != nil {
			t.Fatalf("Walk([home]): %v", err)
		}
		defer homeDir.Close()

		if _, err := homeDir.Symlink("../etc", "sym_etc", p9.NoUID, p9.NoGID); err != nil {
			t.Fatalf("homeDir.Symlink: %v", err)
		}
		if _, f, err := homeDir.Walk([]string{"sym_etc", "shadow"}); err == nil {
			_ = f.Close()
			t.Errorf("Walk through symlink sym_etc/shadow succeeded over 9P wire, want error")
		}
		if _, err := homeDir.Symlink("../etc/shadow", "sym_shadow", p9.NoUID, p9.NoGID); err != nil {
			t.Fatalf("homeDir.Symlink(sym_shadow): %v", err)
		}
		_, symShadow, err := homeDir.Walk([]string{"sym_shadow"})
		if err != nil {
			t.Fatalf("homeDir.Walk([sym_shadow]): %v", err)
		}
		defer symShadow.Close()
		if err := symShadow.SetAttr(p9.SetAttrMask{Size: true}, p9.SetAttr{Size: 0}); !errors.Is(err, linux.EACCES) {
			t.Errorf("SetAttr(sym_shadow) = %v, want EACCES", err)
		}
		if err := homeDir.Link(symShadow, "hardlink_shadow"); !errors.Is(err, linux.EACCES) {
			t.Errorf("Link(sym_shadow) = %v, want EACCES", err)
		}
		if got, err := os.ReadFile(filepath.Join(rootDir, "etc/shadow")); err != nil || string(got) != "root-secret" {
			t.Errorf("etc/shadow modified via symlink: (%q, %v)", got, err)
		}
	})

	t.Run("stale_fid_escape", func(t *testing.T) {
		// Replace home/d on the host FS (so p9.Server does not mark
		// staleFid deleted) and verify filter9PFile.checkPath itself
		// rejects Tlink, Tgetattr, Txattr, and Tlopen with EACCES.
		rootDir := setupFilterTestTree(t)
		outsideDir := t.TempDir()
		outsideFile := filepath.Join(outsideDir, "secret.txt")
		if err := os.WriteFile(outsideFile, []byte("OUTSIDE-SECRET"), 0o600); err != nil {
			t.Fatalf("WriteFile(outside): %v", err)
		}
		innerDir := filepath.Join(rootDir, "home/d")
		if err := os.Mkdir(innerDir, 0o755); err != nil {
			t.Fatalf("Mkdir(inner): %v", err)
		}
		if err := os.WriteFile(filepath.Join(innerDir, "secret.txt"), []byte("inner"), 0o644); err != nil {
			t.Fatalf("WriteFile(inner): %v", err)
		}

		root := startP9WirePair(t, NewFilter9P(NewCPU9P(rootDir), remotes))
		_, homeDir, err := root.Walk([]string{"home"})
		if err != nil {
			t.Fatalf("Walk([home]): %v", err)
		}
		defer homeDir.Close()
		_, staleFid, err := homeDir.Walk([]string{"d", "secret.txt"})
		if err != nil {
			t.Fatalf("Walk([d secret.txt]): %v", err)
		}
		defer staleFid.Close()

		if err := os.RemoveAll(innerDir); err != nil {
			t.Fatalf("RemoveAll(innerDir): %v", err)
		}
		if err := os.Symlink(outsideDir, innerDir); err != nil {
			t.Fatalf("Symlink(innerDir -> outsideDir): %v", err)
		}

		if err := homeDir.Link(staleFid, "stolen"); !errors.Is(err, linux.EACCES) {
			t.Errorf("Link(staleFid) = %v, want EACCES", err)
		}
		if _, _, _, err := staleFid.GetAttr(p9.AttrMaskAll); !errors.Is(err, linux.EACCES) {
			t.Errorf("GetAttr(staleFid) = %v, want EACCES", err)
		}
		if _, err := staleFid.ListXattrs(); !errors.Is(err, linux.EACCES) {
			t.Errorf("ListXattrs(staleFid) = %v, want EACCES", err)
		}
		if _, err := staleFid.GetXattr("user.test"); !errors.Is(err, linux.EACCES) {
			t.Errorf("GetXattr(staleFid) = %v, want EACCES", err)
		}
		if _, _, err := staleFid.Open(p9.ReadOnly); !errors.Is(err, linux.EACCES) {
			t.Errorf("Open(staleFid) = %v, want EACCES", err)
		}
		if got, err := os.ReadFile(outsideFile); err != nil || string(got) != "OUTSIDE-SECRET" {
			t.Errorf("outsideFile modified: (%q, %v)", got, err)
		}
	})

	t.Run("fifo_rejected", func(t *testing.T) {
		// Opening a FIFO over 9P must fail immediately with EACCES
		// without deadlocking filter9PAttacher.mu.
		rootDir := setupFilterTestTree(t)
		if err := unix.Mkfifo(filepath.Join(rootDir, "home/myfifo"), 0o644); err != nil {
			t.Fatalf("Mkfifo: %v", err)
		}
		root := startP9WirePair(t, NewFilter9P(NewCPU9P(rootDir), remotes))
		_, fifoFid, err := root.Walk([]string{"home", "myfifo"})
		if err != nil {
			t.Fatalf("Walk([home myfifo]): %v", err)
		}
		defer fifoFid.Close()
		if _, _, err := fifoFid.Open(p9.ReadOnly); !errors.Is(err, linux.EACCES) {
			t.Errorf("Open(/home/myfifo) = %v, want EACCES", err)
		}
		if got := readP9File(t, root, []string{"home", "user", "hello.txt"}); got != "hello world" {
			t.Errorf("read after FIFO check = %q, want %q", got, "hello world")
		}
	})

	t.Run("unsafe_export", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		root := startP9WirePair(t, NewCPU9P(rootDir))

		// With UnsafeExport, paths outside -namespace are accessible.
		if got := readP9File(t, root, []string{"etc", "shadow"}); got != "root-secret" {
			t.Errorf("read /etc/shadow = %q, want %q", got, "root-secret")
		}
		if got := readP9File(t, root, []string{"b", "other", "secret"}); got != "other-secret" {
			t.Errorf("read /b/other/secret = %q, want %q", got, "other-secret")
		}
		if got, want := readAllP9Dir(t, root, nil), []string{"b", "etc", "home", "topsecret"}; !slices.Equal(got, want) {
			t.Errorf("Readdir(/) = %v, want %v", got, want)
		}
	})
}

func startNFSWirePair(t *testing.T, rootDir string, namespace string, unsafeExport bool) *nfsc.Target {
	t.Helper()
	fs, err := newNFSFS("", rootDir, namespace, unsafeExport)
	if err != nil {
		t.Fatalf("newNFSFS: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	nonce := uuid.NewString()
	handler := NewNullAuthHandler(ln, fs, nonce)
	cacheHelper := nfshelper.NewCachingHandler(handler, 1024*1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = nfs.Serve(ln, cacheHelper)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})

	// go-nfs-client binds a random local port; retry on collisions.
	var rpcClient *rpc.Client
	for range 64 {
		rpcClient, err = rpc.DialTCP("tcp", ln.Addr().String(), false)
		if !errors.Is(err, syscall.EADDRINUSE) {
			break
		}
	}
	if err != nil {
		t.Fatalf("rpc.DialTCP: %v", err)
	}
	t.Cleanup(func() {
		rpcClient.Close()
	})
	mounter := nfsc.Mount{Client: rpcClient}
	target, err := mounter.Mount(nonce, rpc.AuthNull)
	if err != nil {
		t.Fatalf("mounter.Mount: %v", err)
	}
	t.Cleanup(func() {
		_ = mounter.Unmount()
	})
	return target
}

func readNFSDirNames(t *testing.T, target *nfsc.Target, dir string) []string {
	t.Helper()
	ents, err := target.ReadDirPlus(dir)
	if err != nil {
		t.Fatalf("ReadDirPlus(%q): %v", dir, err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func tryReadNFSFile(target *nfsc.Target, path string) (string, error) {
	f, err := target.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func readNFSFile(t *testing.T, target *nfsc.Target, path string) string {
	t.Helper()
	data, err := tryReadNFSFile(target, path)
	if err != nil {
		t.Fatalf("readNFSFile(%q): %v", path, err)
	}
	return data
}

func TestEndToEndNFSExport(t *testing.T) {
	const namespace = "/home:/bin=/b/bin"

	t.Run("namespace_filtering", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		// Export an empty mount root so Remove("/empty") exercises
		// filterFS's mount-root protection rather than ENOTEMPTY.
		if err := os.Mkdir(filepath.Join(rootDir, "empty"), 0o755); err != nil {
			t.Fatalf("Mkdir(empty): %v", err)
		}
		target := startNFSWirePair(t, rootDir, namespace+":/empty", false)

		if got := readNFSFile(t, target, "/home/user/hello.txt"); got != "hello world" {
			t.Errorf("read /home/user/hello.txt = %q, want %q", got, "hello world")
		}
		if got := readNFSFile(t, target, "/b/bin/ls"); got != "binary-ls" {
			t.Errorf("read /b/bin/ls = %q, want %q", got, "binary-ls")
		}

		if got, want := readNFSDirNames(t, target, "/"), []string{"b", "empty", "home"}; !slices.Equal(got, want) {
			t.Errorf("ReadDirPlus(/) = %v, want %v", got, want)
		}
		if got, want := readNFSDirNames(t, target, "/b"), []string{"bin"}; !slices.Equal(got, want) {
			t.Errorf("ReadDirPlus(/b) = %v, want %v", got, want)
		}

		// Disallowed paths fail Lookup over NFSv3.
		for _, bad := range []string{"/etc", "/etc/shadow", "/topsecret", "/b/other", "/b/other/secret"} {
			if _, _, err := target.Lookup(bad); err == nil {
				t.Errorf("Lookup(%q) succeeded over NFS, want error", bad)
			}
		}

		// Mutations on ancestors or exported mount roots fail.
		if _, err := target.Create("/evil.txt", 0o644); err == nil {
			t.Errorf("Create(/evil.txt) succeeded over NFS, want error")
		}
		if _, err := target.Mkdir("/b/evil", 0o755); err == nil {
			t.Errorf("Mkdir(/b/evil) succeeded over NFS, want error")
		}
		if err := target.Remove("/empty"); err == nil {
			t.Errorf("Remove(/empty) succeeded over NFS, want error")
		}
		if _, err := os.Stat(filepath.Join(rootDir, "empty")); err != nil {
			t.Errorf("empty mount root removed: %v", err)
		}

		// Create, write, read, and remove inside "/home" succeed.
		const payload = "nfs-wire-payload"
		wf, err := target.OpenFile("/home/user/nfs_wire.txt", 0o644)
		if err != nil {
			t.Fatalf("OpenFile(/home/user/nfs_wire.txt): %v", err)
		}
		if _, err := wf.Write([]byte(payload)); err != nil {
			_ = wf.Close()
			t.Fatalf("Write: %v", err)
		}
		if err := wf.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if got := readNFSFile(t, target, "/home/user/nfs_wire.txt"); got != payload {
			t.Errorf("read /home/user/nfs_wire.txt = %q, want %q", got, payload)
		}
		onDisk, err := os.ReadFile(filepath.Join(rootDir, "home/user/nfs_wire.txt"))
		if err != nil || string(onDisk) != payload {
			t.Fatalf("on-disk /home/user/nfs_wire.txt = (%q, %v), want (%q, nil)", onDisk, err, payload)
		}
		if err := target.Remove("/home/user/nfs_wire.txt"); err != nil {
			t.Fatalf("Remove(/home/user/nfs_wire.txt): %v", err)
		}
	})

	t.Run("symlink_escape", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		target := startNFSWirePair(t, rootDir, namespace, false)

		if err := os.Symlink("../etc/shadow", filepath.Join(rootDir, "home/esc")); err != nil {
			t.Fatalf("os.Symlink(esc): %v", err)
		}
		if err := os.Symlink("..", filepath.Join(rootDir, "home/up")); err != nil {
			t.Fatalf("os.Symlink(up): %v", err)
		}
		if got, err := tryReadNFSFile(target, "/home/esc"); err == nil {
			t.Errorf("read /home/esc succeeded over NFS (%q), want error", got)
		}
		if _, _, err := target.Lookup("/home/up/etc/shadow"); err == nil {
			t.Errorf("Lookup(/home/up/etc/shadow) succeeded over NFS, want error")
		}
		if err := target.Remove("/home/esc"); err == nil {
			t.Errorf("Remove(/home/esc) succeeded over NFS, want error")
		}
		if got, err := os.ReadFile(filepath.Join(rootDir, "etc/shadow")); err != nil || string(got) != "root-secret" {
			t.Errorf("etc/shadow modified via NFS symlink: (%q, %v)", got, err)
		}
	})

	t.Run("fifo_rejected", func(t *testing.T) {
		// Opening or creating over an existing FIFO over NFS must fail
		// immediately without deadlocking filterFS.mu.
		rootDir := setupFilterTestTree(t)
		if err := unix.Mkfifo(filepath.Join(rootDir, "home/myfifo"), 0o644); err != nil {
			t.Fatalf("Mkfifo: %v", err)
		}
		target := startNFSWirePair(t, rootDir, namespace, false)

		if got, err := tryReadNFSFile(target, "/home/myfifo"); err == nil {
			t.Errorf("read /home/myfifo succeeded over NFS (%q), want error", got)
		}
		if _, err := target.Create("/home/myfifo", 0o644); err == nil {
			t.Errorf("Create(/home/myfifo) succeeded over NFS, want error")
		}
		if got := readNFSFile(t, target, "/home/user/hello.txt"); got != "hello world" {
			t.Errorf("read after FIFO checks = %q, want %q", got, "hello world")
		}
	})

	t.Run("symlinked_root", func(t *testing.T) {
		// Simulate macOS /var -> /private/var where -root contains a
		// symlink component.
		realRoot := setupFilterTestTree(t)
		symRoot := filepath.Join(t.TempDir(), "rootlink")
		if err := os.Symlink(realRoot, symRoot); err != nil {
			t.Fatalf("os.Symlink: %v", err)
		}
		target := startNFSWirePair(t, symRoot, namespace, false)
		if got := readNFSFile(t, target, "/home/user/hello.txt"); got != "hello world" {
			t.Errorf("read /home/user/hello.txt via symlinked root = %q, want %q", got, "hello world")
		}
		if got, want := readNFSDirNames(t, target, "/"), []string{"b", "home"}; !slices.Equal(got, want) {
			t.Errorf("ReadDirPlus(/) via symlinked root = %v, want %v", got, want)
		}
	})

	t.Run("unsafe_export", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		target := startNFSWirePair(t, rootDir, namespace, true)

		if got := readNFSFile(t, target, "/etc/shadow"); got != "root-secret" {
			t.Errorf("read /etc/shadow = %q, want %q", got, "root-secret")
		}
		if got := readNFSFile(t, target, "/b/other/secret"); got != "other-secret" {
			t.Errorf("read /b/other/secret = %q, want %q", got, "other-secret")
		}
		if got, want := readNFSDirNames(t, target, "/"), []string{"b", "etc", "home", "topsecret"}; !slices.Equal(got, want) {
			t.Errorf("ReadDirPlus(/) = %v, want %v", got, want)
		}
	})
}
