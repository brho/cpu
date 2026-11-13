// Copyright 2026 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/go-git/go-billy/v5"
	"github.com/google/uuid"
	"github.com/hugelgupf/p9/p9"
	nfs "github.com/willscott/go-nfs"
	nfsc "github.com/willscott/go-nfs-client/nfs"
	rpc "github.com/willscott/go-nfs-client/nfs/rpc"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

func startP9WirePair(t *testing.T, attacher p9.Attacher) (*p9.Client, p9.File) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	srv := p9.NewServer(attacher)
	go func() {
		_ = srv.Handle(serverConn, serverConn)
	}()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
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
	return cl, root
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
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt(%v): %v", path, err)
	}
	return string(buf[:n])
}

func TestEndToEnd9PExport(t *testing.T) {
	remotes, err := ParseBindRemotes("/home:/bin=/b/bin")
	if err != nil {
		t.Fatalf("ParseBindRemotes: %v", err)
	}

	t.Run("safe_default", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		attacher := NewFilter9P(NewCPU9P(rootDir), remotes)
		_, root := startP9WirePair(t, attacher)

		// Allowed files in /home and /b/bin are readable over 9P.
		if got := readP9File(t, root, []string{"home", "user", "hello.txt"}); got != "hello world" {
			t.Errorf("read /home/user/hello.txt = %q, want %q", got, "hello world")
		}
		if got := readP9File(t, root, []string{"b", "bin", "ls"}); got != "binary-ls" {
			t.Errorf("read /b/bin/ls = %q, want %q", got, "binary-ls")
		}

		// Readdir on ancestor "/" only lists "b" and "home".
		if got, want := readAllP9Dir(t, root, nil), []string{"b", "home"}; !slices.Equal(got, want) {
			t.Errorf("Readdir(/) = %v, want %v", got, want)
		}
		// Readdir on ancestor "/b" only lists "bin" (hiding "other").
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

		// Mutations on ancestor directories are rejected over 9P.
		_, bDir, err := root.Walk([]string{"b"})
		if err != nil {
			t.Fatalf("Walk([b]): %v", err)
		}
		defer bDir.Close()
		if _, _, _, err := bDir.Create("evil", p9.ReadWrite, 0o644, p9.NoUID, p9.NoGID); err == nil {
			t.Errorf("bDir.Create succeeded, want error")
		}
		if _, err := bDir.Mkdir("evil", 0o755, p9.NoUID, p9.NoGID); err == nil {
			t.Errorf("bDir.Mkdir succeeded, want error")
		}
		if err := bDir.UnlinkAt("bin", 0); err == nil {
			t.Errorf("bDir.UnlinkAt(bin) succeeded, want error")
		}
		if err := root.UnlinkAt("home", 0); err == nil {
			t.Errorf("root.UnlinkAt(home) succeeded, want error")
		}

		// Mutations inside exported "/home" succeed over 9P, and
		// p9.Server blocks walking through a symlink to "../etc/shadow".
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
		if err := homeDir.UnlinkAt("sym_etc", 0); err != nil {
			t.Fatalf("homeDir.UnlinkAt(sym_etc): %v", err)
		}

		_, createdDir, err := root.Walk([]string{"home"})
		if err != nil {
			t.Fatalf("Walk([home]): %v", err)
		}
		defer createdDir.Close()
		nf, _, _, err := createdDir.Create("wire.txt", p9.ReadWrite, 0o644, p9.NoUID, p9.NoGID)
		if err != nil {
			t.Fatalf("Create(wire.txt): %v", err)
		}
		if _, err := nf.WriteAt([]byte("wire-data"), 0); err != nil {
			_ = nf.Close()
			t.Fatalf("WriteAt: %v", err)
		}
		_ = nf.Close()
		if got := readP9File(t, root, []string{"home", "wire.txt"}); got != "wire-data" {
			t.Errorf("read /home/wire.txt = %q, want %q", got, "wire-data")
		}
	})

	t.Run("unsafe_export", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		attacher := NewCPU9P(rootDir)
		_, root := startP9WirePair(t, attacher)

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
	mdir, err := filepath.Rel("/", rootDir)
	if err != nil {
		t.Fatalf("filepath.Rel: %v", err)
	}
	osfs := NewOSFS(rootDir)
	mem, err := NewfsCPIO("", WithMount(mdir, osfs))
	if err != nil {
		t.Fatalf("NewfsCPIO: %v", err)
	}
	var fs billy.Filesystem = COS{mem}
	if !unsafeExport {
		remotes, err := ParseBindRemotes(namespace)
		if err != nil {
			t.Fatalf("ParseBindRemotes: %v", err)
		}
		fs = NewFilterFS(fs, remotes)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	nonce := uuid.NewString()
	handler := NewNullAuthHandler(ln, fs, nonce)
	cacheHelper := nfshelper.NewCachingHandler(handler, 1024*1024)
	go func() {
		_ = nfs.Serve(ln, cacheHelper)
	}()
	t.Cleanup(func() {
		_ = ln.Close()
	})

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

func readNFSFile(t *testing.T, target *nfsc.Target, path string) string {
	t.Helper()
	f, err := target.Open(path)
	if err != nil {
		t.Fatalf("target.Open(%q): %v", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("io.ReadAll(%q): %v", path, err)
	}
	return string(data)
}

func TestEndToEndNFSExport(t *testing.T) {
	const namespace = "/home:/bin=/b/bin"

	t.Run("safe_default", func(t *testing.T) {
		rootDir := setupFilterTestTree(t)
		target := startNFSWirePair(t, rootDir, namespace, false)

		// Allowed paths are readable over NFSv3.
		if got := readNFSFile(t, target, "/home/user/hello.txt"); got != "hello world" {
			t.Errorf("read /home/user/hello.txt = %q, want %q", got, "hello world")
		}
		if got := readNFSFile(t, target, "/b/bin/ls"); got != "binary-ls" {
			t.Errorf("read /b/bin/ls = %q, want %q", got, "binary-ls")
		}

		// ReadDirPlus on "/" only returns ["b", "home"].
		if got, want := readNFSDirNames(t, target, "/"), []string{"b", "home"}; !slices.Equal(got, want) {
			t.Errorf("ReadDirPlus(/) = %v, want %v", got, want)
		}
		// ReadDirPlus on "/b" only returns ["bin"].
		if got, want := readNFSDirNames(t, target, "/b"), []string{"bin"}; !slices.Equal(got, want) {
			t.Errorf("ReadDirPlus(/b) = %v, want %v", got, want)
		}

		// Disallowed paths fail Lookup and Open over NFSv3.
		for _, bad := range []string{"/etc", "/etc/shadow", "/topsecret", "/b/other", "/b/other/secret"} {
			if _, _, err := target.Lookup(bad); err == nil {
				t.Errorf("Lookup(%q) succeeded over NFS, want error", bad)
			}
			if f, err := target.Open(bad); err == nil {
				_ = f.Close()
				t.Errorf("Open(%q) succeeded over NFS, want error", bad)
			}
		}

		// Mutations on ancestor directories are rejected over NFSv3.
		if _, err := target.Create("/evil.txt", 0o644); err == nil {
			t.Errorf("Create(/evil.txt) succeeded over NFS, want error")
		}
		if _, err := target.Mkdir("/b/evil", 0o755); err == nil {
			t.Errorf("Mkdir(/b/evil) succeeded over NFS, want error")
		}
		if err := target.Remove("/home"); err == nil {
			t.Errorf("Remove(/home) succeeded over NFS, want error")
		}

		// Create, write, read, and remove inside exported "/home"
		// succeed over NFSv3.
		wf, err := target.OpenFile("/home/user/nfs_wire.txt", 0o644)
		if err != nil {
			t.Fatalf("OpenFile(/home/user/nfs_wire.txt): %v", err)
		}
		payload := []byte("nfs-wire-payload")
		if _, err := wf.Write(payload); err != nil {
			_ = wf.Close()
			t.Fatalf("Write: %v", err)
		}
		if err := wf.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		onDisk, err := os.ReadFile(filepath.Join(rootDir, "home/user/nfs_wire.txt"))
		if err != nil || !bytes.Equal(onDisk, payload) {
			t.Fatalf("on-disk /home/user/nfs_wire.txt = (%q, %v), want (%q, nil)", onDisk, err, payload)
		}
		if err := target.Remove("/home/user/nfs_wire.txt"); err != nil {
			t.Fatalf("Remove(/home/user/nfs_wire.txt): %v", err)
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
