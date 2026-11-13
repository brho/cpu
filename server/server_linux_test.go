package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/hugelgupf/p9/p9"
	config "github.com/kevinburke/ssh_config"
	"github.com/u-root/cpu/client"
	nfsc "github.com/willscott/go-nfs-client/nfs"
	rpc "github.com/willscott/go-nfs-client/nfs/rpc"
	"golang.org/x/sys/unix"
)

func TestHelperProcess(t *testing.T) {
	v, ok := os.LookupEnv("GO_WANT_HELPER_PROCESS")
	if !ok {
		t.Logf("just a helper")
		return
	}
	t.Logf("Check %q", v)
	if err := unix.Mount("cpu", v, "tmpfs", 0, ""); err != nil {
		t.Fatalf("unix.Mount(cpu, %q, \"tmpfs\"): %v != nil", v, err)
	}

	vanish := filepath.Join(v, "vanish")
	t.Logf("Mount ok, try to create %q", vanish)
	msg := "This should not be visible in the parent"
	if err := os.WriteFile(vanish, []byte(msg), 0644); err != nil {
		t.Fatalf(`os.WriteFile(%q, %q, 0644): %v != nil`, vanish, msg, err)
	}
	t.Logf("Created %q", vanish)
}

// TestPrivateNameSpace tests if we are privatizing mounts
// correctly. We spawn a child with syscall.CLONE_NEWNS set.
// The child mounts a tmpfs over the directory, and creates a
// file. When it exits, and returns to us, that file should
// not be visible.
func TestPrivateNameSpace(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skipf("Skipping; not root")
	}
	d := t.TempDir()
	t.Logf("Call helper %q", os.Args[0])
	c := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "-test.v")
	c.Env = []string{"GO_WANT_HELPER_PROCESS=" + d}
	c.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS}
	o, err := c.CombinedOutput()
	t.Logf("out %s", o)
	if err != nil {
		t.Errorf("Error: %v", err)
	}
	vanish := filepath.Join(d, "vanish")
	if _, err := os.Stat(vanish); err == nil {
		t.Logf("Privatization failed ... Try to unmount %v", d)
		if err := unix.Unmount(d, unix.MNT_FORCE); err != nil {
			t.Fatalf("unix.Unmount( %q, %#x): %v != nil", d, unix.MNT_FORCE, err)
		}
		t.Fatalf("os.Stat(%q): nil != err", vanish)
	}
}

// Now the fun begins. We have to be a demon.
func TestDaemonSession(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skipf("Skipping as we are not root")
	}

	runtime.GOMAXPROCS(1)
	v = t.Logf
	d := t.TempDir()
	t.Logf("tempdir is %q", d)
	if err := os.Setenv("HOME", d); err != nil {
		t.Fatalf(`os.Setenv("HOME", %s): %v != nil`, d, err)
	}
	dotSSH := filepath.Join(d, ".ssh")
	hackconfig, err := gendotssh(d, string(sshConfig))
	if err != nil {
		t.Fatalf(`gendotssh(%s): %v != nil`, d, err)
	}

	pubKey := filepath.Join(dotSSH, "server.pub")
	s, err := New(pubKey, "", os.Args[0])
	if err != nil {
		t.Fatalf("New(%q, %q, %q): %v != nil", pubKey, "", os.Args[0], err)
	}

	ln, err := net.Listen("tcp", "")
	if err != nil {
		t.Fatalf("s.Listen(): %v != nil", err)
	}
	t.Cleanup(func() {
		_ = s.Close()
	})
	t.Logf("Listening on %v", ln.Addr())
	// this is a racy test.
	// The ssh package really ought to allow you to accept
	// on a socket and then call with that socket. This would be
	// more in line with bsd sockets which let you write a server
	// and client in line, e.g.
	// socket/bind/listen/connect/accept
	// oh well.
	go func(t *testing.T) {
		if err := s.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) && err.Error() != "ssh: Server closed" {
			t.Errorf("s.Daemon(): %v != nil", err)
		}
	}(t)
	v = t.Logf
	// From this test forward, at least try to get a port.
	// For this test, there must be a key.
	// hack for lack in ssh_config
	// https://github.com/kevinburke/ssh_config/issues/2
	cfg, err := config.Decode(bytes.NewBuffer([]byte(hackconfig)))
	if err != nil {
		t.Fatal(err)
	}
	host, err := cfg.Get("server", "HostName")
	if err != nil || len(host) == 0 {
		t.Fatalf(`cfg.Get("server", "HostName"): (%q, %v) != (localhost, nil`, host, err)
	}
	kf, err := cfg.Get("server", "IdentityFile")
	if err != nil || len(kf) == 0 {
		t.Fatalf(`cfg.Get("server", "IdentityFile"): (%q, %v) != (afilename, nil`, kf, err)
	}
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q): %v != nil", ln.Addr(), err)
	}

	t.Logf("HostName %q, IdentityFile %q, command %v", host, kf, os.Args[0])
	client.SetVerbose(t.Logf)
	c := client.Command(host, "-test.run", "TestDaemonConnectHelper", "-test.v", "--", "ls", "-l")
	if err := c.SetOptions(client.WithPrivateKeyFile(kf), client.WithPort(port), client.WithRoot(d), client.WithNameSpace("")); err != nil {
		t.Fatalf("SetOptions: %v != nil", err)
	}
	c.Stdin = bytes.NewReader(nil)
	c.Env = append(os.Environ(), "GO_WANT_DAEMON_HELPER_PROCESS=1")
	if err := c.Dial(); err != nil {
		t.Fatalf("Dial: got %v, want nil", err)
	}
	if err = c.Start(); err != nil {
		t.Fatalf("Start: got %v, want nil", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: got %v, want nil", err)
		}
	}()
	if err := c.SessionIn.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Errorf("Close stdin: Got %v, want nil", err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("Wait: got %v, want nil", err)
	}
	r, err := c.Outputs()
	if err != nil {
		t.Errorf("Outputs: got %v, want nil", err)
	}
	t.Logf("c.Run: (%v, %q, %q)", err, r[0].String(), r[1].String())
}

// TestDaemonConnect tests connecting to a daemon and exercising
// minimal operations.
func TestDaemonConnect(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skipf("Skipping as we are not root")
	}
	d := t.TempDir()
	if err := os.Setenv("HOME", d); err != nil {
		t.Fatalf(`os.Setenv("HOME", %s): %v != nil`, d, err)
	}
	hackconfig, err := gendotssh(d, string(sshConfig))
	if err != nil {
		t.Fatalf(`gendotssh(%s): %v != nil`, d, err)
	}

	v = t.Logf
	s, err := New(filepath.Join(d, ".ssh", "server.pub"), filepath.Join(d, ".ssh", "hostkey"), os.Args[0])
	if err != nil {
		t.Fatalf(`New(%q, %q, %q): %v != nil`, filepath.Join(d, ".ssh", "server.pub"), filepath.Join(d, ".ssh", "hostkey"), os.Args[0], err)
	}

	ln, err := net.Listen("tcp", "")
	if err != nil {
		t.Fatalf(`net.Listen("", ""): %v != nil`, err)
	}
	t.Cleanup(func() {
		_ = s.Close()
	})
	t.Logf("Listening on %v", ln.Addr())
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// this is a racy test.
	// The ssh package really ought to allow you to accept
	// on a socket and then call with that socket. This would be
	// more in line with bsd sockets which let you write a server
	// and client in line, e.g.
	// socket/bind/listen/connect/accept
	// oh well.
	go func(t *testing.T) {
		if err := s.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) && err.Error() != "ssh: Server closed" {
			t.Errorf("s.Daemon(): %v != nil", err)
		}
	}(t)
	v = t.Logf
	// From this test forward, at least try to get a port.
	// For this test, there must be a key.
	// hack for lack in ssh_config
	// https://github.com/kevinburke/ssh_config/issues/2
	cfg, err := config.Decode(bytes.NewBuffer([]byte(hackconfig)))

	if err != nil {
		t.Fatal(err)
	}
	host, err := cfg.Get("server", "HostName")
	if err != nil || len(host) == 0 {
		t.Fatalf(`cfg.Get("server", "HostName"): (%q, %v) != (localhost, nil`, host, err)
	}
	kf, err := cfg.Get("server", "IdentityFile")
	if err != nil || len(kf) == 0 {
		t.Fatalf(`cfg.Get("server", "IdentityFile"): (%q, %v) != (afilename, nil`, kf, err)
	}
	t.Logf("HostName %q, IdentityFile %q", host, kf)
	c := client.Command(host, "-test.run", "TestDaemonConnectHelper", "-test.v", "--", "date")
	if err := c.SetOptions(client.WithPrivateKeyFile(kf), client.WithPort(port), client.WithRoot("/"), client.WithNameSpace("")); err != nil {
		t.Fatalf("SetOptions: %v != nil", err)
	}
	c.Stdin = bytes.NewReader(nil)
	c.Env = append(os.Environ(), "GO_WANT_DAEMON_HELPER_PROCESS=1")
	if err := c.Dial(); err != nil {
		t.Fatalf("Dial: got %v, want nil", err)
	}
	if err = c.Start(); err != nil {
		t.Fatalf("Start: got %v, want nil", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Fatalf("Close: got %v, want nil", err)
		}
	}()
	if err := c.SessionIn.Close(); err != nil && !errors.Is(err, io.EOF) {
		t.Errorf("Close stdin: Got %v, want nil", err)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("Wait: got %v, want nil", err)
	}
	r, err := c.Outputs()
	if err != nil {
		t.Errorf("Outputs: got %v, want nil", err)
	}
	t.Logf("c.Run: (%v, %q, %q)", err, r[0].String(), r[1].String())
}

func setupDaemonExportTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"home/user", "b/bin", "b/other", "etc"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", d, err)
		}
	}
	for rel, content := range map[string]string{
		"home/user/hello.txt": "hello from home",
		"b/bin/ls":            "binary-ls",
		"b/other/secret":      "other-secret",
		"etc/shadow":          "root-secret",
	} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%q): %v", rel, err)
		}
	}
	return root
}

func startTestCPUD(t *testing.T) (host, port, kf string) {
	t.Helper()
	d := t.TempDir()
	t.Setenv("HOME", d)
	if _, err := gendotssh(d, string(sshConfig)); err != nil {
		t.Fatalf("gendotssh: %v", err)
	}
	pubKey := filepath.Join(d, ".ssh", "server.pub")
	hkFile := filepath.Join(d, ".ssh", "hostkey")
	kf = filepath.Join(d, ".ssh", "server")

	s, err := New(pubKey, hkFile, os.Args[0])
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Close()
	})
	go func() {
		_ = s.Serve(ln)
	}()
	host, port, err = net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return host, port, kf
}

type closeBuffer struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	done chan struct{}
	once sync.Once
}

func newCloseBuffer() *closeBuffer {
	return &closeBuffer{done: make(chan struct{})}
}

func (b *closeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *closeBuffer) Close() error {
	b.once.Do(func() { close(b.done) })
	return nil
}

func (b *closeBuffer) String() string {
	<-b.done
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestDaemon9PNamespaceHelper(t *testing.T) {
	mode := os.Getenv("GO_WANT_DAEMON_9P_HELPER")
	if mode == "" {
		return
	}
	if port9p == "" {
		t.Fatalf("missing -port9p flag in remote helper")
	}
	nonce := os.Getenv("CPUNONCE")
	if nonce == "" {
		t.Fatalf("missing CPUNONCE in remote helper")
	}

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port9p))
	if err != nil {
		t.Fatalf("net.Dial(9p): %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, nonce); err != nil {
		t.Fatalf("write nonce: %v", err)
	}

	cl, err := p9.NewClient(conn)
	if err != nil {
		t.Fatalf("p9.NewClient: %v", err)
	}
	root, err := cl.Attach("")
	if err != nil {
		t.Fatalf("cl.Attach: %v", err)
	}
	defer root.Close()

	// Verify /home/user/hello.txt and /b/bin/ls are accessible in
	// both modes.
	for _, tc := range []struct {
		path []string
		want string
	}{
		{path: []string{"home", "user", "hello.txt"}, want: "hello from home"},
		{path: []string{"b", "bin", "ls"}, want: "binary-ls"},
	} {
		_, f, err := root.Walk(tc.path)
		if err != nil {
			t.Fatalf("Walk(%v): %v", tc.path, err)
		}
		if _, _, err := f.Open(p9.ReadOnly); err != nil {
			_ = f.Close()
			t.Fatalf("Open(%v): %v", tc.path, err)
		}
		buf := make([]byte, 128)
		n, err := f.ReadAt(buf, 0)
		_ = f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("ReadAt(%v): %v", tc.path, err)
		}
		if got := string(buf[:n]); got != tc.want {
			t.Fatalf("ReadAt(%v) = %q, want %q", tc.path, got, tc.want)
		}
	}

	// List root directory entries.
	_, rootCopy, err := root.Walk(nil)
	if err != nil {
		t.Fatalf("Walk(nil): %v", err)
	}
	defer rootCopy.Close()
	if _, _, err := rootCopy.Open(p9.ReadOnly); err != nil {
		t.Fatalf("rootCopy.Open: %v", err)
	}
	ents, err := rootCopy.Readdir(0, 4096)
	if err != nil {
		t.Fatalf("rootCopy.Readdir: %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name)
	}
	slices.Sort(names)

	switch mode {
	case "safe":
		if want := []string{"b", "home"}; !slices.Equal(names, want) {
			t.Fatalf("safe Readdir(/) = %v, want %v", names, want)
		}
		for _, bad := range [][]string{{"etc"}, {"etc", "shadow"}, {"b", "other"}} {
			if _, f, err := root.Walk(bad); err == nil {
				_ = f.Close()
				t.Fatalf("safe Walk(%v) succeeded, want error", bad)
			}
		}
		if _, err := root.Mkdir("escaped", 0o755, p9.NoUID, p9.NoGID); err == nil {
			t.Fatalf("safe root.Mkdir succeeded, want error")
		}
		fmt.Println("DAEMON_9P_SAFE_OK")
	case "unsafe":
		if want := []string{"b", "etc", "home"}; !slices.Equal(names, want) {
			t.Fatalf("unsafe Readdir(/) = %v, want %v", names, want)
		}
		_, f, err := root.Walk([]string{"etc", "shadow"})
		if err != nil {
			t.Fatalf("unsafe Walk(/etc/shadow): %v", err)
		}
		if _, _, err := f.Open(p9.ReadOnly); err != nil {
			_ = f.Close()
			t.Fatalf("unsafe Open(/etc/shadow): %v", err)
		}
		buf := make([]byte, 128)
		n, err := f.ReadAt(buf, 0)
		_ = f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatalf("unsafe ReadAt(/etc/shadow): %v", err)
		}
		if got := string(buf[:n]); got != "root-secret" {
			t.Fatalf("unsafe ReadAt(/etc/shadow) = %q, want %q", got, "root-secret")
		}
		fmt.Println("DAEMON_9P_UNSAFE_OK")
	default:
		t.Fatalf("unknown mode %q", mode)
	}
}

func TestDaemonEndToEnd9PNamespace(t *testing.T) {
	host, port, kf := startTestCPUD(t)

	for _, tc := range []struct {
		name         string
		unsafeExport bool
		mode         string
		wantToken    string
	}{
		{name: "safe_default", unsafeExport: false, mode: "safe", wantToken: "DAEMON_9P_SAFE_OK"},
		{name: "unsafe_export", unsafeExport: true, mode: "unsafe", wantToken: "DAEMON_9P_UNSAFE_OK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := setupDaemonExportTree(t)
			c := client.Command(host, "-test.run=TestDaemon9PNamespaceHelper", "-test.v", "--", "run")
			if err := c.SetOptions(
				client.WithPrivateKeyFile(kf),
				client.WithPort(port),
				client.WithRoot(rootDir),
				client.WithNameSpace("/home:/bin=/b/bin"),
				client.With9P(true),
				client.WithUnsafeExport(tc.unsafeExport),
			); err != nil {
				t.Fatalf("SetOptions: %v", err)
			}
			stdout, stderr := newCloseBuffer(), newCloseBuffer()
			c.Stdin = bytes.NewReader(nil)
			c.Stdout, c.Stderr = stdout, stderr
			c.Env = append(os.Environ(), "GO_WANT_DAEMON_9P_HELPER="+tc.mode)
			if err := c.Dial(); err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Close()
			if err := c.Run(); err != nil {
				t.Fatalf("Run: %v (stdout=%q, stderr=%q)", err, stdout.String(), stderr.String())
			}
			if got := stdout.String(); !strings.Contains(got, tc.wantToken) {
				t.Fatalf("stdout = %q (stderr = %q), want %q", got, stderr.String(), tc.wantToken)
			}
		})
	}
}

func parseNFSFSTab(fstab string) (nonce, port string, err error) {
	for _, line := range strings.Split(fstab, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "nfs" {
			continue
		}
		_, nonce, ok := strings.Cut(fields[0], ":")
		if !ok {
			continue
		}
		for _, opt := range strings.Split(fields[3], ",") {
			if p, ok := strings.CutPrefix(opt, "port="); ok {
				return nonce, p, nil
			}
		}
	}
	return "", "", fmt.Errorf("no nfs entry found in CPU_FSTAB %q", fstab)
}

func TestDaemonNFSNamespaceHelper(t *testing.T) {
	mode := os.Getenv("GO_WANT_DAEMON_NFS_HELPER")
	if mode == "" {
		return
	}
	nonce, portNFS, err := parseNFSFSTab(os.Getenv("CPU_FSTAB"))
	if err != nil {
		t.Fatalf("parseNFSFSTab: %v", err)
	}

	var rpcClient *rpc.Client
	for range 64 {
		rpcClient, err = rpc.DialTCP("tcp", net.JoinHostPort("127.0.0.1", portNFS), false)
		if !errors.Is(err, syscall.EADDRINUSE) {
			break
		}
	}
	if err != nil {
		t.Fatalf("rpc.DialTCP: %v", err)
	}
	defer rpcClient.Close()
	mounter := nfsc.Mount{Client: rpcClient}
	target, err := mounter.Mount(nonce, rpc.AuthNull)
	if err != nil {
		t.Fatalf("mounter.Mount: %v", err)
	}
	defer func() {
		_ = mounter.Unmount()
	}()

	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "/home/user/hello.txt", want: "hello from home"},
		{path: "/b/bin/ls", want: "binary-ls"},
	} {
		f, err := target.Open(tc.path)
		if err != nil {
			t.Fatalf("target.Open(%q): %v", tc.path, err)
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("ReadAll(%q): %v", tc.path, err)
		}
		if string(data) != tc.want {
			t.Fatalf("read %q = %q, want %q", tc.path, data, tc.want)
		}
	}

	ents, err := target.ReadDirPlus("/")
	if err != nil {
		t.Fatalf("ReadDirPlus(/): %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)

	switch mode {
	case "safe":
		if want := []string{"b", "home"}; !slices.Equal(names, want) {
			t.Fatalf("safe ReadDirPlus(/) = %v, want %v", names, want)
		}
		for _, bad := range []string{"/etc", "/etc/shadow", "/b/other"} {
			if _, _, err := target.Lookup(bad); err == nil {
				t.Fatalf("safe Lookup(%q) succeeded, want error", bad)
			}
		}
		if _, err := target.Mkdir("/escaped", 0o755); err == nil {
			t.Fatalf("safe Mkdir(/escaped) succeeded, want error")
		}
		fmt.Println("DAEMON_NFS_SAFE_OK")
	case "unsafe":
		if want := []string{"b", "etc", "home"}; !slices.Equal(names, want) {
			t.Fatalf("unsafe ReadDirPlus(/) = %v, want %v", names, want)
		}
		f, err := target.Open("/etc/shadow")
		if err != nil {
			t.Fatalf("unsafe Open(/etc/shadow): %v", err)
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("unsafe ReadAll(/etc/shadow): %v", err)
		}
		if string(data) != "root-secret" {
			t.Fatalf("unsafe read /etc/shadow = %q, want %q", data, "root-secret")
		}
		fmt.Println("DAEMON_NFS_UNSAFE_OK")
	default:
		t.Fatalf("unknown mode %q", mode)
	}
}

func TestDaemonEndToEndNFSNamespace(t *testing.T) {
	host, port, kf := startTestCPUD(t)

	for _, tc := range []struct {
		name         string
		unsafeExport bool
		mode         string
		wantToken    string
	}{
		{name: "safe_default", unsafeExport: false, mode: "safe", wantToken: "DAEMON_NFS_SAFE_OK"},
		{name: "unsafe_export", unsafeExport: true, mode: "unsafe", wantToken: "DAEMON_NFS_UNSAFE_OK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := setupDaemonExportTree(t)
			c := client.Command(host, "-test.run=TestDaemonNFSNamespaceHelper", "-test.v", "--", "run")
			if err := c.SetOptions(
				client.WithPrivateKeyFile(kf),
				client.WithPort(port),
				client.WithRoot(rootDir),
				client.WithNameSpace("/home:/bin=/b/bin"),
				client.With9P(false),
				client.WithUnsafeExport(tc.unsafeExport),
			); err != nil {
				t.Fatalf("SetOptions: %v", err)
			}
			stdout, stderr := newCloseBuffer(), newCloseBuffer()
			c.Stdin = bytes.NewReader(nil)
			c.Stdout, c.Stderr = stdout, stderr
			c.Env = append(os.Environ(), "GO_WANT_DAEMON_NFS_HELPER="+tc.mode)
			if err := c.Dial(); err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Close()

			srvFn, nfsmount, err := client.SrvNFS(c, "", rootDir)
			if err != nil {
				t.Fatalf("SrvNFS: %v", err)
			}
			go func() {
				_ = srvFn()
			}()
			jfstab := client.JoinFSTab(nfsmount, c.FSTab)
			c.Env = append(c.Env, "CPU_FSTAB="+jfstab, "LC_GLENDA_CPU_FSTAB="+jfstab)

			if err := c.Run(); err != nil {
				t.Fatalf("Run: %v (stdout=%q, stderr=%q)", err, stdout.String(), stderr.String())
			}
			if got := stdout.String(); !strings.Contains(got, tc.wantToken) {
				t.Fatalf("stdout = %q (stderr = %q), want %q", got, stderr.String(), tc.wantToken)
			}
		})
	}
}
