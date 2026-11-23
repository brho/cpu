package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
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

	"github.com/gliderlabs/ssh"
	"github.com/hugelgupf/p9/p9"
	config "github.com/kevinburke/ssh_config"
	"github.com/u-root/cpu/client"
	"github.com/willscott/go-nfs-client/nfs"
	"github.com/willscott/go-nfs-client/nfs/rpc"
	xssh "golang.org/x/crypto/ssh"
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

// Why %s and not %d?
// https://github.com/kevinburke/ssh_config/issues/2
// ssh_config does not do any of the % stuff yet.
// So we have to rewrite this with the full path.
const sshConfig = `
Host server
	HostName localhost
	Port 2222
	User root
	IdentityFile %s/server
`

func genTestSSHKey(t *testing.T) (privPEM, pubAuth []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	block, err := xssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	sshPub, err := xssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return pem.EncodeToMemory(block), xssh.MarshalAuthorizedKey(sshPub)
}

func gendotssh(t *testing.T, dir string) string {
	t.Helper()
	dotssh := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(dotssh, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dotssh, err)
	}

	clientPriv, clientPub := genTestSSHKey(t)
	hostPriv, _ := genTestSSHKey(t)

	// https://github.com/kevinburke/ssh_config/issues/2
	hackconfig := fmt.Sprintf(sshConfig, dotssh)
	for _, f := range []struct {
		name string
		val  []byte
		mode os.FileMode
	}{
		{name: "config", val: []byte(hackconfig), mode: 0o644},
		{name: "hostkey", val: hostPriv, mode: 0o600},
		{name: "server", val: clientPriv, mode: 0o600},
		{name: "server.pub", val: clientPub, mode: 0o644},
	} {
		p := filepath.Join(dotssh, f.name)
		if err := os.WriteFile(p, f.val, f.mode); err != nil {
			t.Fatalf("WriteFile(%q): %v", p, err)
		}
	}
	return hackconfig
}

func serveTestSSH(t *testing.T, s *ssh.Server, ln net.Listener) {
	t.Helper()
	// gliderlabs/ssh does not wait for active session handlers on Close,
	// so gate and track s.Handler under mu/wg to drain before teardown.
	var (
		mu     sync.Mutex
		closed bool
		wg     sync.WaitGroup
	)
	origHandler := s.Handler
	s.Handler = func(sess ssh.Session) {
		mu.Lock()
		if closed {
			mu.Unlock()
			return
		}
		wg.Add(1)
		mu.Unlock()
		defer wg.Done()
		origHandler(sess)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, ssh.ErrServerClosed) {
			t.Errorf("s.Serve(): %v != nil", err)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = s.Close()
		mu.Lock()
		closed = true
		mu.Unlock()
		wg.Wait()
	})
}

// Now the fun begins. We have to be a demon.
func TestDaemonSession(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skipf("Skipping as we are not root")
	}

	setTestVerbose(t)
	prevProcs := runtime.GOMAXPROCS(1)
	client.SetVerbose(t.Logf)
	t.Cleanup(func() {
		client.SetVerbose(func(string, ...any) {})
		runtime.GOMAXPROCS(prevProcs)
	})

	d := t.TempDir()
	t.Logf("tempdir is %q", d)
	if err := os.Setenv("HOME", d); err != nil {
		t.Fatalf(`os.Setenv("HOME", %s): %v != nil`, d, err)
	}
	dotSSH := filepath.Join(d, ".ssh")
	hackconfig := gendotssh(t, d)

	pubKey := filepath.Join(dotSSH, "server.pub")
	s, err := New(pubKey, "", os.Args[0])
	if err != nil {
		t.Fatalf("New(%q, %q, %q): %v != nil", pubKey, "", os.Args[0], err)
	}

	ln, err := net.Listen("tcp", "")
	if err != nil {
		t.Fatalf("s.Listen(): %v != nil", err)
	}
	t.Logf("Listening on %v", ln.Addr())
	// this is a racy test.
	// The ssh package really ought to allow you to accept
	// on a socket and then call with that socket. This would be
	// more in line with bsd sockets which let you write a server
	// and client in line, e.g.
	// socket/bind/listen/connect/accept
	// oh well.
	serveTestSSH(t, s, ln)
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
	setTestVerbose(t)

	d := t.TempDir()
	if err := os.Setenv("HOME", d); err != nil {
		t.Fatalf(`os.Setenv("HOME", %s): %v != nil`, d, err)
	}
	hackconfig := gendotssh(t, d)

	s, err := New(filepath.Join(d, ".ssh", "server.pub"), filepath.Join(d, ".ssh", "hostkey"), os.Args[0])
	if err != nil {
		t.Fatalf(`New(%q, %q, %q): %v != nil`, filepath.Join(d, ".ssh", "server.pub"), filepath.Join(d, ".ssh", "hostkey"), os.Args[0], err)
	}

	ln, err := net.Listen("tcp", "")
	if err != nil {
		t.Fatalf(`net.Listen("", ""): %v != nil`, err)
	}
	t.Logf("Listening on %v", ln.Addr())
	// this is a racy test.
	// The ssh package really ought to allow you to accept
	// on a socket and then call with that socket. This would be
	// more in line with bsd sockets which let you write a server
	// and client in line, e.g.
	// socket/bind/listen/connect/accept
	// oh well.
	serveTestSSH(t, s, ln)
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
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
	for rel, content := range map[string]string{
		"home/user/hello.txt": "hello from home",
		"b/bin/ls":            "binary-ls",
		"b/other/secret":      "other-secret",
		"etc/shadow":          "root-secret",
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("MkdirAll(%q): %v", filepath.Dir(p), err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%q): %v", rel, err)
		}
	}
	return root
}

func startTestCPUD(t *testing.T) (host, port, kf string) {
	t.Helper()
	setTestVerbose(t)
	prevUnshare := unshareMountNS
	unshareMountNS = false
	t.Cleanup(func() {
		unshareMountNS = prevUnshare
	})

	d := t.TempDir()
	t.Setenv("HOME", d)
	gendotssh(t, d)
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
	serveTestSSH(t, s, ln)
	host, port, err = net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	return host, port, kf
}

// preserveUmask restores the process umask cleared by localfs.Attach.
func preserveUmask(t *testing.T) {
	t.Helper()
	old := unix.Umask(0)
	unix.Umask(old)
	t.Cleanup(func() {
		unix.Umask(old)
	})
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

type daemonExportClient interface {
	readFile(rel string) string
	listRoot() []string
	lookup(rel string) error
	mkdirRoot(name string) error
}

func verifyDaemonExport(t *testing.T, mode, tokenPrefix string, exp daemonExportClient) {
	t.Helper()
	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "home/user/hello.txt", want: "hello from home"},
		{path: "b/bin/ls", want: "binary-ls"},
	} {
		if got := exp.readFile(tc.path); got != tc.want {
			t.Fatalf("read %q = %q, want %q", tc.path, got, tc.want)
		}
	}

	names := exp.listRoot()
	switch mode {
	case "safe":
		if want := []string{"b", "home"}; !slices.Equal(names, want) {
			t.Fatalf("safe root listing = %v, want %v", names, want)
		}
		for _, bad := range []string{"etc", "etc/shadow", "b/other"} {
			if err := exp.lookup(bad); err == nil {
				t.Fatalf("safe lookup(%q) succeeded, want error", bad)
			}
		}
		if err := exp.mkdirRoot("escaped"); err == nil {
			t.Fatalf("safe mkdir(/escaped) succeeded, want error")
		}
		fmt.Println(tokenPrefix + "_SAFE_OK")
	case "unsafe":
		if want := []string{"b", "etc", "home"}; !slices.Equal(names, want) {
			t.Fatalf("unsafe root listing = %v, want %v", names, want)
		}
		if got := exp.readFile("etc/shadow"); got != "root-secret" {
			t.Fatalf("unsafe read etc/shadow = %q, want %q", got, "root-secret")
		}
		fmt.Println(tokenPrefix + "_UNSAFE_OK")
	default:
		t.Fatalf("unknown mode %q", mode)
	}
}

type p9DaemonClient struct {
	t    *testing.T
	root p9.File
}

func (c p9DaemonClient) readFile(rel string) string {
	c.t.Helper()
	parts := strings.Split(rel, "/")
	_, f, err := c.root.Walk(parts)
	if err != nil {
		c.t.Fatalf("Walk(%v): %v", parts, err)
	}
	defer f.Close()
	if _, _, err := f.Open(p9.ReadOnly); err != nil {
		c.t.Fatalf("Open(%v): %v", parts, err)
	}
	buf := make([]byte, 128)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		c.t.Fatalf("ReadAt(%v): %v", parts, err)
	}
	return string(buf[:n])
}

func (c p9DaemonClient) listRoot() []string {
	c.t.Helper()
	_, rootCopy, err := c.root.Walk(nil)
	if err != nil {
		c.t.Fatalf("Walk(nil): %v", err)
	}
	defer rootCopy.Close()
	if _, _, err := rootCopy.Open(p9.ReadOnly); err != nil {
		c.t.Fatalf("rootCopy.Open: %v", err)
	}
	ents, err := rootCopy.Readdir(0, 4096)
	if err != nil {
		c.t.Fatalf("rootCopy.Readdir: %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name)
	}
	slices.Sort(names)
	return names
}

func (c p9DaemonClient) lookup(rel string) error {
	_, f, err := c.root.Walk(strings.Split(rel, "/"))
	if err == nil {
		_ = f.Close()
	}
	return err
}

func (c p9DaemonClient) mkdirRoot(name string) error {
	_, err := c.root.Mkdir(name, 0o755, p9.NoUID, p9.NoGID)
	return err
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

	verifyDaemonExport(t, mode, "DAEMON_9P", p9DaemonClient{t: t, root: root})
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

type nfsDaemonClient struct {
	t      *testing.T
	target *nfs.Target
}

func (c nfsDaemonClient) readFile(rel string) string {
	c.t.Helper()
	f, err := c.target.Open("/" + rel)
	if err != nil {
		c.t.Fatalf("target.Open(%q): %v", "/"+rel, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		c.t.Fatalf("ReadAll(%q): %v", "/"+rel, err)
	}
	return string(data)
}

func (c nfsDaemonClient) listRoot() []string {
	c.t.Helper()
	ents, err := c.target.ReadDirPlus("/")
	if err != nil {
		c.t.Fatalf("ReadDirPlus(/): %v", err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func (c nfsDaemonClient) lookup(rel string) error {
	_, _, err := c.target.Lookup("/" + rel)
	return err
}

func (c nfsDaemonClient) mkdirRoot(name string) error {
	_, err := c.target.Mkdir("/"+name, 0o755)
	return err
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

	// go-nfs-client binds a random local port; retry on collisions.
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
	mounter := nfs.Mount{Client: rpcClient}
	target, err := mounter.Mount(nonce, rpc.AuthNull)
	if err != nil {
		t.Fatalf("mounter.Mount: %v", err)
	}
	defer func() {
		_ = mounter.Unmount()
	}()

	verifyDaemonExport(t, mode, "DAEMON_NFS", nfsDaemonClient{t: t, target: target})
}

func runDaemonNamespaceTest(t *testing.T, helperName, envKey string, use9P bool, tokenPrefix string) {
	t.Helper()
	if use9P {
		preserveUmask(t)
	}

	for _, tc := range []struct {
		name         string
		unsafeExport bool
		mode         string
		wantToken    string
	}{
		{name: "safe_default", unsafeExport: false, mode: "safe", wantToken: tokenPrefix + "_SAFE_OK"},
		{name: "unsafe_export", unsafeExport: true, mode: "unsafe", wantToken: tokenPrefix + "_UNSAFE_OK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rootDir := setupDaemonExportTree(t)

			// Register srvDone wait before startTestCPUD so LIFO
			// cleanup closes cpud (unblocking nfs.Serve), waits
			// for srvFn to exit, and only then removes rootDir.
			var srvDone chan struct{}
			if !use9P {
				t.Cleanup(func() {
					if srvDone != nil {
						<-srvDone
					}
				})
			}

			// Start an isolated cpud per subtest so each gets its
			// own ForwardedTCPHandler for "127.0.0.1:0".
			host, port, kf := startTestCPUD(t)

			c := client.Command(host, "-test.run="+helperName, "-test.v")
			if err := c.SetOptions(
				client.WithPrivateKeyFile(kf),
				client.WithPort(port),
				client.WithRoot(rootDir),
				client.WithNameSpace("/home:/bin=/b/bin"),
				client.With9P(use9P),
				client.WithUnsafeExport(tc.unsafeExport),
			); err != nil {
				t.Fatalf("SetOptions: %v", err)
			}
			stdout, stderr := newCloseBuffer(), newCloseBuffer()
			c.Stdin = bytes.NewReader(nil)
			c.Stdout, c.Stderr = stdout, stderr
			c.Env = append(os.Environ(), envKey+"="+tc.mode)
			if err := c.Dial(); err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Close()

			if !use9P {
				srvFn, nfsmount, err := client.SrvNFS(c, "", rootDir)
				if err != nil {
					t.Fatalf("SrvNFS: %v", err)
				}
				srvDone = make(chan struct{})
				go func() {
					defer close(srvDone)
					_ = srvFn()
				}()
				c.Env = append(c.Env, "CPU_FSTAB="+nfsmount)
			}

			if err := c.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}
			if err := c.Wait(); err != nil {
				t.Fatalf("Wait: %v (stdout=%q, stderr=%q)", err, stdout.String(), stderr.String())
			}
			if got := stdout.String(); !strings.Contains(got, tc.wantToken) {
				t.Fatalf("stdout = %q (stderr = %q), want %q", got, stderr.String(), tc.wantToken)
			}
		})
	}
}

func TestDaemonEndToEnd9PNamespace(t *testing.T) {
	runDaemonNamespaceTest(t, "TestDaemon9PNamespaceHelper", "GO_WANT_DAEMON_9P_HELPER", true, "DAEMON_9P")
}

func TestDaemonEndToEndNFSNamespace(t *testing.T) {
	runDaemonNamespaceTest(t, "TestDaemonNFSNamespaceHelper", "GO_WANT_DAEMON_NFS_HELPER", false, "DAEMON_NFS")
}
