// Copyright 2018-2022 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"flag"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/u-root/cpu/session"
)

func setTestVerbose(t *testing.T) {
	t.Helper()
	prev := v
	v = t.Logf
	t.Cleanup(func() { v = prev })
}

func TestNewServer(t *testing.T) {
	s, err := New("key.pub", "", os.Args[0])
	if err != nil {
		t.Fatalf(`New("key.pub", "", %q): %v != nil`, os.Args[0], err)
	}
	if s.PublicKeyHandler == nil {
		t.Fatalf(`New("key.pub", "", %q) returns a server without a public key handler`, os.Args[0])
	}
	t.Logf("New server: %v", s)
}

func TestNewServerWithoutKey(t *testing.T) {
	s, err := New("", "", os.Args[0])
	if err != nil {
		t.Fatalf(`New("", "", %q): %v != nil`, os.Args[0], err)
	}
	if s.PublicKeyHandler != nil {
		t.Fatalf(`New("", "", %q) returns a server with a public key handler`, os.Args[0])
	}
	t.Logf("New server: %v", s)
}

func TestRemoteNoNameSpace(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skipf("Skipping as we are not root")
	}
	setTestVerbose(t)
	s := session.New("", "date")
	o, e := &bytes.Buffer{}, &bytes.Buffer{}
	s.Stdin, s.Stdout, s.Stderr = nil, o, e
	if err := s.Run(); err != nil {
		t.Fatalf(`s.Run("", "date"): %v != nil`, err)
	}
	t.Logf("%q %q", o, e)
	if len(o.String()) == 0 {
		t.Errorf("no command output: \"\" != non-zero-length string")
	}
	if e.String() != "" {
		t.Errorf("command error: %q != %q", e.String(), "")
	}
}

func TestDaemonStart(t *testing.T) {
	setTestVerbose(t)
	s, err := New("", "", os.Args[0])
	if err != nil {
		t.Fatalf(`New("", "", %q): %v != nil`, os.Args[0], err)
	}

	ln, err := net.Listen("tcp", "")
	if err != nil {
		t.Fatalf("net.Listen(): %v != nil", err)
	}
	t.Logf("Listening on %v", ln.Addr())
	// this is a racy test.
	go func() {
		time.Sleep(5 * time.Second)
		s.Close()
	}()

	if err := s.Serve(ln); err != ssh.ErrServerClosed {
		t.Fatalf("s.Daemon(): %v != %v", err, ssh.ErrServerClosed)
	}
	t.Logf("Daemon returns")
}

func TestDaemonConnectHelper(t *testing.T) {
	if _, ok := os.LookupEnv("GO_WANT_DAEMON_HELPER_PROCESS"); !ok {
		t.Logf("just a helper")
		return
	}
	t.Logf("As a helper, we are supposed to run %q", args)
	s := session.New(port9p, args[0], args[1:]...)
	// Step through the things a server is supposed to do with a session
	if err := s.Run(); err != nil {
		log.Fatalf("CPUD(as remote):%v", err)
	}
}

var (
	args   []string
	port9p string
)

func TestMain(m *testing.M) {
	// server.handler prepends -remote and client.Start prepends -port9p
	// before the test flags when re-execing the test binary.
	flag.Bool("remote", false, "remote helper process")
	flag.StringVar(&port9p, "port9p", "", "port9p on remote machine for 9p mount")
	// Strip out the args after --
	x := -1
	var osargs = os.Args
	for i := range os.Args {
		if x > 0 {
			args = os.Args[i:]
			break
		}
		if os.Args[i] == "--" {
			osargs = os.Args[:i]
			x = i
		}
	}
	os.Args = osargs
	// log.Printf("os.Args %v, args %v", os.Args, args)
	flag.Parse()
	os.Exit(m.Run())
}
