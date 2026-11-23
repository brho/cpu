// Copyright 2026 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package client

import (
	"errors"
	"os"
	"testing"

	"github.com/hugelgupf/p9/p9"
)

func TestNewCPU9PEmptyRoot(t *testing.T) {
	if _, err := NewCPU9P("").Attach(); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf(`NewCPU9P("").Attach() = %v, want os.ErrInvalid`, err)
	}
}

func TestTranslateOpenFlags(t *testing.T) {
	// P9_DOTL_DIRECT (0o40000) collides with O_DIRECTORY on linux/arm64,
	// and P9_DOTL_CREATE (0o100) collides with O_ASYNC on darwin/freebsd.
	const foreignBits = p9.OpenFlags(0o0040000 | 0o0000100)
	base := translatePlatformOpenFlags(0)
	got := translateOpenFlags(p9.WriteOnly | p9DotlAppend | p9DotlTrunc | p9DotlSync | foreignBits)
	want := p9.OpenFlags(os.O_WRONLY | os.O_APPEND | os.O_TRUNC | os.O_SYNC | base)
	if got != want {
		t.Fatalf("translateOpenFlags = %#x, want %#x", got, want)
	}

	gotDSync := translateOpenFlags(p9.ReadWrite | p9DotlDSync)
	wantDSync := p9.OpenFlags(os.O_RDWR | os.O_SYNC | base)
	if gotDSync != wantDSync {
		t.Fatalf("translateOpenFlags(DSync) = %#x, want %#x", gotDSync, wantDSync)
	}
}
