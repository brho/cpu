// Copyright 2026 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build unix

package client

import (
	"github.com/hugelgupf/p9/p9"
	"golang.org/x/sys/unix"
)

const (
	// Unix-only 9P2000.L wire open flags (Linux include/net/9p/9p.h).
	p9DotlNonblock  p9.OpenFlags = 0o0004000
	p9DotlDirectory p9.OpenFlags = 0o0200000
	p9DotlNofollow  p9.OpenFlags = 0o0400000
)

func translatePlatformOpenFlags(mode p9.OpenFlags) int {
	// Always set O_NOCTTY so a 9P server never acquires a controlling tty.
	flags := unix.O_NOCTTY
	if mode&p9DotlNonblock != 0 {
		flags |= unix.O_NONBLOCK
	}
	if mode&p9DotlDirectory != 0 {
		flags |= unix.O_DIRECTORY
	}
	if mode&p9DotlNofollow != 0 {
		flags |= unix.O_NOFOLLOW
	}
	return flags
}
