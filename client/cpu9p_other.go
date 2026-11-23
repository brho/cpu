// Copyright 2026 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !unix

package client

import "github.com/hugelgupf/p9/p9"

func translatePlatformOpenFlags(_ p9.OpenFlags) int {
	return 0
}
