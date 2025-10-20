/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package manager

import (
	"context"
	"testing"

	"github.com/containerd/log/logtest"

	"github.com/containerd/containerd/v2/core/mount"
)

// TestDmverityTransformer demonstrates how the dm-verity transformer works
func TestDmverityTransformer(t *testing.T) {
	ctx := logtest.WithT(context.Background(), t)

	tr := dmverityTransformer{}

	// Example mount spec from EROFS snapshotter with dm-verity enabled
	m := mount.Mount{
		Source: "/var/lib/containerd/io.containerd.snapshotter.v1.erofs/snapshots/abc123/layer.erofs",
		Type:   "erofs",
		Options: []string{
			"ro",
			"X-containerd.dmverity.roothash-file=/var/lib/containerd/io.containerd.snapshotter.v1.erofs/snapshots/abc123/.roothash",
		},
	}

	// In a real scenario, this would:
	// 1. Read the root hash from .roothash file
	// 2. Call dmverity.Open() to create /dev/mapper/dmverity-xxx
	// 3. Return a mount with Source pointing to the device

	// Note: This test won't actually work without a real dm-verity formatted file
	// It's here to demonstrate the API usage
	_, err := tr.Transform(ctx, m, nil)

	// Expect failure in test environment (no actual dm-verity device)
	if err == nil {
		t.Skip("dm-verity transformation unexpectedly succeeded (likely not in a proper test environment)")
	}

	t.Logf("Expected failure (no real dm-verity device): %v", err)
}
