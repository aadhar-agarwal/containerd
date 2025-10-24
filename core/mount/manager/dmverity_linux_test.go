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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/containerd/containerd/v2/core/mount"
)

// TestDmverityTransformer tests the core transformer functionality
func TestDmverityTransformer(t *testing.T) {
	ctx := logtest.WithT(context.Background(), t)
	tr := dmverityTransformer{}

	// Test missing roothash
	t.Run("requires roothash", func(t *testing.T) {
		m := mount.Mount{
			Source:  "/path/to/layer.erofs",
			Type:    "erofs",
			Options: []string{"ro"},
		}
		_, err := tr.Transform(ctx, m, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dmverity requires roothash option")
	})

	// Test missing hash-offset
	t.Run("requires hash-offset", func(t *testing.T) {
		m := mount.Mount{
			Source: "/path/to/layer.erofs",
			Type:   "erofs",
			Options: []string{
				"ro",
				"X-containerd.dmverity.roothash=abc123def456789012345678901234567890123456789012345678901234",
			},
		}
		_, err := tr.Transform(ctx, m, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dmverity requires hash-offset option")
	})

	// Test invalid option format
	t.Run("validates option format", func(t *testing.T) {
		m := mount.Mount{
			Source:  "/path/to/layer.erofs",
			Type:    "erofs",
			Options: []string{"ro", "X-containerd.dmverity.invalid-format"},
		}
		_, err := tr.Transform(ctx, m, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid dmverity option")
	})

	// Test unknown dmverity option
	t.Run("rejects unknown dmverity options", func(t *testing.T) {
		m := mount.Mount{
			Source: "/path/to/layer.erofs",
			Type:   "erofs",
			Options: []string{
				"ro",
				"X-containerd.dmverity.unknown=value",
			},
		}
		_, err := tr.Transform(ctx, m, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown dmverity option")
	})

	// Test invalid hash-offset value
	t.Run("validates hash-offset format", func(t *testing.T) {
		m := mount.Mount{
			Source: "/path/to/layer.erofs",
			Type:   "erofs",
			Options: []string{
				"ro",
				"X-containerd.dmverity.roothash=abc123def456789012345678901234567890123456789012345678901234",
				"X-containerd.dmverity.hash-offset=not-a-number",
			},
		}
		_, err := tr.Transform(ctx, m, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid hash-offset value")
	})

	// Test no-superblock flag
	t.Run("parses no-superblock flag", func(t *testing.T) {
		m := mount.Mount{
			Source: "/path/to/layer.erofs",
			Type:   "erofs",
			Options: []string{
				"ro",
				"X-containerd.dmverity.roothash=abc123def456789012345678901234567890123456789012345678901234",
				"X-containerd.dmverity.hash-offset=1048576",
				"X-containerd.dmverity.no-superblock",
			},
		}
		_, err := tr.Transform(ctx, m, nil)
		// Will fail at device creation, but parsing should succeed
		if err != nil {
			// Should not be a parsing error
			assert.NotContains(t, err.Error(), "invalid dmverity option")
			assert.NotContains(t, err.Error(), "requires roothash")
			assert.NotContains(t, err.Error(), "requires hash-offset")
		}
	})

	// Test device name extraction
	t.Run("extracts device name from options", func(t *testing.T) {
		m := mount.Mount{
			Source: "/path/to/layer.erofs",
			Type:   "erofs",
			Options: []string{
				"ro",
				"X-containerd.dmverity.roothash=abc123def456789012345678901234567890123456789012345678901234",
				"X-containerd.dmverity.hash-offset=1048576",
				"X-containerd.dmverity.device-name=test-device",
			},
		}
		_, err := tr.Transform(ctx, m, nil)
		// Will fail at device creation, but parsing should succeed
		if err != nil {
			// Should not be a parsing error
			assert.NotContains(t, err.Error(), "invalid dmverity option")
			assert.NotContains(t, err.Error(), "requires roothash")
		}
	})
}
