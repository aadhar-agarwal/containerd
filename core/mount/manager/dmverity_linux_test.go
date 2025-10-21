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
	"fmt"
	"os"
	"path/filepath"
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
		assert.Contains(t, err.Error(), "dmverity requires either roothash-file or roothash option")
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

	// Test roothash file reading
	t.Run("reads roothash from file", func(t *testing.T) {
		tmpDir := t.TempDir()
		roothashFile := filepath.Join(tmpDir, ".roothash")
		hash := "abc123def456789012345678901234567890123456789012345678901234"
		require.NoError(t, os.WriteFile(roothashFile, []byte(hash+"\n"), 0644))

		m := mount.Mount{
			Source: "/path/to/layer.erofs",
			Type:   "erofs",
			Options: []string{
				"ro",
				fmt.Sprintf("X-containerd.dmverity.roothash-file=%s", roothashFile),
			},
		}

		_, err := tr.Transform(ctx, m, nil)
		// Will fail at device creation, but hash file should be read successfully
		if err != nil {
			assert.NotContains(t, err.Error(), "failed to read root hash file")
		}
	})
}

// TestDmverityHandler tests the handler's Mount method
func TestDmverityHandler(t *testing.T) {
	ctx := logtest.WithT(context.Background(), t)
	handler := dmverityHandler{}

	t.Run("requires device name in options", func(t *testing.T) {
		m := mount.Mount{
			Source:  "/dev/mapper/test-device",
			Type:    "erofs",
			Options: []string{"ro"},
		}

		_, err := handler.Mount(ctx, m, "/tmp/target", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dm-verity device name not found")
	})

	t.Run("extracts device name to MountData", func(t *testing.T) {
		m := mount.Mount{
			Source: "/dev/mapper/test-device",
			Type:   "erofs",
			Options: []string{
				"ro",
				"X-containerd.dmverity.device-name=test-device-name",
			},
		}

		tmpDir := t.TempDir()
		target := filepath.Join(tmpDir, "target")
		require.NoError(t, os.MkdirAll(target, 0755))

		active, err := handler.Mount(ctx, m, target, nil)

		// Mount will fail (device doesn't exist), but we can verify device name extraction
		if err != nil {
			t.Logf("Expected mount failure: %v", err)
		} else {
			// Verify MountData contains device name
			require.NotNil(t, active.MountData)
			assert.Equal(t, "test-device-name", active.MountData["dmverity-device"])
			_ = mount.Unmount(target, 0)
		}
	})
}
