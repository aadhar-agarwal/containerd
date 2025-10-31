//go:build linux

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

package erofs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/log/logtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/containerd/containerd/v2/internal/dmverity"
)

// TestGetDmverityOptions tests the block size configuration
func TestGetDmverityOptions(t *testing.T) {
	// tar-index mode uses 512-byte blocks
	opts := (&erofsDiff{enableTarIndex: true, enableDmverity: true}).getDmverityOptions()
	assert.Equal(t, uint32(512), opts.DataBlockSize)
	assert.Equal(t, uint32(512), opts.HashBlockSize)

	// regular mode uses 4096-byte blocks
	opts = (&erofsDiff{enableTarIndex: false, enableDmverity: true}).getDmverityOptions()
	assert.Equal(t, uint32(4096), opts.DataBlockSize)
	assert.Equal(t, uint32(4096), opts.HashBlockSize)
}

// TestFormatDmverityLayer tests the layer formatting logic
func TestFormatDmverityLayer(t *testing.T) {
	supported, err := dmverity.IsSupported()
	if err != nil || !supported {
		t.Skip("dm-verity is not supported on this system")
	}

	ctx := logtest.WithT(context.Background(), t)
	tmpDir := t.TempDir()
	d := &erofsDiff{enableDmverity: true}

	// Test basic formatting and metadata creation
	layerPath := filepath.Join(tmpDir, "layer.erofs")
	require.NoError(t, os.WriteFile(layerPath, make([]byte, 8192), 0644))
	require.NoError(t, d.formatDmverityLayer(ctx, layerPath))

	metadata, err := dmverity.ParseMetadata(layerPath)
	require.NoError(t, err)
	assert.NotEmpty(t, metadata.RootHash)
	assert.Greater(t, metadata.HashOffset, uint64(0))

	// Test idempotency
	origHash := metadata.RootHash
	require.NoError(t, d.formatDmverityLayer(ctx, layerPath))
	metadata, _ = dmverity.ParseMetadata(layerPath)
	assert.Equal(t, origHash, metadata.RootHash)

	// Test 4096-byte block alignment (regular mode)
	layerPath2 := filepath.Join(tmpDir, "layer-4k.erofs")
	require.NoError(t, os.WriteFile(layerPath2, make([]byte, 5000), 0644))
	d.enableTarIndex = false
	require.NoError(t, d.formatDmverityLayer(ctx, layerPath2))
	metadata, _ = dmverity.ParseMetadata(layerPath2)
	assert.Equal(t, uint64(8192), metadata.HashOffset) // 5000 bytes rounds up to 8192

	// Test 512-byte block alignment (tar-index mode)
	layerPath3 := filepath.Join(tmpDir, "layer-512.erofs")
	require.NoError(t, os.WriteFile(layerPath3, make([]byte, 1024), 0644))
	d.enableTarIndex = true
	require.NoError(t, d.formatDmverityLayer(ctx, layerPath3))
	metadata, _ = dmverity.ParseMetadata(layerPath3)
	assert.Equal(t, uint64(1024), metadata.HashOffset) // 1024 is already aligned to 512

	// Test error handling
	err = d.formatDmverityLayer(ctx, filepath.Join(tmpDir, "missing.erofs"))
	require.Error(t, err)
}
