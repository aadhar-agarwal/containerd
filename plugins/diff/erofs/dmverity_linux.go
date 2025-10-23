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
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/log"

	"github.com/containerd/containerd/v2/internal/dmverity"
)

// getDmverityOptions returns dm-verity options configured for this differ instance.
// The block size is determined by the differ's mode:
// - Tar index mode requires 512-byte blocks for proper alignment
// - Regular mode uses 4096-byte blocks (standard page size)
func (s *erofsDiff) getDmverityOptions() dmverity.DmverityOptions {
	opts := dmverity.DefaultDmverityOptions()

	// Tar index mode requires 512-byte block alignment because the tar archive
	// format uses 512-byte blocks, and EROFS tar index mode preserves this alignment
	if s.enableTarIndex {
		opts.DataBlockSize = 512
		opts.HashBlockSize = 512
	}
	// Regular mode uses the default 4096-byte blocks (standard page size)

	return opts
}

// formatDmverityLayer formats an EROFS layer with dm-verity hash tree
func (s *erofsDiff) formatDmverityLayer(ctx context.Context, layerBlobPath string) error {
	// Check if layer is already formatted by checking for metadata file
	metadataPath := layerBlobPath + ".metadata"
	if _, err := os.Stat(metadataPath); err == nil {
		log.G(ctx).WithField("path", layerBlobPath).Debug("Layer already formatted with dm-verity, skipping")
		return nil
	}

	// Get file info
	fileinfo, err := os.Stat(layerBlobPath)
	if err != nil {
		return fmt.Errorf("failed to stat layer blob: %w", err)
	}

	// Open file for truncating
	f, err := os.OpenFile(layerBlobPath, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open layer blob for truncating: %w", err)
	}
	defer f.Close()

	fileSize := fileinfo.Size()

	// Get dm-verity options configured for this differ
	opts := s.getDmverityOptions()

	// Calculate data blocks and hash offset aligned to block boundaries
	// dm-verity requires the hash area to start at a block-aligned offset
	blockSize := int64(opts.DataBlockSize)
	dataBlocks := (fileSize + blockSize - 1) / blockSize
	hashOffset := dataBlocks * blockSize

	// Truncate the file to provide space for the dm-verity hash tree.
	// The hash tree will never exceed the original data size.
	// Most filesystems use sparse allocation, so unused space doesn't consume disk.
	newSize := hashOffset * 2
	if err := f.Truncate(newSize); err != nil {
		return fmt.Errorf("failed to truncate layer blob: %w", err)
	}

	opts.DataBlocks = uint64(dataBlocks)
	opts.HashOffset = uint64(hashOffset)

	// Create root hash file path in the same directory
	rootHashPath := layerBlobPath + ".roothash"
	opts.RootHashFile = rootHashPath

	_, err = dmverity.Format(layerBlobPath, layerBlobPath, &opts)
	if err != nil {
		return fmt.Errorf("failed to format dm-verity device: %w", err)
	}

	// Read the root hash from the file
	rootHashBytes, err := os.ReadFile(rootHashPath)
	if err != nil {
		return fmt.Errorf("failed to read root hash file: %w", err)
	}
	rootHash := string(bytes.TrimSpace(rootHashBytes))

	// Store root hash in options for metadata persistence
	opts.RootHash = rootHash

	// Save complete dm-verity options as metadata for use by snapshotter and mount manager
	if err := dmverity.SaveMetadata(metadataPath, &opts); err != nil {
		return fmt.Errorf("failed to save metadata: %w", err)
	}

	log.G(ctx).WithFields(log.Fields{
		"path":         layerBlobPath,
		"size":         fileSize,
		"blockSize":    opts.DataBlockSize,
		"dataBlocks":   dataBlocks,
		"hashOffset":   hashOffset,
		"metadataPath": metadataPath,
	}).Info("Successfully formatted dm-verity layer")

	return nil
}

// rootHashPathFromLayer returns the root hash file path for a layer blob path
func rootHashPathFromLayer(layerBlobPath string) string {
	return layerBlobPath + ".roothash"
}

// dmverityDeviceNameFromLayer returns the dm-verity device name for a layer blob
func dmverityDeviceNameFromLayer(layerBlobPath string) string {
	// Extract the snapshot ID from the path
	// Path format: /path/to/snapshots/<id>/layer.erofs
	dir := filepath.Dir(layerBlobPath)
	id := filepath.Base(dir)
	return fmt.Sprintf("containerd-erofs-%s", id)
}
