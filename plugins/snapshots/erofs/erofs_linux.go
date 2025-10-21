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

	"github.com/containerd/continuity/fs"
	"github.com/containerd/log"
	"github.com/containerd/plugin"
	"golang.org/x/sys/unix"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/erofsutils"
)

// check if EROFS kernel filesystem is registered or not
func findErofs() bool {
	fs, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	return bytes.Contains(fs, []byte("\terofs\n"))
}

func checkCompatibility(root string) error {
	supportsDType, err := fs.SupportsDType(root)
	if err != nil {
		return err
	}
	if !supportsDType {
		return fmt.Errorf("%s does not support d_type. If the backing filesystem is xfs, please reformat with ftype=1 to enable d_type support", root)
	}

	if !findErofs() {
		return fmt.Errorf("EROFS unsupported, please `modprobe erofs`: %w", plugin.ErrSkipPlugin)
	}

	return nil
}

func setImmutable(path string, enable bool) error {
	//nolint:revive,staticcheck	// silence "don't use ALL_CAPS in Go names; use CamelCase"
	const (
		FS_IMMUTABLE_FL = 0x10
	)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open: %w", err)
	}
	defer f.Close()

	oldattr, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return fmt.Errorf("error getting inode flags: %w", err)
	}
	newattr := oldattr | FS_IMMUTABLE_FL
	if !enable {
		newattr ^= FS_IMMUTABLE_FL
	}
	if newattr == oldattr {
		return nil
	}
	return unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, newattr)
}

func cleanupUpper(upper string) error {
	if err := mount.UnmountAll(upper, 0); err != nil {
		return fmt.Errorf("failed to unmount EROFS upper path: %w", err)
	}
	return nil
}

func convertDirToErofs(ctx context.Context, dest string, src string) error {
	if _, err := os.Stat(dest); err == nil {
		log.G(ctx).WithField("dest", dest).Warn("Skipping erofs conversion, already exists")
		return nil
	}
	return erofsutils.ConvertErofs(ctx, dest, src, nil)
}

func upperDirectoryPermission(child string, parent string) error {
	childStat, err := os.Stat(child)
	if err != nil {
		return err
	}
	parentStat, err := os.Stat(parent)
	if err != nil {
		return err
	}

	return os.Chmod(child, parentStat.Mode().Perm()&childStat.Mode().Perm())
}

// checkDmveritySupport checks if dm-verity is supported on this system
func checkDmveritySupport() error {
	supported, err := dmverity.IsSupported()
	if err != nil {
		return fmt.Errorf("failed to check dmverity support: %w", err)
	}
	if !supported {
		return fmt.Errorf("dmverity is not supported on this system")
	}
	return nil
}

// isLayerWithDmverity checks if a layer has dm-verity metadata
func (s *snapshotter) isLayerWithDmverity(id string) bool {
	_, err := os.Stat(s.rootHashPath(id))
	return err == nil
}

// formatDmverityLayer formats a committed EROFS layer with dm-verity hash tree
func (s *snapshotter) formatDmverityLayer(ctx context.Context, id string) error {
	// Skip if already formatted
	if s.isLayerWithDmverity(id) {
		log.G(ctx).WithField("id", id).Debug("Layer already has dm-verity, skipping format")
		return nil
	}

	layerBlob := s.layerBlobPath(id)
	fileinfo, err := os.Stat(layerBlob)
	if err != nil {
		return fmt.Errorf("failed to stat layer blob: %w", err)
	}

	// Open file for truncating
	f, err := os.OpenFile(layerBlob, os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("failed to open layer blob for truncating: %w", err)
	}
	defer f.Close()

	fileSize := fileinfo.Size()
	// Truncate the file to double its size to provide space for the dm-verity hash tree.
	// The hash tree will never exceed the original data size.
	// Most filesystems use sparse allocation, so unused space doesn't consume disk.
	if err := f.Truncate(fileSize * 2); err != nil {
		return fmt.Errorf("failed to truncate layer blob: %w", err)
	}

	opts := dmverity.DefaultDmverityOptions()
	opts.HashOffset = uint64(fileSize)
	opts.RootHashFile = s.rootHashPath(id)

	_, err = dmverity.Format(layerBlob, layerBlob, &opts)
	if err != nil {
		return fmt.Errorf("failed to format dmverity: %w", err)
	}

	log.G(ctx).WithField("id", id).WithField("size", fileSize).Info("Successfully formatted dm-verity layer")
	return nil
}
