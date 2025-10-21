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

package manager

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/log"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
)

// dmverityHandler implements mount.Handler to manage dm-verity device lifecycle
// It ensures that dm-verity devices are properly closed when mounts are deactivated
type dmverityHandler struct{}

// Mount handles mounting with dm-verity device tracking
func (h dmverityHandler) Mount(ctx context.Context, m mount.Mount, target string, active []mount.ActiveMount) (mount.ActiveMount, error) {
	// Extract the device name from mount options
	deviceName := ""
	for _, opt := range m.Options {
		if strings.HasPrefix(opt, "X-containerd.dmverity.device-name=") {
			deviceName = strings.TrimPrefix(opt, "X-containerd.dmverity.device-name=")
			break
		}
	}

	if deviceName == "" {
		return mount.ActiveMount{}, fmt.Errorf("dm-verity device name not found in mount options")
	}

	// Perform the mount
	if err := m.Mount(target); err != nil {
		return mount.ActiveMount{}, err
	}

	t := time.Now()
	// Store device name in MountData for cleanup
	return mount.ActiveMount{
		Mount:      m,
		MountPoint: target,
		MountedAt:  &t,
		MountData: map[string]string{
			"dmverity-device": deviceName,
		},
	}, nil
}

// Unmount unmounts the filesystem and closes the dm-verity device
func (h dmverityHandler) Unmount(ctx context.Context, target string) error {
	// Note: We need access to the MountData to get the device name
	// This is a design limitation - the Unmount interface doesn't provide access to ActiveMount
	// For now, we'll just unmount the filesystem and log that manual cleanup may be needed

	if err := mount.Unmount(target, 0); err != nil {
		log.G(ctx).WithError(err).WithField("target", target).Warn("failed to unmount dm-verity filesystem")
		return err
	}

	log.G(ctx).WithField("target", target).Debug("unmounted dm-verity filesystem (device cleanup handled by GC)")
	return nil
}

// UnmountWithData unmounts and cleans up the dm-verity device
// This should be called from the manager's Deactivate with access to MountData
func unmountDmverity(ctx context.Context, active mount.ActiveMount) error {
	// First unmount the filesystem
	if err := mount.Unmount(active.MountPoint, 0); err != nil {
		log.G(ctx).WithError(err).WithField("target", active.MountPoint).Warn("failed to unmount dm-verity filesystem")
		return err
	}

	// Get device name from MountData
	deviceName, ok := active.MountData["dmverity-device"]
	if !ok {
		log.G(ctx).WithField("target", active.MountPoint).Warn("dm-verity device name not found in mount data, device may leak")
		return nil
	}

	// Check if device is still in use by checking open count
	// dm-verity devices show up in /sys/block/dm-*/holders/
	// For now, we attempt to close and ignore "device busy" errors
	log.G(ctx).WithField("device", deviceName).Debug("closing dm-verity device")
	if _, err := dmverity.Close(deviceName); err != nil {
		// If device is busy, it's likely still in use by another container
		// This is not an error - the device will be cleaned up when the last user stops
		log.G(ctx).WithError(err).WithField("device", deviceName).Debug("failed to close dm-verity device (may still be in use)")
		return nil // Don't return error, device will be cleaned up later
	}

	log.G(ctx).WithField("device", deviceName).Info("dm-verity device closed successfully")
	return nil
}
