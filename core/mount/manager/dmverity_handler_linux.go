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
	"os"
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
	// Extract the device name from mount options and filter it out
	deviceName := ""
	var filteredOptions []string
	for _, opt := range m.Options {
		if strings.HasPrefix(opt, "X-containerd.dmverity.device-name=") {
			deviceName = strings.TrimPrefix(opt, "X-containerd.dmverity.device-name=")
		} else {
			filteredOptions = append(filteredOptions, opt)
		}
	}

	if deviceName == "" {
		return mount.ActiveMount{}, fmt.Errorf("dm-verity device name not found in mount options")
	}

	// Update mount options to exclude the device-name
	m.Options = filteredOptions

	// Create the target directory if it doesn't exist
	if err := os.MkdirAll(target, 0755); err != nil {
		return mount.ActiveMount{}, fmt.Errorf("failed to create mount target: %w", err)
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

// Unmount is not used for dm-verity mounts because the manager's Deactivate()
// calls unmountDmverity() directly when it detects the "dmverity-device" key in MountData.
// This method is required by the mount.Handler interface but remains unimplemented
// as the standard Unmount signature doesn't provide access to the MountData needed
// to retrieve the device name for cleanup.
func (h dmverityHandler) Unmount(ctx context.Context, target string) error {
	// This should never be called for dm-verity mounts due to the check in
	// manager.Deactivate() that prioritizes MountData["dmverity-device"] checks
	log.G(ctx).WithField("target", target).Warn("dmverityHandler.Unmount called unexpectedly, device may leak")
	return mount.Unmount(target, 0)
}

// unmountDmverity unmounts the filesystem and closes the dm-verity device.
// This function is called directly by the manager's Deactivate() instead of going
// through the Unmount() interface method because it requires access to the full
// ActiveMount struct to retrieve the device name from MountData. The standard
// Handler.Unmount() interface only provides the mount point path, which is
// insufficient to determine which dm-verity device to close.
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
