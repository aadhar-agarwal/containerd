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

	"github.com/containerd/errdefs"
	"github.com/containerd/log"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
)

const (
	// prefixDmverity is the option prefix for dm-verity specific options
	prefixDmverity = "X-containerd.dmverity."
)

// dmverityTransformer is a mount transformer that sets up dm-verity devices
// for integrity verification. It reads dm-verity options from mount options
// and creates a read-only device-mapper target.
type dmverityTransformer struct{}

func (dmverityTransformer) Transform(ctx context.Context, m mount.Mount, a []mount.ActiveMount) (mount.Mount, error) {
	log.G(ctx).Debugf("transforming dmverity mount: %+v", m)

	var (
		rootHashFile string
		rootHash     string
		hashOffset   uint64
		deviceName   string
	)

	// Parse dm-verity options from mount options
	var options []string
	for _, o := range m.Options {
		if dmverityOption, isDmverity := strings.CutPrefix(o, prefixDmverity); isDmverity {
			key, value, ok := strings.Cut(dmverityOption, "=")
			if !ok {
				return mount.Mount{}, fmt.Errorf("invalid dmverity option %q: %w", o, errdefs.ErrInvalidArgument)
			}
			switch key {
			case "roothash-file":
				rootHashFile = value
			case "roothash":
				rootHash = value
			case "hash-offset":
				_, err := fmt.Sscanf(value, "%d", &hashOffset)
				if err != nil {
					return mount.Mount{}, fmt.Errorf("invalid hash-offset %q: %w", value, err)
				}
			case "device-name":
				deviceName = value
			default:
				return mount.Mount{}, fmt.Errorf("unknown dmverity option %q: %w", key, errdefs.ErrInvalidArgument)
			}
		} else {
			options = append(options, o)
		}
	}

	// Validate required options
	if rootHashFile == "" && rootHash == "" {
		return mount.Mount{}, fmt.Errorf("dmverity requires either roothash-file or roothash option: %w", errdefs.ErrInvalidArgument)
	}

	// Read root hash from file if specified
	if rootHashFile != "" {
		hashBytes, err := os.ReadFile(rootHashFile)
		if err != nil {
			return mount.Mount{}, fmt.Errorf("failed to read root hash file %q: %w", rootHashFile, err)
		}
		rootHash = strings.TrimSpace(string(hashBytes))
	}

	// Generate device name if not specified
	if deviceName == "" {
		deviceName = fmt.Sprintf("dmverity-%d", time.Now().UnixNano())
	}

	// Update mount to point to the dm-verity device
	devicePath := fmt.Sprintf("/dev/mapper/%s", deviceName)

	// Check if device already exists (for layer reuse)
	if _, err := os.Stat(devicePath); err == nil {
		log.G(ctx).WithField("device", devicePath).Debug("dm-verity device already exists, reusing")
		// Device exists, just reuse it
		m.Source = devicePath
		m.Options = append(options, fmt.Sprintf("X-containerd.dmverity.device-name=%s", deviceName))
		return m, nil
	}

	// Prepare dm-verity options
	opts := dmverity.DefaultDmverityOptions()
	if hashOffset > 0 {
		opts.HashOffset = hashOffset
	}
	if rootHashFile != "" {
		opts.RootHashFile = rootHashFile
	}

	// Create dm-verity device
	log.G(ctx).WithFields(log.Fields{
		"source":      m.Source,
		"device-name": deviceName,
		"root-hash":   rootHash[:16] + "...", // Log only first few chars for security
	}).Debug("opening dm-verity device")

	_, err := dmverity.Open(m.Source, deviceName, m.Source, rootHash, &opts)
	if err != nil {
		return mount.Mount{}, fmt.Errorf("failed to open dm-verity device: %w", err)
	}

	// Wait for device to appear
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(devicePath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify device exists
	if _, err := os.Stat(devicePath); err != nil {
		// Try to close the device we just created
		dmverity.Close(deviceName)
		return mount.Mount{}, fmt.Errorf("dm-verity device %q not found after creation: %w", devicePath, err)
	}

	log.G(ctx).WithField("device", devicePath).Info("dm-verity device created successfully")

	// Return updated mount pointing to dm-verity device
	// Store the device name in options so it can be retrieved during cleanup
	m.Source = devicePath
	m.Options = append(options, fmt.Sprintf("X-containerd.dmverity.device-name=%s", deviceName))
	return m, nil
}
