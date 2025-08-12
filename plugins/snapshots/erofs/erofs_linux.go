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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	"github.com/containerd/containerd/v2/internal/fsverity"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/continuity/fs"
	"github.com/containerd/log"
	"github.com/containerd/plugin"
	"golang.org/x/sys/unix"
)

// SnapshotterConfig is used to configure the erofs snapshotter instance
type SnapshotterConfig struct {
	// ovlOptions are the base options added to the overlayfs mount (defaults to [""])
	ovlOptions []string
	// enableFsverity enables fsverity for EROFS layers
	enableFsverity bool
	// enableDmverity enables dmverity for EROFS layers
	enableDmverity bool
}

// Opt is an option to configure the erofs snapshotter
type Opt func(config *SnapshotterConfig)

// WithOvlOptions defines the extra mount options for overlayfs
func WithOvlOptions(options []string) Opt {
	return func(config *SnapshotterConfig) {
		config.ovlOptions = options
	}
}

// WithFsverity enables fsverity for EROFS layers
func WithFsverity() Opt {
	return func(config *SnapshotterConfig) {
		config.enableFsverity = true
	}
}

// WithDmverity enables dmverity for EROFS layers
func WithDmverity() Opt {
	return func(config *SnapshotterConfig) {
		config.enableDmverity = true
	}
}

type MetaStore interface {
	TransactionContext(ctx context.Context, writable bool) (context.Context, storage.Transactor, error)
	WithTransaction(ctx context.Context, writable bool, fn storage.TransactionCallback) error
	Close() error
}

// Label keys for EROFS snapshotter metadata
const (
	// ErofsRootHashLabel is the label key for the root hash of the EROFS layer
	ErofsRootHashLabel = "containerd.io/snapshot/erofs.root-hash"
	// ErofsSignatureLabel is the label key for the signature of the EROFS layer
	ErofsSignatureLabel = "containerd.io/snapshot/erofs.signature"
	// Default signature manifests directory relative to root (for JSON metadata files)
	SignatureManifestsDir = "signature-manifests"
	// Directory for binary signature files relative to root used by dm-verity
	SignaturesDir = "signatures"
)

// ImageInfo holds information about an image and its layers
type ImageInfo struct {
	Layers []LayerInfo `json:"layers"`
}

// LayerInfo holds information about a specific layer
type LayerInfo struct {
	Digest    string `json:"digest"`
	RootHash  string `json:"root_hash"`
	Signature string `json:"signature"`
}

// readSignatureManifests reads all signature manifest files from the signature manifests directory
// and builds a map of layer digest to layer info
func readSignatureManifests(root string) (map[string]LayerInfo, error) {
	digestToLayerInfoMap := make(map[string]LayerInfo)

	// Get signature manifests directory path relative to the provided root
	signatureManifestDirPath := filepath.Join(root, SignatureManifestsDir)

	// Check if the signature manifests directory exists
	if _, err := os.Stat(signatureManifestDirPath); err != nil {
		if os.IsNotExist(err) {
			// Directory doesn't exist, return empty digest to layer info map
			log.L.Debugf("signature manifests directory %s does not exist, skipping signature manifest loading", signatureManifestDirPath)
			return digestToLayerInfoMap, nil
		}
		return nil, fmt.Errorf("failed to access signature manifests directory: %w", err)
	}

	// Read all files from the signature manifests directory
	files, err := os.ReadDir(signatureManifestDirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature manifests directory: %w", err)
	}

	// Process each signature manifest file
	for _, file := range files {
		// Skip directories and non-regular files (symlinks, pipes, devices, etc.)
		if !file.Type().IsRegular() {
			log.L.Debugf("skipping non-regular file %s", file.Name())
			continue
		}

		// Read the signature manifest file content
		sigPath := filepath.Join(signatureManifestDirPath, file.Name())
		sigContent, err := os.ReadFile(sigPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read signature manifest file %s: %w", sigPath, err)
		}

		// Parse the JSON content
		var imageInfoList []ImageInfo
		if err := json.Unmarshal(sigContent, &imageInfoList); err != nil {
			// Log the error but continue with other files
			log.L.WithError(err).Warnf("failed to parse signature manifest file %s", sigPath)
			continue
		}

		// Extract layer information
		for _, imageInfo := range imageInfoList {
			for _, layerInfo := range imageInfo.Layers {
				digestToLayerInfoMap[layerInfo.Digest] = layerInfo
				// Log the digest, root hash and signature
				log.L.Debugf("loaded signature manifest for layer %s: root hash %s, signature %s\n",
					layerInfo.Digest, layerInfo.RootHash, layerInfo.Signature)
			}
		}
	}

	return digestToLayerInfoMap, nil
}

// prepareSignatureFile writes the signature bytes to a file that can be used with veritysetup
// Reference: https://man7.org/linux/man-pages/man8/veritysetup.8.html
func (s *snapshotter) prepareSignatureFile(hash, signatureBase64 string) (string, error) {
	log.L.Debugf("Preparing signature file for root hash %s", hash)

	// Create signatures directory if it doesn't exist
	sigDir := filepath.Join(s.root, SignaturesDir)
	if err := os.MkdirAll(sigDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create signature directory: %w", err)
	}

	// Create a file to store the signature bytes
	sigPath := filepath.Join(sigDir, fmt.Sprintf("%s.sig", hash))

	// Check if the signature file already exists
	if _, err := os.Stat(sigPath); err == nil {
		log.L.Debugf("Signature file already exists at %s", sigPath)
		return sigPath, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to check if signature file exists: %w", err)
	}

	// Decode the base64 encoded signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode signature: %w", err)
	}

	if err := os.WriteFile(sigPath, signatureBytes, 0644); err != nil {
		return "", fmt.Errorf("failed to write signature to file: %w", err)
	}

	log.L.Debugf("Wrote signature to file %s", sigPath)

	return sigPath, nil
}

type snapshotter struct {
	root                 string
	ms                   *storage.MetaStore
	ovlOptions           []string
	enableFsverity       bool
	enableDmverity       bool
	digestToLayerInfoMap map[string]LayerInfo
}

// check if EROFS kernel filesystem is registered or not
func findErofs() bool {
	fs, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	return bytes.Contains(fs, []byte("\terofs\n"))
}

// we have to claim it as uint32, otherwise s390x CI will complain.. :(
const erofsSuperMagic = uint32(0xE0F5E1E2)

// Check if a directory is actually an EROFS mount, which is used to setup or
// recover EROFS mounts for lowerdirs.
func isErofs(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false
	}
	return uint32(st.Type) == erofsSuperMagic
}

// NewSnapshotter returns a Snapshotter which uses EROFS+OverlayFS. The layers
// are stored under the provided root. A metadata file is stored under the root.
func NewSnapshotter(root string, opts ...Opt) (snapshots.Snapshotter, error) {
	var config SnapshotterConfig
	for _, opt := range opts {
		opt(&config)
	}

	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	supportsDType, err := fs.SupportsDType(root)
	if err != nil {
		return nil, err
	}
	if !supportsDType {
		return nil, fmt.Errorf("%s does not support d_type. If the backing filesystem is xfs, please reformat with ftype=1 to enable d_type support", root)
	}

	if !findErofs() {
		return nil, fmt.Errorf("EROFS unsupported, please `modprobe erofs`: %w", plugin.ErrSkipPlugin)
	}

	// Check fsverity support if enabled
	if config.enableFsverity {
		supported, err := fsverity.IsSupported(root)
		if err != nil {
			return nil, fmt.Errorf("failed to check fsverity support on %q: %w", root, err)
		}
		if !supported {
			return nil, fmt.Errorf("fsverity is not supported on the filesystem of %q", root)
		}
	}

	if config.enableDmverity {
		supported, err := dmverity.IsSupported()
		if err != nil {
			return nil, fmt.Errorf("failed to check dmverity support on %q: %w", root, err)
		}
		if !supported {
			return nil, fmt.Errorf("dmverity is not supported on the filesystem of %q", root)
		}
	}

	ms, err := storage.NewMetaStore(filepath.Join(root, "metadata.db"))
	if err != nil {
		return nil, err
	}

	if err := os.Mkdir(filepath.Join(root, "snapshots"), 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}

	s := &snapshotter{
		root:                 root,
		ms:                   ms,
		ovlOptions:           config.ovlOptions,
		enableFsverity:       config.enableFsverity,
		enableDmverity:       config.enableDmverity,
		digestToLayerInfoMap: make(map[string]LayerInfo),
	}

	// get signature manifests if available
	digestToLayerInfoMap, err := readSignatureManifests(root)
	if err != nil {
		log.L.WithError(err).Warn("failed to read signature manifests, continuing without signature verification")
	} else if len(digestToLayerInfoMap) > 0 {
		s.digestToLayerInfoMap = digestToLayerInfoMap
		log.L.Debugf("initialized with %d signature manifests", len(digestToLayerInfoMap))
	} else {
		log.L.Debug("no signature manifests found, continuing without signature verification")
	}

	return s, nil
}

// Close closes the snapshotter
func (s *snapshotter) Close() error {
	// If dmverity is enabled, try to close all devices
	if s.enableDmverity {
		// Get a list of all snapshots
		err := s.ms.WithTransaction(context.Background(), false, func(ctx context.Context) error {
			return storage.WalkInfo(ctx, func(ctx context.Context, info snapshots.Info) error {
				if info.Kind == snapshots.KindCommitted {
					// Close the device if it exists
					if err := s.closeDmverityDevice(info.Name); err != nil {
						log.L.WithError(err).Warnf("failed to close dmverity device for %v", info.Name)
					}
				}
				return nil
			})
		})
		if err != nil {
			log.L.WithError(err).Warn("error closing dmverity devices")
		}
	}
	return s.ms.Close()
}

func (s *snapshotter) upperPath(id string) string {
	return filepath.Join(s.root, "snapshots", id, "fs")
}

func (s *snapshotter) workPath(id string) string {
	return filepath.Join(s.root, "snapshots", id, "work")
}

// A committed layer blob generated by the EROFS differ
func (s *snapshotter) layerBlobPath(id string) string {
	return filepath.Join(s.root, "snapshots", id, "layer.erofs")
}

func (s *snapshotter) formatLayerBlob(ctx context.Context, id string, snapshotInfo snapshots.Info) error {
	layerBlob := s.layerBlobPath(id)
	if _, err := os.Stat(layerBlob); err != nil {
		return fmt.Errorf("failed to find valid erofs layer blob: %w", err)
	}
	if !s.isLayerWithDmverity(id) {
		opts := dmverity.DefaultDmverityOptions()
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
		file_size := fileinfo.Size()
		// Truncate the file to double its size
		if err := f.Truncate(file_size * 2); err != nil {
			return fmt.Errorf("failed to truncate layer blob: %w", err)
		}
		opts.HashOffset = uint64(file_size)
		info, err := dmverity.Format(layerBlob, layerBlob, &opts)
		if err != nil {
			return fmt.Errorf("failed to format dmverity: %w", err)
		}

		dmverityData := fmt.Sprintf("%s|%d", info.RootHash, fileinfo.Size())
		if err := os.WriteFile(filepath.Join(s.root, "snapshots", id, ".dmverity"), []byte(dmverityData), 0644); err != nil {
			return fmt.Errorf("failed to write dmverity root hash: %w", err)
		}

		// Find signature and update snapshot labels
		if err := s.findSignatureAndUpdateLabels(ctx, info, snapshotInfo); err != nil {
			return err
		}
	}
	return nil
}

func (s *snapshotter) runDmverity(ctx context.Context, id string) (string, error) {
	layerBlob := s.layerBlobPath(id)
	if _, err := os.Stat(layerBlob); err != nil {
		return "", fmt.Errorf("failed to find valid erofs layer blob: %w", err)
	}
	dmName := fmt.Sprintf("containerd-erofs-%s", id)
	devicePath := fmt.Sprintf("/dev/mapper/%s", dmName)
	if _, err := os.Stat(devicePath); err == nil {
		status, err := dmverity.Status(dmName)
		log.L.Debugf("dmverity device status: %v", status)
		if err != nil {
			return "", fmt.Errorf("failed to get dmverity device status: %w", err)
		}
		if !status.IsVerified() {
			return "", fmt.Errorf("dmverity device %s is not verified, status: %s", dmName, status.Status)
		}

		return devicePath, nil
	}
	dmverityContent, err := os.ReadFile(filepath.Join(s.root, "snapshots", id, ".dmverity"))
	if err != nil {
		return "", fmt.Errorf("failed to read dmverity root hash: %w", err)
	}

	parts := strings.Split(string(dmverityContent), "|")
	rootHash := parts[0]
	var originalSize uint64
	if len(parts) > 1 {
		var err error
		originalSize, err = strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return "", fmt.Errorf("failed to parse original size: %w", err)
		}
	}

	// Prepare signature file if a signature is available
	rootHashSignaturePath, err := s.prepareSnapshotSignature(ctx, id, rootHash)
	if err != nil {
		return "", err
	}

	if _, err := os.Stat(devicePath); err != nil {
		log.L.Debugf("Opening dmverity device for %s", id)
		opts := dmverity.DefaultDmverityOptions()
		opts.HashOffset = originalSize

		if rootHashSignaturePath != "" {
			log.L.Debugf("Using signature file %s for root hash %s", rootHashSignaturePath, rootHash)
			// The rootHashSignaturePath now contains the path to the signature file
			// We'll pass the file path to be used with --root-hash-signature by veritysetup
			opts.RootHashSignaturePath = rootHashSignaturePath
		}

		_, err = dmverity.Open(layerBlob, dmName, layerBlob, string(rootHash), &opts)
		if err != nil {
			return "", fmt.Errorf("failed to open dmverity device: %w", err)
		}

		for i := 0; i < 50; i++ {
			if _, err := os.Stat(devicePath); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return devicePath, nil
}

func (s *snapshotter) lowerPath(id string) (mount.Mount, string, error) {
	layerBlob := s.layerBlobPath(id)
	if _, err := os.Stat(layerBlob); err != nil {
		return mount.Mount{}, "", fmt.Errorf("failed to find valid erofs layer blob: %w", err)
	}

	return mount.Mount{
		Source:  layerBlob,
		Type:    "erofs",
		Options: []string{"ro"},
	}, s.upperPath(id), nil
}

func (s *snapshotter) prepareDirectory(ctx context.Context, snapshotDir string, kind snapshots.Kind) (string, error) {
	td, err := os.MkdirTemp(snapshotDir, "new-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	if err := os.Mkdir(filepath.Join(td, "fs"), 0755); err != nil {
		return td, err
	}

	if kind == snapshots.KindActive {
		if err := os.Mkdir(filepath.Join(td, "work"), 0711); err != nil {
			return td, err
		}
	}
	// Create a special file for the EROFS differ to indicate it will be
	// prepared as an EROFS layer by the EROFS snapshotter.
	if err := os.WriteFile(filepath.Join(td, ".erofslayer"), []byte{}, 0644); err != nil {
		return td, err
	}
	return td, nil
}

func (s *snapshotter) mounts(ctx context.Context, snap storage.Snapshot, info snapshots.Info) ([]mount.Mount, error) {
	var options []string

	log.L.Debugf("mounts called, info: %+v", info)
	log.L.Debugf("snap: %+v", snap)
	if len(snap.ParentIDs) == 0 {
		log.L.Debugf("no parent ids")
		m, mntpoint, err := s.lowerPath(snap.ID)
		log.L.Debugf("lowerPath: m = %v, mntpoint = %v", m, mntpoint)
		if err == nil {
			if snap.Kind != snapshots.KindView {
				return nil, fmt.Errorf("only works for snapshots.KindView on a committed snapshot: %w", err)
			}
			if s.enableFsverity {
				if err := s.verifyFsverity(m.Source); err != nil {
					return nil, err
				}
			}
			log.L.Debugf("formatting layer blob m: %+v", m)
			if s.enableDmverity {
				if err := s.formatLayerBlob(ctx, snap.ID, info); err != nil {
					return nil, err
				}
			}
			// We have to force a loop device here since mount[] is static.
			// However, if we're using dmverity, it's already a block device
			if !strings.HasPrefix(m.Source, "/dev/mapper/") {
				m.Options = append(m.Options, "loop")
			}
			return []mount.Mount{m}, nil
		}
		// if we only have one layer/no parents then just return a bind mount as overlay
		// will not work
		roFlag := "rw"
		if snap.Kind == snapshots.KindView {
			roFlag = "ro"
		}
		return []mount.Mount{
			{
				Source: s.upperPath(snap.ID),
				Type:   "bind",
				Options: append(options,
					roFlag,
					"rbind",
				),
			},
		}, nil
	}

	log.L.Debugf("snap.Kind: %+v", snap.Kind)
	if snap.Kind == snapshots.KindActive {
		options = append(options,
			fmt.Sprintf("workdir=%s", s.workPath(snap.ID)),
			fmt.Sprintf("upperdir=%s", s.upperPath(snap.ID)),
		)
	} else if len(snap.ParentIDs) == 1 {
		log.L.Debugf("len(snap.ParentIDs) == 1")
		m, mntpoint, err := s.lowerPath(snap.ParentIDs[0])
		if err != nil {
			return nil, err
		}
		log.L.Debugf("lowerPath: m = %v, mntpoint = %v", m, mntpoint)
		if s.enableDmverity {
			parentKey, err := storage.KeyFromID(ctx, snap.ParentIDs[0])
			if err != nil {
				return nil, fmt.Errorf("failed to get parent key from ID: %w", err)
			}
			var parentInfo, parentInfoErr = s.Stat(ctx, parentKey)
			if parentInfoErr != nil {
				return nil, fmt.Errorf("failed to get parent snapshot info: %w", parentInfoErr)
			}
			if err := s.formatLayerBlob(ctx, snap.ParentIDs[0], parentInfo); err != nil {
				return nil, err
			}
		}
		fmt.Printf("lowerPath: m = %v, mntpoint = %v\n", m, mntpoint)
		// We have to force a loop device here too since mount[] is static.
		// However, if we're using dmverity, it's already a block device
		if !strings.HasPrefix(m.Source, "/dev/mapper/") {
			m.Options = append(m.Options, "loop")
		}
		return []mount.Mount{m}, nil
	}

	log.L.Debugf("snap.ParentIDs: %+v", snap.ParentIDs)
	var lowerdirs []string
	for i := range snap.ParentIDs {
		m, mntpoint, err := s.lowerPath(snap.ParentIDs[i])
		if err != nil {
			return nil, err
		}
		fmt.Printf("active lowerPath: m = %v, mntpoint = %v\n", m, mntpoint)
		// If the lowerdir is actually an EROFS committed layer but
		// doesn't have an EROFS mount.  Let's recover now.
		if !s.enableDmverity && mntpoint != m.Source && !isErofs(mntpoint) {
			err := m.Mount(mntpoint)
			// Use loop if the current kernel (6.12+) doesn't support file-backed mount
			// Skip 'loop' if using dmverity device
			if errors.Is(err, unix.ENOTBLK) && (!s.enableDmverity || !strings.HasPrefix(m.Source, "/dev/mapper/")) {
				m.Options = append(m.Options, "loop")
				err = m.Mount(mntpoint)
			}
			if err != nil {
				return nil, err
			}
		}
		if s.enableDmverity {
			devicePath, err := s.runDmverity(ctx, snap.ParentIDs[i])
			if err != nil {
				return nil, err
			}
			dmName := fmt.Sprintf("containerd-erofs-%s", snap.ParentIDs[i])
			if _, err := os.Stat(devicePath); err == nil {
				status, err := dmverity.Status(dmName)
				if err != nil {
					return nil, fmt.Errorf("failed to get dmverity device status: %w", err)
				}
				m.Source = devicePath
				if !status.IsInUse() {
					err = m.Mount(mntpoint)
					if err != nil {
						return nil, err
					}
				}
			}

		}
		lowerdirs = append(lowerdirs, mntpoint)
	}
	log.L.Debugf("lowerdirs: %+v", lowerdirs)
	options = append(options, fmt.Sprintf("lowerdir=%s", strings.Join(lowerdirs, ":")))
	options = append(options, s.ovlOptions...)
	log.L.Debugf("options = %+v", options)
	return []mount.Mount{{
		Type:    "overlay",
		Source:  "overlay",
		Options: options,
	}}, nil
}

func (s *snapshotter) createSnapshot(ctx context.Context, kind snapshots.Kind, key, parent string, opts []snapshots.Opt) (_ []mount.Mount, err error) {
	var (
		snap     storage.Snapshot
		td, path string
		info     snapshots.Info
	)

	defer func() {
		if err != nil {
			if td != "" {
				if err1 := os.RemoveAll(td); err1 != nil {
					log.G(ctx).WithError(err1).Warn("failed to cleanup temp snapshot directory")
				}
			}
			if path != "" {
				if err1 := os.RemoveAll(path); err1 != nil {
					log.G(ctx).WithError(err1).WithField("path", path).Error("failed to reclaim snapshot directory, directory may need removal")
					err = fmt.Errorf("failed to remove path: %v: %w", err1, err)
				}
			}
		}
	}()

	if err := s.ms.WithTransaction(ctx, true, func(ctx context.Context) (err error) {
		snapshotDir := filepath.Join(s.root, "snapshots")
		td, err = s.prepareDirectory(ctx, snapshotDir, kind)
		if err != nil {
			return fmt.Errorf("failed to create prepare snapshot dir: %w", err)
		}

		snap, err = storage.CreateSnapshot(ctx, kind, key, parent, opts...)
		if err != nil {
			return fmt.Errorf("failed to create snapshot: %w", err)
		}

		_, info, _, err = storage.GetInfo(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to get snapshot info: %w", err)
		}

		if len(snap.ParentIDs) > 0 {
			st, err := os.Stat(s.upperPath(snap.ParentIDs[0]))
			if err != nil {
				return fmt.Errorf("failed to stat parent: %w", err)
			}

			stat := st.Sys().(*syscall.Stat_t)
			if err := os.Lchown(filepath.Join(td, "fs"), int(stat.Uid), int(stat.Gid)); err != nil {
				return fmt.Errorf("failed to chown: %w", err)
			}
		}

		path = filepath.Join(snapshotDir, snap.ID)
		if err = os.Rename(td, path); err != nil {
			return fmt.Errorf("failed to rename: %w", err)
		}
		td = ""

		return nil
	}); err != nil {
		return nil, err
	}
	return s.mounts(ctx, snap, info)
}

func (s *snapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	log.G(ctx).Tracef("In Prepare for key: %s, parent: %s, opts: %v", key, parent, opts)
	return s.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)
}

func (s *snapshotter) View(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	log.G(ctx).Tracef("In View for key: %s, parent: %s, opts: %v", key, parent, opts)
	return s.createSnapshot(ctx, snapshots.KindView, key, parent, opts)
}

func (s *snapshotter) isLayerWithDmverity(id string) bool {
	if _, err := os.Stat(filepath.Join(s.root, "snapshots", id, ".dmverity")); err != nil {
		return false
	}
	return true
}

func setImmutable(path string, enable bool) error {
	//nolint:revive	// silence "don't use ALL_CAPS in Go names; use CamelCase"
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

func (s *snapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	log.G(ctx).Tracef("In Commit for key: %s, name: %s, opts: %v", key, name, opts)

	var layerBlob, upperDir string

	// Apply the overlayfs upperdir (generated by non-EROFS differs) into a EROFS blob
	// in a read transaction first since conversion could be slow.
	err := s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		id, info, _, err := storage.GetInfo(ctx, key)
		if err != nil {
			return err
		}

		// If the layer blob doesn't exist, which means this layer wasn't applied by
		// the EROFS differ (possibly the walking differ), convert the upperdir instead.
		layerBlob = s.layerBlobPath(id)
		if _, err := os.Stat(layerBlob); err != nil {
			upperDir = s.upperPath(id)
			err = erofsutils.ConvertErofs(ctx, layerBlob, upperDir, nil)
			if err != nil {
				return err
			}

			// Remove all sub-directories in the overlayfs upperdir.  Leave the
			// overlayfs upperdir itself since it's used for Lchown.
			fd, err := os.Open(upperDir)
			if err != nil {
				return err
			}
			defer fd.Close()

			dirs, err := fd.Readdirnames(0)
			if err != nil {
				return err
			}

			for _, d := range dirs {
				dir := filepath.Join(upperDir, d)
				if err := os.RemoveAll(dir); err != nil {
					log.G(ctx).WithError(err).WithField("path", dir).Warn("failed to remove directory")
				}
			}
		}

		// Enable fsverity on the EROFS layer if configured
		if s.enableFsverity {
			if err := fsverity.Enable(layerBlob); err != nil {
				return fmt.Errorf("failed to enable fsverity: %w", err)
			}
		}

		if s.enableDmverity {
			err := s.formatLayerBlob(ctx, id, info)
			// _, err := s.runDmverity(id)
			if err != nil {
				return fmt.Errorf("failed to run dmverity: %w", err)
			}
		}

		// Set IMMUTABLE_FL on the EROFS layer to avoid artificial data loss
		// if err := setImmutable(layerBlob, true); err != nil {
		// 	log.G(ctx).WithError(err).Warnf("failed to set IMMUTABLE_FL for %s", layerBlob)
		// }
		return nil
	})

	if err != nil {
		return err
	}
	return s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		if _, err := os.Stat(layerBlob); err != nil {
			return fmt.Errorf("failed to get the converted erofs blob: %w", err)
		}

		// Get current snapshot info to preserve the labels we've set in formatLayerBlob
		_, info, _, err := storage.GetInfo(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to get snapshot info: %w", err)
		}

		// Add any labels from formatLayerBlob to our opts
		preservedOpts := append([]snapshots.Opt{}, opts...)
		if len(info.Labels) > 0 {
			labelOpt := snapshots.WithLabels(info.Labels)
			preservedOpts = append(preservedOpts, labelOpt)
		}

		usage, err := fs.DiskUsage(ctx, layerBlob)
		if err != nil {
			return err
		}

		if _, err = storage.CommitActive(ctx, key, name, snapshots.Usage(usage), preservedOpts...); err != nil {
			return fmt.Errorf("failed to commit snapshot %s: %w", key, err)
		}
		log.G(ctx).Infof("Committed snapshot %s to %s", key, name)
		return nil
	})
}

func (s *snapshotter) Mounts(ctx context.Context, key string) (_ []mount.Mount, err error) {
	log.G(ctx).Tracef("In Mounts for key: %s", key)

	var snap storage.Snapshot
	var info snapshots.Info
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		snap, err = storage.GetSnapshot(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to get active mount: %w", err)
		}

		_, info, _, err = storage.GetInfo(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to get snapshot info: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s.mounts(ctx, snap, info)
}

func (s *snapshotter) getCleanupDirectories(ctx context.Context) ([]string, error) {
	ids, err := storage.IDMap(ctx)
	if err != nil {
		return nil, err
	}

	snapshotDir := filepath.Join(s.root, "snapshots")
	fd, err := os.Open(snapshotDir)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	dirs, err := fd.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	cleanup := []string{}
	for _, d := range dirs {
		if _, ok := ids[d]; ok {
			continue
		}
		cleanup = append(cleanup, filepath.Join(snapshotDir, d))
	}

	return cleanup, nil
}

// Remove abandons the snapshot identified by key. The snapshot will
// immediately become unavailable and unrecoverable. Disk space will
// be freed up on the next call to `Cleanup`.
func (s *snapshotter) Remove(ctx context.Context, key string) (err error) {
	log.L.Tracef("Remove called, key: %s", key)

	var removals []string
	var id string
	// Remove directories after the transaction is closed, failures must not
	// return error since the transaction is committed with the removal
	// key no longer available.
	defer func() {
		if err == nil {
			if err := mount.UnmountAll(s.upperPath(id), 0); err != nil {
				log.G(ctx).Warnf("failed to unmount EROFS mount for %v", id)
			}

			if err := s.closeDmverityDevice(id); err != nil {
				log.G(ctx).WithError(err).Warnf("failed to close dmverity device for %v", id)
			}

			for _, dir := range removals {
				if err := os.RemoveAll(dir); err != nil {
					log.G(ctx).WithError(err).WithField("path", dir).Warn("failed to remove directory")
				}
			}
		}
	}()
	return s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		var k snapshots.Kind

		id, k, err = storage.Remove(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to remove snapshot %s: %w", key, err)
		}

		removals, err = s.getCleanupDirectories(ctx)
		if err != nil {
			return fmt.Errorf("unable to get directories for removal: %w", err)
		}
		// The layer blob is only persisted for committed snapshots.
		if k == snapshots.KindCommitted {
			log.L.Debugf("closing dmverity device for %v", id)
			if err := s.closeDmverityDevice(id); err != nil {
				log.G(ctx).WithError(err).Warnf("failed to close dmverity device for %v", id)
			}

			// Clear IMMUTABLE_FL before removal, since this flag avoids it.
			err = setImmutable(s.layerBlobPath(id), false)
			if err != nil {
				return fmt.Errorf("failed to clear IMMUTABLE_FL: %w", err)
			}
		}
		return nil
	})
}

func (s *snapshotter) Stat(ctx context.Context, key string) (info snapshots.Info, err error) {
	err = s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		_, info, _, err = storage.GetInfo(ctx, key)
		return err
	})
	if err != nil {
		return snapshots.Info{}, err
	}

	return info, nil
}

func (s *snapshotter) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (_ snapshots.Info, err error) {
	err = s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		info, err = storage.UpdateInfo(ctx, info, fieldpaths...)
		return err
	})
	if err != nil {
		return snapshots.Info{}, err
	}

	return info, nil
}

func (s *snapshotter) Walk(ctx context.Context, fn snapshots.WalkFunc, fs ...string) error {
	return s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		return storage.WalkInfo(ctx, fn, fs...)
	})
}

// Usage returns the resources taken by the snapshot identified by key.
//
// For active snapshots, this will scan the usage of the overlay "diff" (aka
// "upper") directory and may take some time.
//
// For committed snapshots, the value is returned from the metadata database.
func (s *snapshotter) Usage(ctx context.Context, key string) (_ snapshots.Usage, err error) {
	var (
		usage snapshots.Usage
		info  snapshots.Info
		id    string
	)
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		id, info, usage, err = storage.GetInfo(ctx, key)
		return err
	}); err != nil {
		return usage, err
	}

	if info.Kind == snapshots.KindActive {
		upperPath := s.upperPath(id)
		du, err := fs.DiskUsage(ctx, upperPath)
		if err != nil {
			// TODO(stevvooe): Consider not reporting an error in this case.
			return snapshots.Usage{}, err
		}
		usage = snapshots.Usage(du)
	}
	return usage, nil
}

// Add a method to verify fsverity
func (s *snapshotter) verifyFsverity(path string) error {
	if !s.enableFsverity {
		return nil
	}
	enabled, err := fsverity.IsEnabled(path)
	if err != nil {
		return fmt.Errorf("failed to check fsverity status: %w", err)
	}
	if !enabled {
		return fmt.Errorf("fsverity is not enabled on %s", path)
	}
	return nil
}

// closeDmverityDevice closes the dmverity device for a specific snapshot ID
func (s *snapshotter) closeDmverityDevice(id string) error {
	if !s.enableDmverity || !s.isLayerWithDmverity(id) {
		return nil
	}

	dmName := fmt.Sprintf("containerd-erofs-%s", id)
	devicePath := fmt.Sprintf("/dev/mapper/%s", dmName)
	if _, err := os.Stat(devicePath); err == nil {
		_, err = dmverity.Close(dmName)
		return err
	}
	return nil
}

// getLayerDigestFromLabels extracts the layer digest from snapshot labels
// Returns the layer digest if found
// Returns an error if the labels are nil or if the digest label is not found
func getLayerDigestFromLabels(labels map[string]string) (string, error) {
	if labels == nil {
		return "", fmt.Errorf("snapshot labels are nil, cannot find layer digest")
	}

	digest, ok := labels[snapshotters.TargetLayerDigestLabel]
	if !ok {
		return "", fmt.Errorf("target layer digest label '%s' not found in snapshot labels", snapshotters.TargetLayerDigestLabel)
	}

	return digest, nil
}

// findMatchingSignature looks for a matching signature for the layer digest and verifies the root hash
// Returns the signature if found and verified, or empty string if no signature was found
// Returns an error ONLY if the root hashes don't match
func findMatchingSignature(digestToLayerInfoMap map[string]LayerInfo, layerDigest string, calculatedRootHash string) (string, error) {
	if len(digestToLayerInfoMap) == 0 {
		return "", nil // No signature manifests available
	}

	// Check if the layer digest exists in our digest to layer info map
	layerInfo, ok := digestToLayerInfoMap[layerDigest]
	if !ok {
		log.L.Debugf("no signature found for layer digest: %s", layerDigest)
		return "", nil
	}

	// Verify that the calculated root hash matches the one in the signature
	if layerInfo.RootHash != calculatedRootHash {
		return "", fmt.Errorf("root hash mismatch: calculated %s vs expected %s",
			calculatedRootHash, layerInfo.RootHash)
	}

	log.L.Debugf("root hash from signature matches calculated root hash: %s", calculatedRootHash)
	return layerInfo.Signature, nil
}

// updateSnapshotLabelsWithSignature updates the snapshot labels with root hash and signature information
func updateSnapshotLabelsWithSignature(ctx context.Context, info snapshots.Info, rootHash, signature string) error {
	// Update labels with root hash and signature
	info.Labels[ErofsRootHashLabel] = rootHash
	info.Labels[ErofsSignatureLabel] = signature

	// Update the info in storage
	updatedInfo, err := storage.UpdateInfo(ctx, info, "labels."+ErofsRootHashLabel, "labels."+ErofsSignatureLabel)
	if err != nil {
		log.L.WithError(err).Warn("failed to update snapshot labels with signature")
		return err
	}

	log.L.Debugf("Updated snapshot labels with signature and root hash: %v", updatedInfo.Labels)
	return nil
}

// prepareSnapshotSignature retrieves a snapshot's signature from its labels and prepares
// a signature file for dm-verity verification.
// Returns the path to the prepared signature file, or empty string if no signature is found.
func (s *snapshotter) prepareSnapshotSignature(ctx context.Context, id string, rootHash string) (string, error) {
	if len(s.digestToLayerInfoMap) == 0 {
		return "", nil // No signature manifests available
	}

	var rootHashSignaturePath string = ""
	var snapshotInfo snapshots.Info

	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		var key, key_err = storage.KeyFromID(ctx, id)
		if key_err != nil {
			return fmt.Errorf("failed to get snapshot key from ID: %w", key_err)
		}
		log.L.Debugf("Key for snapshot %s: %s", id, key)

		var snapshotInfoErr error
		snapshotInfo, snapshotInfoErr = s.Stat(ctx, key)
		if snapshotInfoErr != nil {
			return fmt.Errorf("failed to get snapshot info: %w", snapshotInfoErr)
		}
		log.L.Debugf("Snapshot info for %s: %+v", id, snapshotInfo)
		return nil
	}); err != nil {
		return "", err
	}

	log.L.Debugf("Labels from snapshot: %+v", snapshotInfo.Labels)

	// Extract signature from labels and prepare signature file if available
	if signature, exists := snapshotInfo.Labels[ErofsSignatureLabel]; exists && signature != "" {
		log.L.Debugf("Found signature for %s: %s", id, signature)
		// Prepare the signature file to be used with veritysetup
		var err error
		rootHashSignaturePath, err = s.prepareSignatureFile(rootHash, signature)
		if err != nil {
			return "", fmt.Errorf("failed to prepare signature file for root hash %s: %w", rootHash, err)
		}
		log.L.Debugf("Prepared signature file for root hash %s at %s", rootHash, rootHashSignaturePath)
	} else {
		log.L.Debugf("No signature found for root hash %s in snapshot labels", rootHash)
	}

	return rootHashSignaturePath, nil
}

// findSignatureAndUpdateLabels locates a matching signature for the snapshot's layer
// and updates the snapshot's labels with signature information when found
func (s *snapshotter) findSignatureAndUpdateLabels(ctx context.Context, info *dmverity.FormatOutputInfo, snapshotInfo snapshots.Info) error {
	// Extract layer digest from snapshot labels
	layerDigest, err := getLayerDigestFromLabels(snapshotInfo.Labels)
	if err != nil {
		// Error out if the layer digest is not found
		return fmt.Errorf("missing target layer digest label: %w", err)
	}
	log.L.Debugf("found target layer digest in labels: %s", layerDigest)

	// Try to find a matching signature and verify its root hash
	signature, err := findMatchingSignature(s.digestToLayerInfoMap, layerDigest, info.RootHash)
	if err != nil {
		return fmt.Errorf("failed to verify signature for layer %s: %w", layerDigest, err)
	}

	// Update the snapshot labels only if a signature was found
	if signature != "" {
		updatedInfoErr := updateSnapshotLabelsWithSignature(ctx, snapshotInfo, info.RootHash, signature)
		if updatedInfoErr != nil {
			// Error out if updating labels fails
			return fmt.Errorf("failed to update snapshot labels with signature info: %w", updatedInfoErr)
		}
		log.L.Debugf("Updated snapshot with verified signature")
	} else {
		log.L.Debugf("No signature found for layer digest %s, continuing without signature verification", layerDigest)
	}

	return nil
}
