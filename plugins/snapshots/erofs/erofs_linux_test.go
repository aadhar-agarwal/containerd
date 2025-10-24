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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/containerd/v2/core/snapshots/testsuite"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	"github.com/containerd/containerd/v2/internal/fsverity"
	"github.com/containerd/containerd/v2/pkg/archive/tartest"
	"github.com/containerd/containerd/v2/pkg/testutil"
	"github.com/containerd/containerd/v2/plugins/content/local"
	erofsdiffer "github.com/containerd/containerd/v2/plugins/diff/erofs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testFileContent       = "Hello, this is content for testing the EROFS Snapshotter!"
	testNestedFileContent = "Nested file content"
)

func newSnapshotter(t *testing.T, opts ...Opt) func(ctx context.Context, root string) (snapshots.Snapshotter, func() error, error) {
	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}

	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}
	return func(ctx context.Context, root string) (snapshots.Snapshotter, func() error, error) {
		snapshotter, err := NewSnapshotter(root, opts...)
		if err != nil {
			return nil, nil, err
		}

		return snapshotter, func() error { return snapshotter.Close() }, nil
	}
}

func testMount(t *testing.T, scratchFile string) error {
	root, err := os.MkdirTemp(t.TempDir(), "")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)

	m := []mount.Mount{
		{
			Type:    "ext4",
			Source:  scratchFile,
			Options: []string{"loop", "direct-io", "sync"},
		},
	}

	if err := mount.All(m, root); err != nil {
		return fmt.Errorf("failed to mount device %s: %w", scratchFile, err)
	}

	if err := os.Remove(filepath.Join(root, "lost+found")); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(root, "work"), 0755); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(root, "upper"), 0755); err != nil {
		return err
	}
	return mount.UnmountAll(root, 0)
}

func TestErofs(t *testing.T) {
	testutil.RequiresRoot(t)
	testsuite.SnapshotterSuite(t, "erofs", newSnapshotter(t))
}

func TestErofsWithQuota(t *testing.T) {
	testutil.RequiresRoot(t)
	testsuite.SnapshotterSuite(t, "erofs", newSnapshotter(t, WithDefaultSize(16*1024*1024)))
}

func TestErofsFsverity(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := context.Background()

	root := t.TempDir()

	// Skip if fsverity is not supported
	supported, err := fsverity.IsSupported(root)
	if !supported || err != nil {
		t.Skip("fsverity not supported, skipping test")
	}

	// Create snapshotter with fsverity enabled
	s, err := NewSnapshotter(root, WithFsverity())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create a test snapshot
	key := "test-snapshot"
	mounts, err := s.Prepare(ctx, key, "")
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, key)
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := mount.All(mounts, target); err != nil {
		t.Fatal(err)
	}
	defer testutil.Unmount(t, target)

	// Write test data
	if err := os.WriteFile(filepath.Join(target, "foo"), []byte("test data"), 0777); err != nil {
		t.Fatal(err)
	}

	// Commit the snapshot
	commitKey := "test-commit"
	if err := s.Commit(ctx, commitKey, key); err != nil {
		t.Fatal(err)
	}

	snap := s.(*snapshotter)

	// Get the internal ID from the snapshotter
	var id string
	if err := snap.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		id, _, _, err = storage.GetInfo(ctx, commitKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Verify fsverity is enabled on the EROFS layer

	layerPath := snap.layerBlobPath(id)

	enabled, err := fsverity.IsEnabled(layerPath)
	if err != nil {
		t.Fatalf("Failed to check fsverity status: %v", err)
	}
	if !enabled {
		t.Fatal("Expected fsverity to be enabled on committed layer")
	}

	// Try to modify the layer file directly (should fail)
	if err := os.WriteFile(layerPath, []byte("tampered data"), 0666); err == nil {
		t.Fatal("Expected direct write to fsverity-enabled layer to fail")
	}
}

func TestErofsDifferWithTarIndexMode(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := context.Background()

	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	// Check if mkfs.erofs supports tar index mode
	supported, err := erofsutils.SupportGenerateFromTar()
	if err != nil || !supported {
		t.Skip("mkfs.erofs does not support tar mode, skipping tar index test")
	}

	tempDir := t.TempDir()

	// Create content store for the differ
	contentStore, err := local.NewStore(filepath.Join(tempDir, "content"))
	if err != nil {
		t.Fatal(err)
	}

	// Create EROFS differ with tar index mode enabled
	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithTarIndexMode())

	// Create EROFS snapshotter
	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create test tar content
	tarReader := createTestTarContent()
	defer tarReader.Close()

	// Read the tar content into a buffer for digest calculation and writing
	tarContent, err := io.ReadAll(tarReader)
	if err != nil {
		t.Fatal(err)
	}

	// Write tar content to content store
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromBytes(tarContent),
		Size:      int64(len(tarContent)),
	}

	writer, err := contentStore.Writer(ctx,
		content.WithRef("test-layer"),
		content.WithDescriptor(desc))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := writer.Write(tarContent); err != nil {
		writer.Close()
		t.Fatal(err)
	}

	if err := writer.Commit(ctx, desc.Size, desc.Digest); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	writer.Close()

	// Prepare a snapshot using the snapshotter
	snapshotKey := "test-snapshot"
	mounts, err := s.Prepare(ctx, snapshotKey, "")
	if err != nil {
		t.Fatal(err)
	}

	// Apply the tar content using the EROFS differ with tar index mode
	appliedDesc, err := differ.Apply(ctx, desc, mounts)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Applied layer using EROFS differ with tar index mode:")
	t.Logf("  Original: %s (%d bytes)", desc.Digest, desc.Size)
	t.Logf("  Applied:  %s (%d bytes)", appliedDesc.Digest, appliedDesc.Size)
	t.Logf("  MediaType: %s", appliedDesc.MediaType)

	// Commit the snapshot to finalize the EROFS layer creation
	commitKey := "test-commit"
	if err := s.Commit(ctx, commitKey, snapshotKey); err != nil {
		t.Fatal(err)
	}

	// Get the internal snapshot ID to check the EROFS layer file
	snap := s.(*snapshotter)
	var id string
	if err := snap.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		id, _, _, err = storage.GetInfo(ctx, commitKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Verify the EROFS layer file was created
	layerPath := snap.layerBlobPath(id)
	if _, err := os.Stat(layerPath); err != nil {
		t.Fatalf("EROFS layer file should exist: %v", err)
	}

	// Verify the layer file is not empty
	stat, err := os.Stat(layerPath)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() == 0 {
		t.Fatal("EROFS layer file should not be empty")
	}

	t.Logf("EROFS layer file created with tar index mode: %s (%d bytes)", layerPath, stat.Size())

	// Create a view to verify the content
	viewKey := "test-view"
	viewMounts, err := s.View(ctx, viewKey, commitKey)
	if err != nil {
		t.Fatal(err)
	}

	viewTarget := filepath.Join(tempDir, viewKey)
	if err := os.MkdirAll(viewTarget, 0755); err != nil {
		t.Fatal(err)
	}
	if err := mount.All(viewMounts, viewTarget); err != nil {
		t.Fatal(err)
	}
	defer testutil.Unmount(t, viewTarget)

	// Verify we can read the original test data
	testData, err := os.ReadFile(filepath.Join(viewTarget, "test-file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	expected := testFileContent
	if string(testData) != expected {
		t.Fatalf("Expected %q, got %q", expected, string(testData))
	}

	// Verify nested file
	nestedData, err := os.ReadFile(filepath.Join(viewTarget, "testdir", "nested.txt"))
	if err != nil {
		t.Fatal(err)
	}
	expectedNested := testNestedFileContent
	if string(nestedData) != expectedNested {
		t.Fatalf("Expected %q, got %q", expectedNested, string(nestedData))
	}

	t.Logf("Successfully verified EROFS Snapshotter using the differ with tar index mode")
}

// Helper function to create test tar content using tartest
func createTestTarContent() io.ReadCloser {
	// Create a tar context with current time for consistency
	tc := tartest.TarContext{}.WithModTime(time.Now())

	// Create the tar with our test files and directories
	tarWriter := tartest.TarAll(
		tc.File("test-file.txt", []byte(testFileContent), 0644),
		tc.Dir("testdir", 0755),
		tc.File("testdir/nested.txt", []byte(testNestedFileContent), 0644),
	)

	// Return the tar as a ReadCloser
	return tartest.TarFromWriterTo(tarWriter)
}

// TestCreateDmverityErofsMount tests dm-verity mount creation
func TestCreateDmverityErofsMount(t *testing.T) {
	testutil.RequiresRoot(t)

	tmpDir := t.TempDir()

	// Helper to create layer with metadata
	createLayer := func(name, roothash string, hashOffset int64, useSuperblock bool) string {
		layerBlob := filepath.Join(tmpDir, name)
		metadataFile := layerBlob + ".dmverity"

		metadataContent := fmt.Sprintf("roothash=%s\nhash-offset=%d\nuse-superblock=%t\n",
			roothash, hashOffset, useSuperblock)
		require.NoError(t, os.WriteFile(metadataFile, []byte(metadataContent), 0644))
		require.NoError(t, os.WriteFile(layerBlob, []byte{}, 0644))

		return layerBlob
	}

	// Helper to check if option exists
	hasOption := func(options []string, opt string) bool {
		for _, o := range options {
			if o == opt {
				return true
			}
		}
		return false
	}

	s := &snapshotter{
		root:           tmpDir,
		enableDmverity: true,
	}

	t.Run("creates dmverity mount with metadata", func(t *testing.T) {
		layerBlob := createLayer("layer.erofs",
			"abc123def456789012345678901234567890123456789012345678901234", 8192, true)

		m, err := s.createDmverityErofsMount("test-id", layerBlob)
		require.NoError(t, err)

		assert.Equal(t, "dmverity/erofs", m.Type)
		assert.Equal(t, layerBlob, m.Source)
		assert.True(t, hasOption(m.Options, "ro"), "should have ro option")
		assert.True(t, hasOption(m.Options, "X-containerd.dmverity.roothash=abc123def456789012345678901234567890123456789012345678901234"))
		assert.True(t, hasOption(m.Options, "X-containerd.dmverity.hash-offset=8192"))
		assert.True(t, hasOption(m.Options, "X-containerd.dmverity.device-name=containerd-erofs-test-id"))
		assert.False(t, hasOption(m.Options, "X-containerd.dmverity.no-superblock"), "should not have no-superblock when use-superblock=true")
	})

	t.Run("handles no-superblock flag", func(t *testing.T) {
		layerBlob := createLayer("layer-no-sb.erofs",
			"def456abc789012345678901234567890123456789012345678901234567", 16384, false)

		m, err := s.createDmverityErofsMount("test-id-no-sb", layerBlob)
		require.NoError(t, err)

		assert.True(t, hasOption(m.Options, "X-containerd.dmverity.no-superblock"), "should have no-superblock when use-superblock=false")
	})

	t.Run("fails without metadata file", func(t *testing.T) {
		layerBlob := filepath.Join(tmpDir, "layer-no-meta.erofs")
		require.NoError(t, os.WriteFile(layerBlob, []byte{}, 0644))

		_, err := s.createDmverityErofsMount("test-id-2", layerBlob)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse dm-verity metadata")
	})

	t.Run("fails with invalid metadata format", func(t *testing.T) {
		layerBlob := filepath.Join(tmpDir, "layer-bad-meta.erofs")
		metadataFile := layerBlob + ".dmverity"

		require.NoError(t, os.WriteFile(metadataFile, []byte("invalid metadata"), 0644))
		require.NoError(t, os.WriteFile(layerBlob, []byte{}, 0644))

		_, err := s.createDmverityErofsMount("test-id-bad", layerBlob)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse dm-verity metadata")
	})
}

// TestCreateErofsMount tests mount creation without dm-verity
func TestCreateErofsMount(t *testing.T) {
	tmpDir := t.TempDir()
	layerBlob := filepath.Join(tmpDir, "layer.erofs")
	require.NoError(t, os.WriteFile(layerBlob, []byte{}, 0644))

	s := &snapshotter{
		root:           tmpDir,
		enableDmverity: false,
	}

	t.Run("creates regular erofs mount", func(t *testing.T) {
		m, err := s.createErofsMount("test-id", layerBlob)
		require.NoError(t, err)

		assert.Equal(t, "erofs", m.Type)
		assert.Equal(t, layerBlob, m.Source)
		assert.Equal(t, []string{"ro", "loop"}, m.Options)
	})

	t.Run("dispatcher calls dmverity function when enabled", func(t *testing.T) {
		s.enableDmverity = true
		metadataFile := layerBlob + ".dmverity"
		metadataContent := "roothash=fedcba098765432109876543210987654321098765432109876543210987\nhash-offset=4096\nuse-superblock=true\n"
		require.NoError(t, os.WriteFile(metadataFile, []byte(metadataContent), 0644))

		m, err := s.createErofsMount("test-id", layerBlob)
		require.NoError(t, err)
		assert.Equal(t, "dmverity/erofs", m.Type)
	})
}

// TestDmverityDeviceName tests device name generation
func TestDmverityDeviceName(t *testing.T) {
	s := &snapshotter{}

	tests := []struct {
		name string
		id   string
		want string
	}{
		{
			name: "simple id",
			id:   "abc123",
			want: "containerd-erofs-abc123",
		},
		{
			name: "numeric id",
			id:   "12345",
			want: "containerd-erofs-12345",
		},
		{
			name: "uuid style id",
			id:   "550e8400-e29b-41d4-a716-446655440000",
			want: "containerd-erofs-550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.dmverityDeviceName(tt.id)
			assert.Equal(t, tt.want, got)
		})
	}
}
