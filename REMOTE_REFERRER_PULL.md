# OCI Referrers API Support for Image Signature Verification

This document describes the implementation of OCI Referrers API support in containerd for automatically discovering and pulling dm-verity signature artifacts attached to container images.

---

## Overview

### What are Referrers?
Referrers are OCI artifacts that are **linked to** (reference) another artifact like a container image. They are used for:
- **Signatures** (dm-verity filesystem signatures)
- **SBOMs** (Software Bill of Materials)
- **Scan results** (vulnerability reports)
- **Attestations** (provenance, policy compliance)

The OCI Referrers API (OCI Distribution Spec v1.1.0+) provides a standardized way to discover these linked artifacts.

---

## Implementation

### Core Changes

#### 1. Configuration Support
**File:** `internal/cri/config/config.go`

Added `EnableReferrersPull` field:
```go
type PluginConfig struct {
    EnableReferrersPull bool `toml:"enable_referrers_pull"`
    // ... other fields
}
```

#### 2. OCI Referrers API Implementation
**File:** `core/remotes/docker/referrers.go` (NEW - 107 lines)

Implements the OCI Distribution Spec GET `/v2/{name}/referrers/{digest}` endpoint:
```go
// FetchReferrers queries the OCI Referrers API for artifacts referencing the given digest
func (r *dockerFetcher) FetchReferrers(ctx context.Context, digest digest.Digest) (io.ReadCloser, ocispec.Descriptor, error) {
    // Build URL: /v2/{name}/referrers/{digest}
    refURL := r.url("/v2/%s/referrers/%s", r.repository, digest)
    
    // Make HTTP GET request
    req := r.request(refURL, "application/vnd.oci.image.index.v1+json")
    resp, err := r.doRequest(ctx, req)
    
    // Returns OCI Index listing all referrers
    return resp.Body, descriptor, nil
}
```

#### 3. Integration into Image Pull Flow  
**File:** `internal/cri/server/images/image_pull.go` (simplified from 1,952 to 1,173 lines)

After pulling the main image, automatically pull its referrers:
```go
// Pull referrers if enabled
if c.config.EnableReferrersPull {
    // Create a default resolver (no registry configuration required)
    referrersResolver := docker.NewResolver(docker.ResolverOptions{
        Headers: c.config.Registry.Headers,
    })
    
    // Pull referrers for manifest digest (OCI standard)
    if err := c.pullReferrers(ctx, ref, image.Target(), referrersResolver); err != nil {
        log.G(ctx).WithError(err).Debugf("Failed to pull referrers")
    }
}
```

#### 4. Referrers Discovery and Pull
**File:** `internal/cri/server/images/image_pull.go`

```go
func (c *CRIImageService) pullReferrers(ctx context.Context, ref string, target ocispec.Descriptor, resolver remotes.Resolver) error {
    // Get fetcher from resolver
    fetcher, err := resolver.Fetcher(ctx, ref)
    
    // Check if it supports referrers API
    referrersFetcher, ok := fetcher.(remotes.ReferrersFetcher)
    if !ok {
        return nil // Skip if not supported
    }
    
    // Query the referrers API
    rc, _, err := referrersFetcher.FetchReferrers(ctx, target.Digest)
    
    // Parse the OCI Index response
    var referrersIndex ocispec.Index
    json.Unmarshal(indexData, &referrersIndex)
    
    // Pull each referrer manifest and its layers
    for _, refDesc := range referrersIndex.Manifests {
        c.pullSingleReferrer(ctx, fetcher, ref, refDesc)
    }
    
    return nil
}
```

#### 5. Signature Metadata Extraction
**File:** `internal/cri/server/images/image_pull.go`

For dm-verity signatures (artifactType: `application/vnd.oci.mt.pkcs7`):
```go
func (c *CRIImageService) extractAndStoreSignatureMetadata(ctx context.Context, imageRef string, manifestDesc ocispec.Descriptor) error {
    // Read referrer manifest from content store
    var manifest ocispec.Manifest
    json.Unmarshal(manifestData, &manifest)
    
    // Check artifact type
    if manifest.ArtifactType != "application/vnd.oci.mt.pkcs7" {
        return nil // Not a dm-verity signature
    }
    
    // Extract signature metadata from layers
    for _, layer := range manifest.Layers {
        layerDigest := layer.Annotations["image.layer.digest"]
        rootHash := layer.Annotations["image.layer.root_hash"]
        signatureData, _ := content.ReadBlob(ctx, cs, layer)
        signatureBase64 := base64.StdEncoding.EncodeToString(signatureData)
        
        layerInfo := map[string]interface{}{
            "digest":     layerDigest,
            "root_hash":  rootHash,
            "signature":  signatureBase64,
        }
        layerInfos = append(layerInfos, layerInfo)
    }
    
    // Write to snapshotter-specific signatures.json
    filePath := filepath.Join(snapshotterPath, "signature-manifests", "signatures.json")
    os.WriteFile(filePath, jsonData, 0644)
    
    return nil
}
```

---

## Data Flow

```
┌──────────────────────────────────────────────────────────┐
│ 1. OCI REGISTRY (Referrers API)                          │
│    GET /v2/{name}/referrers/{digest}                     │
│    Returns: OCI Index with signature manifests          │
└────────────────┬─────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│ 2. CONTAINERD PULL (image_pull.go)                       │
│    - Pull main image                                     │
│    - Call FetchReferrers() for manifest digest          │
│    - Pull each referrer manifest + layers               │
│    - Store in content store                             │
└────────────────┬─────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│ 3. SIGNATURE EXTRACTION (extractAndStoreSignatureMetadata)│
│    - Read referrer manifest from content store          │
│    - Extract layer annotations (digest, root_hash, sig) │
│    - Write signatures.json to snapshotter directory     │
└────────────────┬─────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│ 4. EROFS SNAPSHOTTER (erofs_linux.go)                    │
│    - Read signatures.json                                │
│    - Match signature to layer digest                     │
│    - Create .sig file with PKCS7 binary                  │
│    - Call veritysetup with signature                     │
└────────────────┬─────────────────────────────────────────┘
                 │
                 ▼
┌──────────────────────────────────────────────────────────┐
│ 5. KERNEL DM-VERITY                                       │
│    - Verify signature against kernel keyring            │
│    - Mount integrity-protected filesystem               │
└──────────────────────────────────────────────────────────┘
```

---

## Configuration

### 1. Containerd Configuration
**File:** `/etc/containerd/config.toml`

```toml
[plugins."io.containerd.grpc.v1.cri"]
  # Enable automatic referrers pull
  enable_referrers_pull = true

[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "erofs"

[plugins."io.containerd.snapshotter.v1.erofs"]
  # Enable dm-verity verification
  enable_dmverity = true
```

### 2. No Registry Configuration Required!
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. KERNEL DM-VERITY                                              │
│    - Mount verified block device                                │
│    - All reads verified against merkle tree                     │
│    - Container runs with integrity-protected filesystem         │
└─────────────────────────────────────────────────────────────────┘
```

---

### 2. No Registry Configuration Required!

The implementation uses a **default resolver** that works with any fully-qualified registry URL without requiring `hosts.toml` configuration files.

**Supported registries out-of-the-box:**
- Azure Container Registry (`*.azurecr.io`)
- Docker Hub (`docker.io`)
- GitHub Container Registry (`ghcr.io`)
- Google Container Registry (`gcr.io`)
- Any OCI-compliant registry

**Example images that work without configuration:**
```bash
liunancr.azurecr.io/azurelinux/busybox:1.36
steamboat947202ukitest.azurecr.io/cloudtest/azuredefender/stable/low-level-collector:2.0.124
```

Authentication is handled automatically through:
- Docker credential helpers
- Azure managed identity (for Azure VMs)
- Standard containerd auth mechanisms

---

## File Locations

### Signature Storage Hierarchy
```
/var/lib/containerd/io.containerd.snapshotter.v1.erofs/
├── signature-manifests/
│   └── signatures.json           # Written by extractAndStoreSignatureMetadata()
│       [
│         {
│           "layers": [
│             {
│               "digest": "sha256:abc...",
│               "root_hash": "def...",
│               "signature": "base64(PKCS7)"
│             }
│           ]
│         }
│       ]
├── signatures/
│   ├── <root_hash1>.sig          # Binary PKCS7 files for veritysetup
│   └── <root_hash2>.sig
└── snapshots/
    └── 123/
        ├── layer.erofs
        ├── .dmverity
        └── fs/
```

---

## Testing

### Verify Referrers are Pulled

```bash
# Enable debug logging
export CONTAINERD_LOG_LEVEL=debug

# Pull an image with signatures
crictl pull liunancr.azurecr.io/azurelinux/busybox:1.36

# Check logs for referrers discovery
journalctl -u containerd -n 100 | grep -i referrer

# Expected log output:
# "Pulling referrers for image ..."
# "Found X referrers for image ..."
# "Successfully pulled X referrers ..."
```

### Verify Signatures are Extracted

```bash
# Check signatures.json was created
cat /var/lib/containerd/io.containerd.snapshotter.v1.erofs/signature-manifests/signatures.json

# Should show JSON with layer digests, root hashes, and signatures
