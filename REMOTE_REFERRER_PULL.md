# dm-verity Remote Signature Verification

---

## Solution

### Code Changes

#### 1. Fixed `prepareSignatureFile()` Function
**File:** `plugins/snapshots/erofs/erofs_linux.go` (Lines 178-220)

**Before:**
```go
func (s *snapshotter) prepareSignatureFile(hash, signatureBase64 string) (string, error) {
    // ... setup code ...
    
    // Decode base64 once
    sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
    if err != nil {
        return "", fmt.Errorf("failed to decode signature: %w", err)
    }
    
    // Write JSON text to .sig file (WRONG!)
    if err := os.WriteFile(sigPath, sigBytes, 0644); err != nil {
        return "", fmt.Errorf("failed to write signature to file: %w", err)
    }
    
    return sigPath, nil
}
```

**After:**
```go
func (s *snapshotter) prepareSignatureFile(hash, signatureBase64 string) (string, error) {
    // ... setup code ...
    
    // Always regenerate the signature file to ensure it has the correct format
    // (older versions may have written JSON text instead of binary PKCS7)
    
    // STEP 1: Decode the base64 to get JSON bytes
    jsonBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
    if err != nil {
        return "", fmt.Errorf("failed to decode signature JSON: %w", err)
    }
    
    // STEP 2: Parse JSON to extract the signature field
    var signatureData struct {
        LayerDigest string `json:"layer_digest"`
        RootHash    string `json:"root_hash"`
        Signature   string `json:"signature"`
    }
    if err := json.Unmarshal(jsonBytes, &signatureData); err != nil {
        return "", fmt.Errorf("failed to parse signature JSON: %w", err)
    }
    
    // STEP 3: Decode the PKCS7 signature from base64
    pkcs7Bytes, err := base64.StdEncoding.DecodeString(signatureData.Signature)
    if err != nil {
        return "", fmt.Errorf("failed to decode PKCS7 signature: %w", err)
    }
    
    // STEP 4: Write raw binary PKCS7 to file (this is what veritysetup expects)
    if err := os.WriteFile(sigPath, pkcs7Bytes, 0644); err != nil {
        return "", fmt.Errorf("failed to write signature to file: %w", err)
    }
    
    return sigPath, nil
}
```

**Key Changes:**
1. Removed early return when `.sig` file exists (always regenerate)
2. Parse JSON structure from base64-decoded data
3. Extract `signature` field from JSON
4. Decode the nested base64 PKCS7
5. Write raw binary PKCS7 bytes to file

#### 2. Cleaned Up Debug Logging
**Files Modified:**
- `plugins/snapshots/erofs/erofs_linux.go` - Removed `fmt.Printf("dallas ...")` statements
- `internal/cri/server/images/image_pull.go` - Changed debug logs to `Debugf` level

---

## Data Flow

### Complete Signature Verification Flow

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. OCI REGISTRY (Referrers API)                                 │
│    - Image manifest + config                                    │
│    - Referrer manifest (artifactType: application/vnd.cncf...)  │
│      Contains signature layers with annotations                 │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. CONTAINERD PULL (internal/cri/server/images/image_pull.go)  │
│    - Pull main image                                            │
│    - If EnableReferrersPull: pull referrers for manifest digest │
│    - Store referrer content in content store                    │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. BRIDGE EXECUTION (external binary)                           │
│    - Read referrer manifests from content store                 │
│    - Extract layer annotations (root_hash, layer_digest, sig)   │
│    - Create signatures.json file                                │
│    Location: /var/lib/containerd/.../signature-manifests/       │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. SNAPSHOTTER READS SIGNATURES.JSON                            │
│    Function: readSignatureManifests()                           │
│    - Load all signatures.json files                             │
│    - Build map: layer_digest -> LayerInfo{RootHash, Signature}  │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. SNAPSHOT COMMIT                                               │
│    Function: findSignatureAndUpdateLabels()                     │
│    - Look up signature by layer digest                          │
│    - Add to snapshot labels:                                    │
│      * containerd.io/snapshot/erofs.root-hash                   │
│      * containerd.io/snapshot/erofs.signature (base64 JSON)     │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. MOUNT/DMVERITY SETUP                                          │
│    Function: runDmverity() → prepareSnapshotSignature()         │
│    - Read signature from snapshot labels                        │
│    - Call prepareSignatureFile() to create .sig file            │
│    - Extract PKCS7 from double-encoded JSON ⚠️ FIX HERE          │
│    Location: /var/lib/containerd/.../signatures/<hash>.sig      │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│ 7. VERITYSETUP OPEN                                              │
│    Command: veritysetup open --root-hash-signature=<path>       │
│    - Read binary PKCS7 from .sig file                           │
│    - Extract certificate chain from PKCS7                       │
│    - Check kernel keyring (.platform) for trusted CA            │
│    - Verify signature matches root hash                         │
│    - Create /dev/mapper/containerd-erofs-<id> device            │
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

## Configuration Requirements

### 1. Containerd Configuration
**File:** `/etc/containerd/config.toml`

```toml
[plugins."io.containerd.grpc.v1.cri"]
  # Enable referrers pull for signature discovery
  enable_referrers_pull = true

[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "erofs"

[plugins."io.containerd.snapshotter.v1.erofs"]
  # Enable dm-verity verification
  enable_dmverity = true
```

### 2. Registry Configuration
**Files:** `/etc/containerd/certs.d/<registry>/hosts.toml`

**Example for Azure Container Registry:**
```toml
server = "https://liunancr.azurecr.io"

[host."https://liunancr.azurecr.io"]
  capabilities = ["pull", "resolve", "referrers"]
  # Note: capabilities value = 1 (pull) + 2 (resolve) + 8 (referrers) = 11
```

**Example for Steamboat Registry:**
```toml
server = "https://steamboat947202ukitest.azurecr.io"

[host."https://steamboat947202ukitest.azurecr.io"]
  capabilities = ["pull", "resolve", "referrers"]
```

### 3. Kernel Keyring Setup
**Required for signature verification:**

```bash
# Check current keys in .platform keyring
keyctl list %keyring:.platform

# Example output:
# 9f03cb6c asymmetri LinuxGuard Test UEFI Ephemeral CA
```

The kernel keyring must contain the CA certificate that signed the image signatures. Without this, you'll get:
```
Required key not available
```

---

## File Locations

### Signature Storage Hierarchy
```
/var/lib/containerd/io.containerd.snapshotter.v1.erofs/
├── signature-manifests/
│   └── signatures.json           # Created by bridge, read by snapshotter
│       [
│         {
│           "image": "registry.io/image:tag",
│           "layers": [
│             {
│               "digest": "sha256:abc...",
│               "root_hash": "def...",
│               "signature": "base64(JSON{signature:base64(PKCS7)})"
│             }
│           ]
│         }
│       ]
├── signatures/
│   ├── <root_hash1>.sig          # Binary PKCS7 files for veritysetup
│   ├── <root_hash2>.sig
│   └── ...
└── snapshots/
    ├── 123/
    │   ├── layer.erofs            # EROFS formatted layer
    │   ├── .dmverity              # Root hash metadata
    │   └── fs/                    # Mount point
    └── ...
```

---

## Verification Steps

### 1. Check Signature File Format
```bash
# Good - Binary PKCS7 (starts with 30 82)
hexdump -C /var/lib/containerd/.../signatures/<hash>.sig | head -3
00000000  30 82 05 11 06 09 2a 86  48 86 f7 0d 01 07 02 a0  |0.....*.H.......|

# Bad - JSON text (starts with 7b 0a 20 20 22 6c)
hexdump -C /var/lib/containerd/.../signatures/<hash>.sig | head -3
00000000  7b 0a 20 20 22 6c 61 79  65 72 5f 64 69 67 65 73  |{.  "layer_diges|
```

### 2. Validate PKCS7 Structure
```bash
openssl pkcs7 -print -inform DER -in <hash>.sig
# Should show certificate chain and signature data
```

### 3. Check Kernel Keyring
```bash
keyctl list %keyring:.platform
# Should list trusted CA certificates
```

### 4. Test Image Pull
```bash
# Image with trusted signature - should succeed
crictl pull steamboat947202ukitest.azurecr.io/cloudtest/azuredefender/stable/low-level-collector:2.0.124

# Image with untrusted signature - should fail with "Required key not available"
crictl pull liunancr.azurecr.io/azurelinux/busybox:1.36
```

---

## Error Messages Explained

| Error | Meaning | Solution |
|-------|---------|----------|
| `Bad message` | Signature file format invalid (not PKCS7) | Fixed by this PR - proper PKCS7 extraction |
| `Required key not available` | Certificate not in kernel keyring | Add signing CA to `.platform` keyring |
| `no pull hosts: not found` | Missing referrers capability | Add `"referrers"` to hosts.toml capabilities |
| `failed to pull referrers` | Registry doesn't support OCI Referrers API | Use registry with referrers support |

---

## Certificate and Signature Relationship

### How It Works

1. **Kernel Keyring** (`.platform` keyring)
   - Contains trusted CA certificates (public keys)
   - Acts like a trust store (similar to browser root CAs)

2. **Signature File** (`.sig` file)
   - PKCS#7 signed data structure containing:
     - The root hash being signed
     - The signer's certificate chain
     - The cryptographic signature (encrypted hash)

3. **Verification Process**
   ```
   veritysetup reads .sig file
        ↓
   Extract certificate from PKCS#7
        ↓
   Check: Does cert chain to a CA in kernel keyring?
        ↓
   Yes: Verify signature with cert's public key
        ↓
   Signature valid: Open dm-verity device ✅
   
   Certificate not in keyring: "Required key not available" ❌
   Signature invalid: Verification failed ❌
   ```

---

## Testing Results

### ✅ Success Case (steamboat image)
```
Image: steamboat947202ukitest.azurecr.io/.../low-level-collector:2.0.124
Certificate: LinuxGuard Test UEFI Ephemeral CA (in keyring)
Result: Container started successfully
Log: "StartContainer ... returns successfully"
```

### ❌ Failure Case (busybox image)
```
Image: liunancr.azurecr.io/azurelinux/busybox:1.36
Certificate: Different CA (not in keyring)
Error: "device-mapper: reload ioctl failed: Required key not available"
Result: Image pull rejected ✅ (security working correctly)
```

---

## Referrers Pull Implementation

### Overview
Added OCI Referrers API support to automatically discover and pull signature artifacts attached to container images. This is required to get the dm-verity signatures before verifying images.

### What are Referrers?
Referrers are OCI artifacts that are **linked to** (reference) another artifact like a container image. They are used for:
- **Signatures** (like our dm-verity signatures)
- **SBOMs** (Software Bill of Materials)
- **Scan results** (vulnerability reports)
- **Attestations** (provenance, policy compliance)

The OCI Referrers API provides a standardized way to discover these linked artifacts.

### Code Changes for Referrers Pull

#### 1. Configuration Support
**File:** `internal/cri/server/images/service.go`

Added `EnableReferrersPull` field to the configuration:
```go
type CRIImageService struct {
    config criconfig.Config
    // ... other fields
}

// In config struct (elsewhere):
type Config struct {
    EnableReferrersPull bool `toml:"enable_referrers_pull"`
    // ... other fields
}
```

#### 2. Pull Flow Integration
**File:** `internal/cri/server/images/image_pull.go` (Lines 260-280)

After pulling the main image, automatically pull its referrers:
```go
// Pull referrers if enabled
if c.config.EnableReferrersPull {
    log.G(ctx).Debugf("Pulling referrers for image %q with manifest digest %s", ref, image.Target().Digest)
    
    // Create a fresh resolver for referrers pulls
    referrersResolver := docker.NewResolver(docker.ResolverOptions{
        Headers: c.config.Registry.Headers,
        Hosts:   c.registryHosts(ctx, credentials, nil),
    })
    
    // Try referrers for manifest digest (most common for signatures)
    if err := c.pullReferrers(ctx, ref, image.Target(), referrersResolver); err != nil {
        log.G(ctx).WithError(err).Debugf("Failed to pull referrers for manifest digest %s", image.Target().Digest)
    }
    
    // Also try referrers for config digest (some tools associate referrers with the image ID)
    if err := c.pullReferrers(ctx, ref, configDesc, referrersResolver); err != nil {
        log.G(ctx).WithError(err).Debugf("Failed to pull referrers for config digest %s", configDesc.Digest)
    }
}
```

**Why pull for both manifest and config digests?**
- Most signature tools attach to the **manifest digest** (what you pull by tag)
- Some tools attach to the **config digest** (the image ID)
- Pulling both ensures we find signatures regardless of attachment point

#### 3. Referrers Discovery and Pull
**File:** `internal/cri/server/images/image_pull.go` (Lines 818-890)

```go
func (c *CRIImageService) pullReferrers(ctx context.Context, ref string, target ocispec.Descriptor, resolver remotes.Resolver) error {
    log.G(ctx).Debugf("Fetching referrers for ref=%q, digest=%s", ref, target.Digest)
    
    // Get the fetcher from the resolver
    fetcher, err := resolver.Fetcher(ctx, ref)
    if err != nil {
        return fmt.Errorf("failed to get fetcher for referrers: %w", err)
    }
    
    // Use ReferrersFetcher interface for discovery
    referrersFetcher, ok := fetcher.(remotes.ReferrersFetcher)
    if !ok {
        log.G(ctx).Debugf("Fetcher does not implement ReferrersFetcher interface, skipping referrers discovery")
        return nil
    }
    
    // Call FetchReferrers to get the OCI index of referrers
    readCloser, _, err := referrersFetcher.FetchReferrers(ctx, target.Digest)
    if err != nil {
        log.G(ctx).WithError(err).Debugf("FetchReferrers failed for digest %s", target.Digest)
        return err
    }
    defer readCloser.Close()
    
    // Read and parse the referrers index
    indexData, err := io.ReadAll(readCloser)
    if err != nil {
        return fmt.Errorf("failed to read referrers response: %w", err)
    }
    
    var referrersIndex ocispec.Index
    if err := json.Unmarshal(indexData, &referrersIndex); err != nil {
        return fmt.Errorf("failed to parse referrers index: %w", err)
    }
    
    if len(referrersIndex.Manifests) == 0 {
        log.G(ctx).Debugf("No referrers found for image %q with digest %s", ref, target.Digest)
        return nil
    }
    
    log.G(ctx).Infof("Found %d referrers for image %q", len(referrersIndex.Manifests), ref)
    
    // Pull each referrer
    for i, refDesc := range referrersIndex.Manifests {
        log.G(ctx).Debugf("Pulling referrer %d/%d (digest: %s)", i+1, len(referrersIndex.Manifests), refDesc.Digest)
        if err := c.pullSingleReferrer(ctx, fetcher, ref, refDesc); err != nil {
            log.G(ctx).WithError(err).Warnf("Failed to pull referrer %s", refDesc.Digest)
            continue
        }
    }
    
    log.G(ctx).Infof("Successfully pulled %d referrers for image %q", len(referrersIndex.Manifests), ref)
    return nil
}
```

#### 4. Individual Referrer Pull
**File:** `internal/cri/server/images/image_pull.go` (Lines 892-950)

```go
func (c *CRIImageService) pullSingleReferrer(ctx context.Context, fetcher remotes.Fetcher, ref string, refDesc ocispec.Descriptor) error {
    log.G(ctx).Debugf("pullSingleReferrer: Starting pull of referrer %s (artifactType: %s)", refDesc.Digest, refDesc.ArtifactType)
    
    // Fetch the referrer manifest
    reader, err := fetcher.Fetch(ctx, refDesc)
    if err != nil {
        return fmt.Errorf("failed to fetch referrer manifest: %w", err)
    }
    defer reader.Close()
    
    // Read manifest content
    manifestData, err := io.ReadAll(reader)
    if err != nil {
        return fmt.Errorf("failed to read referrer manifest: %w", err)
    }
    
    // Store in content store
    contentWriter, err := c.client.ContentStore().Writer(ctx,
        content.WithDescriptor(refDesc),
        content.WithRef(fmt.Sprintf("referrer-%s", refDesc.Digest)),
    )
    if err != nil {
        return fmt.Errorf("failed to create content writer: %w", err)
    }
    defer contentWriter.Close()
    
    if _, err := contentWriter.Write(manifestData); err != nil {
        return fmt.Errorf("failed to write referrer content: %w", err)
    }
    
    if err := contentWriter.Commit(ctx, refDesc.Size, refDesc.Digest); err != nil {
        if !errdefs.IsAlreadyExists(err) {
            return fmt.Errorf("failed to commit referrer content: %w", err)
        }
    }
    
    // Parse manifest to get layers
    var manifest ocispec.Manifest
    if err := json.Unmarshal(manifestData, &manifest); err != nil {
        return fmt.Errorf("failed to parse referrer manifest: %w", err)
    }
    
    // Pull each layer in the referrer
    for _, layer := range manifest.Layers {
        log.G(ctx).Debugf("Pulling referrer layer %s", layer.Digest)
        layerReader, err := fetcher.Fetch(ctx, layer)
        if err != nil {
            return fmt.Errorf("failed to fetch referrer layer: %w", err)
        }
        defer layerReader.Close()
        
        // Store layer in content store
        // ... (similar to manifest storage)
    }
    
    return nil
}
```

### Referrers API Details

#### Request Flow
```
Client: GET /v2/<name>/referrers/<digest>
Server: Returns OCI Index listing all referrers

Example Response:
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:abc123...",
      "size": 1234,
      "artifactType": "application/vnd.cncf.dmverity.signature.v1",
      "annotations": {
        "org.opencontainers.image.created": "2025-10-06T..."
      }
    }
  ]
}
```

#### Registry Capabilities Required
The registry must support the `referrers` capability. This is configured in hosts.toml:

```toml
[host."https://registry.example.com"]
  capabilities = ["pull", "resolve", "referrers"]
  # Numeric value: 1 + 2 + 8 = 11
```

**Capability Bits:**
- `pull` = 1 (0x1) - Download blobs and manifests
- `resolve` = 2 (0x2) - Resolve tags to digests
- `push` = 4 (0x4) - Upload content
- `referrers` = 8 (0x8) - Query referrers API

### Integration with Bridge

After referrers are pulled and stored in the content store, an external bridge process:

1. **Scans the content store** for referrer manifests
2. **Extracts signature layers** with annotations containing:
   - `layer_digest` - Which image layer this signature is for
   - `root_hash` - The dm-verity root hash
   - `signature` - Base64-encoded PKCS7 signature
3. **Creates signatures.json** in the signature-manifests directory
4. **Snapshotter reads** signatures.json on image pull

This completes the flow from registry → containerd → dm-verity verification.

---

## Modified Files Summary

### Core Functionality
1. **`plugins/snapshots/erofs/erofs_linux.go`**
   - Fixed `prepareSignatureFile()` to extract PKCS7 from double-encoded JSON
   - Removed early return to always regenerate .sig files
   - Cleaned up debug logging

2. **`internal/cri/server/images/image_pull.go`**
   - **NEW:** Added `pullReferrers()` function to discover and pull referrers using OCI Referrers API
   - **NEW:** Added `pullSingleReferrer()` to download individual referrer manifests and layers
   - **NEW:** Integrated referrers pull into main image pull flow (after image pull, before unpack)
   - **NEW:** Pull referrers for both manifest digest and config digest
   - Cleaned up verbose logging to use `Debugf` instead of `Infof`

3. **`internal/cri/server/images/service.go`**
   - **NEW:** Added `EnableReferrersPull` configuration support to toggle referrers functionality

4. **`.gitignore`**
   - Updated to ignore build artifacts and logs

---

## Deployment Steps

### 1. Build New Binary
```bash
cd /home/dallas/src/containerd
make binaries
```

### 2. Deploy to Test VM
```bash
scp -i <ssh-key> ./bin/containerd <user>@<vm-ip>:~
ssh -i <ssh-key> <user>@<vm-ip>
sudo systemctl stop containerd
sudo cp ~/containerd /usr/bin/containerd
sudo systemctl start containerd
```

### 3. Verify Configuration
```bash
# Check containerd config
cat /etc/containerd/config.toml | grep -A 5 referrers

# Check registry hosts
cat /etc/containerd/certs.d/*/hosts.toml

# Check kernel keyring
keyctl list %keyring:.platform
```

### 4. Test Image Pull
```bash
# Test with signed image
crictl pull <signed-image>

# Check logs
journalctl -u containerd -f
```

---

## References

- **dm-verity documentation:** https://man7.org/linux/man-pages/man8/veritysetup.8.html
- **OCI Referrers API:** https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers
- **PKCS#7 Format:** https://datatracker.ietf.org/doc/html/rfc2315
- **Kernel Keyring:** https://www.kernel.org/doc/html/latest/security/keys/core.html

---

## Future Improvements

1. **Validation:** Add format validation in `prepareSignatureFile()` to check first bytes are `30 82` (DER SEQUENCE)
2. **Metrics:** Add counters for signature verification success/failure rates
3. **Caching:** Consider smarter .sig file regeneration based on content hash
4. **Testing:** Add unit tests for double-decoding logic
5. **Documentation:** Add troubleshooting guide to containerd docs

---

**Status:** ✅ Complete and Verified  
**Build Date:** October 6, 2025  
**Tested:** October 7-8, 2025
