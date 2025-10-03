# OCI Referrers Support in containerd v2

containerd v2 includes comprehensive support for [OCI Referrers](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers), enabling automatic discovery and pulling of artifacts associated with container images. This implementation uses the proper **ReferrersFetcher interface** for dynamic referrer discovery, matching the approach used by Microsoft Kata Containers and other modern container runtimes.

## What are Referrers?

Referrers are OCI artifacts that reference other artifacts (typically container images) through their digest. Common use cases include:

- **Security signatures** (e.g., Sigstore, Notary v2)
- **Software bill of materials (SBOM)** attestations
- **Filesystem integrity signatures** (e.g., EROFS, dm-verity) - used by Azure Linux
- **Vulnerability scan reports**
- **Supply chain metadata**

## Key Features

✅ **Dynamic Discovery** - No hardcoded referrer mappings required  
✅ **ReferrersFetcher Interface** - Proper OCI Distribution Spec implementation  
✅ **Registry Capability Support** - Configurable per-registry via `hosts.toml`  
✅ **Multi-Method Fallback** - OCI API, direct resolution, and tag-based discovery  
✅ **Azure Container Registry Support** - Tested with Azure Linux images  

## Configuration

### CRI Configuration

Enable referrers pulling in your containerd CRI configuration:

```toml
version = 2

[plugins."io.containerd.cri.v1.images"]
  enable_referrers_pull = true

[plugins."io.containerd.cri.v1.images".registry]
  config_path = "/etc/containerd/certs.d"
```

### Registry Host Configuration

For registries that support the referrers API (like Azure Container Registry), create a `hosts.toml` file:

```bash
# Create hosts directory for your registry
mkdir -p /etc/containerd/certs.d/liunancr.azurecr.io

# Create hosts.toml with referrers capability
cat > /etc/containerd/certs.d/liunancr.azurecr.io/hosts.toml << 'EOF'
server = "https://liunancr.azurecr.io"

[host."https://liunancr.azurecr.io"]
  capabilities = ["pull", "resolve", "referrers"]
  skip_verify = false
EOF
```

The `referrers` capability tells containerd that this registry supports the OCI Referrers API.

### Command Line Usage

Use the `--referrers` flag with `ctr`:

```bash
ctr image pull --referrers docker.io/library/hello-world:latest
```

## Validation and Testing

### Quick Validation

Test referrers pulling with Azure Linux (known to have EROFS signature referrers):

```bash
# 1. Ensure you're authenticated to Azure Container Registry
az acr login --name liunancr

# 2. Pull the image with crictl (CRI client)
crictl pull liunancr.azurecr.io/azurelinux/busybox:1.36

# 3. Check containerd logs for successful referrer discovery
tail -100 containerd.log | grep -E "referrer|FetchReferrers"
```

### Expected Successful Output

When referrers are successfully pulled, you'll see logs like:

```
time="2025-10-02T00:14:58.155560946Z" level=info msg="Successfully fetched referrers, descriptor: mediaType=application/vnd.oci.image.index.v1+json, size=0"
time="2025-10-02T00:14:58.155667362Z" level=info msg="Response content: {\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:38dfa10d185eb899ff94a02a360f6e431f78232eda2f3b2a56a83d4f8c4c3d76\",\"size\":5079,\"annotations\":{\"image.ref.name\":\"liunancr.azurecr.io/azurelinux/busybox:1.36\",\"org.opencontainers.image.created\":\"2025-06-05T21:08:24.681369861+00:00\"},\"artifactType\":\"application/vnd.oci.mt.pkcs7\"}]}"
time="2025-10-02T00:14:58.155744374Z" level=info msg="Successfully parsed referrers index with 1 manifests"
time="2025-10-02T00:15:23.004377836Z" level=info msg="OCI referrers API returned 1 referrers"
```

### Verify Referrer Content

Check that the referrer was actually pulled:

```bash
# The referrer manifest digest for Azure Linux busybox:1.36
REFERRER_DIGEST="sha256:38dfa10d185eb899ff94a02a360f6e431f78232eda2f3b2a56a83d4f8c4c3d76"

# Check if it exists in content store
ctr content ls | grep ${REFERRER_DIGEST}

# Inspect the referrer content
ctr content get ${REFERRER_DIGEST} | jq .
```

Expected referrer content structure:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.oci.mt.pkcs7",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "size": 2,
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.erofs.sig",
      "digest": "sha256:a2590e920e2826ba63138c3773f8dcf1a3573a232a71c8ada0e41360708c4d7d",
      "size": 1933,
      "annotations": {
        "image.layer.digest": "sha256:bfea0ca9eae3f210b25b8b72f0d585f7bf072deb969e883b600be5ab530e4be8",
        "image.layer.root_hash": "bbc5eb630285e35804912451d25e30b03439f4c56fb015e5c3b8830d2b8c2b8f",
        "image.layer.signature": "MIIFEQYJKoZIhvcNAQcCoIIFAjCCBP4CAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGgggNlMIIDYTCCAkmgAwIBAgIRANykMm5OjUuOuHusH7EO7UMwDQYJKoZIhvcNAQELBQAwMDEuMCwGA1UEAxMlTGludXhHdWFyZCBUZXN0IENlcnRNdWxlIEVwaGVtZXJhbCBDQTAeFw0yNTA2MDUxODQyMjVaFw0zNTA2MDMxODQyMjVaMCgxJjAkBgNVBAMTHUxpbnV4R3VhcmQgVGVzdCBTVEsgRXBoZW1lcmFsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzPZx74r5f5DmkWT527wCnfyhJhuJU4NUhwUsxupnBPnEjasPfGMHCUryCmTTq0XExDGgz9zs0PtWQD2pv48wAWwhiXILZQVFF1jH0lC8DPpZx71yKu6Wqa2Ir3xMTBSvY6A21hrc8Po5RzMo3vRbfjxPXnjG5AgqgkkbGz3PVhUo6dCk8uviRcPg5xHc9DOLk0aKctFXGEnOj4oXax6/aFVeuw+iHUTw++PZmTMnrOcbJKLM3fLaZGtF4wvvEGqEmTc720ajeBA7hESpJJKSVGArnS0TCMInEpoCBsLozJ25gH0IhrzYaDLpswv2A9c9PDFranvmCIaVNz7M/tLzWQIDAQABo34wfDAfBgNVHSMEGDAWgBSy9cOpOssmPvSMt38ZYUxwAEmPCTAVBglghkgBhvhCAQEBAf8EBQMDAPABMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIEsDAdBgNVHQ4EFgQUiKydjyfBL+Eqb9yI/dLs2lntkVswDQYJKoZIhvcNAQELBQADggEBADQZyHr4eNooJ57/0Lw0oFUeIjh56lpkDUeHRPh7PgOa2+ivbW+4t+NWU+pWDT0eB0Me3/blGsyayHdfBIHxTb3t3GGy2fr3JmtVGaFXgPYg90FfX1CjMrYsEGxLd2rUy31HttURoA188RF8xZJybd8wZy8cnyqNqKyJJbNd7762VaU2Q+dSYRsriJSQ4GCPICFnNZ/ANwkbGYtmXuN7yfeE9M76tYZ1lXsp4OPuhAoCOI3iKkyrdnNVaP9xze0TqEkAd/XDIi3jEgy8qXTVeCog0Vexm3Q7ZfVp0hRxoEsQ0UQvFh9gmE4e/e72Axy9ll1CpD0d9YxpWtOknGYG/6oxggFwMIIBbAIBATBFMDAxLjAsBgNVBAMTJUxpbnV4R3VhcmQgVGVzdCBDZXJ0TXVsZSBFcGhlbWVyYWwgQ0ECEQDcpDJuTo1Ljrh7rB+xDu1DMA0GCWCGSAFlAwQCAQUAMA0GCSqGSIb3DQEBAQUABIIBAGXcq7Yla2h+BSQxEWvLYKTsNV0B97EM/ee2Yqmp58nS/UVT+DFLMKhIXGx4u4l79EPiPIrwQKJA3LInIG9doDlvegqP1nIZNnjCB+LeoXscHlhwefKPpC5zC4agFx3qAQUCU7fLsNSogdpTMeuUUhvlIbZCT133XKZ3TNJjN1n29b03NCiArBn+ajeGO7EiwIC2MOy1LG2NbM78KyXyJWgV1LW/boK/k4uQjpl61pe4G4gsfudlr1CayKtyeCwQ0UMkgfI1YPDh+dtdA8rdIwD9q56lke2SG51BFU2Y7ktWyNYdSyf55EkVlIbEtE3/aoSn66SwAfnhDi86tyZihpA=",
        "signature.blob.name": "signature_for_layer_bfea0ca9eae3f210b25b8b72f0d585f7bf072deb969e883b600be5ab530e4be8.json"
      }
    }
  ]
}
```

## Storage Location

Referrer artifacts are stored in containerd's content store alongside the main image:

```
/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/
├── abc123...def456  # Main image manifest
├── fed789...abc012  # Referrer manifest 1
├── 456def...789ghi  # Referrer manifest 2
└── ...              # Referrer content blobs
```

## Real-World Example: Azure Linux EROFS Signatures

Azure Linux container images include EROFS filesystem integrity signatures as referrers:

```bash
# Pull Azure Linux image with referrers
ctr image pull --referrers liunancr.azurecr.io/azurelinux/busybox:1.36

# Inspect the referrers
ctr content ls | grep $(ctr image ls -q liunancr.azurecr.io/azurelinux/busybox:1.36)
```

The referrer contains:
- **EROFS root hashes** for filesystem verification
- **Microsoft PKCS#7 signatures** with LinuxGuard certificates  
- **dm-verity metadata** for block-level integrity

### Expected Real Data

When you pull the Azure Linux image, you should see referrer content like:

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.oci.mt.pkcs7",
  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "size": 2,
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.erofs.sig",
      "size": 4096,
      "digest": "sha256:bbc5eb630285e358...",
      "annotations": {
        "image.layer.root_hash": "bbc5eb630285e358...",
        "image.layer.digest": "sha256:12d2d5b73c70632b...",
        "image.layer.signature": "MIIKmwYJKoZIhvcNAQcCoIIKjDCCCog..."
      }
    }
  ]
}
```

## Discovery Methods

containerd implements multiple discovery strategies for maximum compatibility:

### 1. ReferrersFetcher Interface (Primary)

The implementation uses the proper **ReferrersFetcher interface** from `core/remotes/resolver.go`:

```go
type ReferrersFetcher interface {
    FetchReferrers(ctx context.Context, dgst digest.Digest, artifactTypes ...string) (io.ReadCloser, ocispec.Descriptor, error)
}
```

This interface is implemented in `core/remotes/docker/referrers.go` and provides:
- **Host capability filtering** - Only queries registries with `HostCapabilityReferrers`
- **OCI API calls** - Uses standard `GET /v2/<name>/referrers/<digest>` endpoint
- **Fallback support** - Automatically falls back to tag-based discovery if API fails

### 2. Direct Resolution

Attempts to resolve referrers by constructing direct references and checking if they exist in the registry.

### 3. Tag-Based Fallback

When the referrers API is unavailable, containerd searches for referrer tags using comprehensive patterns:

- Cosign signatures: `sha256-<digest>.sig`, `<digest>.sig`
- Cosign attestations: `sha256-<digest>.att`, `<digest>.att`
- Notary v2: `<digest>.nv2.sig`, `sha256-<digest>.nv2.sig`
- SBOM artifacts: `<digest>.sbom`, `sha256-<digest>.sbom`
- Generic referrers: `sha256-<digest>`, `<digest>.ref`
- And 30+ additional patterns

### Why ReferrersFetcher Interface?

This implementation matches the approach used by:
- **Microsoft Kata Containers** - Uses the same ReferrersFetcher pattern
- **ORAS project** - Provides the oci-client library patterns
- **Modern OCI tools** - Standard interface for referrer discovery

Benefits:
- ✅ No hardcoded referrer mappings needed
- ✅ Proper abstraction layer for registry-specific behavior
- ✅ Configuration-driven capability discovery
- ✅ Handles authentication transparently

## Debug Logging

Enable debug logging to monitor referrers discovery:

```toml
[debug]
  level = "debug"
```

Look for log entries with these prefixes:
- `[dallas] 🔍` - Referrers discovery operations
- `[dallas] 📦` - Referrer content inspection
- `[dallas] 🔐` - Security artifact detection
- `[dallas] 📝` - Root hash and signature extraction

## Implementation Details

### Architecture

The referrers implementation consists of several key components:

#### Core Components

1. **ReferrersFetcher Interface** (`core/remotes/resolver.go`)
   ```go
   type ReferrersFetcher interface {
       FetchReferrers(ctx context.Context, dgst digest.Digest, artifactTypes ...string) (io.ReadCloser, ocispec.Descriptor, error)
   }
   ```

2. **Docker Fetcher Implementation** (`core/remotes/docker/referrers.go`)
   - Implements `FetchReferrers()` method
   - Filters hosts by `HostCapabilityReferrers` capability
   - Makes OCI Distribution Spec API calls
   - Provides automatic fallback to Cosign tag patterns

3. **Host Capability System** (`core/remotes/docker/registry.go`)
   - `HostCapabilityReferrers` bit flag
   - Configured via `hosts.toml` files
   - Enables per-registry referrer support configuration

4. **Configuration Parser** (`core/remotes/docker/config/hosts.go`)
   - Parses `capabilities = ["pull", "resolve", "referrers"]`
   - Sets `HostCapabilityReferrers` flag for configured hosts

5. **CRI Integration** (`internal/cri/server/images/image_pull.go`)
   - Calls `pullReferrers()` during image pull
   - Uses `ReferrersFetcher` interface for discovery
   - Handles both manifest and config digest referrers
   - Falls back gracefully on errors

### Discovery Flow

```
Image Pull Request
    ↓
Enable Referrers Pull? → No → Skip referrers
    ↓ Yes
Get Resolver & Fetcher
    ↓
Cast to ReferrersFetcher
    ↓
Call FetchReferrers(digest)
    ↓
Filter Hosts by HostCapabilityReferrers
    ↓
Try: GET /v2/<name>/referrers/<digest>
    ↓
Parse OCI Index Response
    ↓
Pull Each Referrer Manifest
    ↓
Store in Content Store
```

### Content Storage

- **Discovery**: Automatic during image pull operations
- **Storage**: Integrated with containerd content store at `/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/`
- **Validation**: Content descriptors verified against digests
- **Performance**: Concurrent pulling of referrers (errors don't block main image)

### Error Handling

- ✅ Referrer failures don't block main image pulls (logged as debug/warn)
- ✅ Comprehensive fallback: OCI API → Direct Resolution → Tag-Based Discovery
- ✅ Graceful handling of registries without referrers support
- ✅ Detailed logging for troubleshooting (when debug enabled)

## Validation Documentation

For comprehensive validation procedures and expected data structures, see:

- [`VALIDATION_GUIDE.md`](VALIDATION_GUIDE.md) - Complete validation procedures
- [`DATA_STRUCTURES.md`](DATA_STRUCTURES.md) - Technical data structure reference
- [`REFERRERS_VALIDATION.md`](REFERRERS_VALIDATION.md) - Validation summary

## Testing Scripts

The repository includes several validation scripts:

- `validate_content_store.sh` - Content store validation
- `validate_referrers.go` - Programmatic validation
- `test_referrers.go` - Comprehensive test suite
- `test_cri_referrers.go` - CRI-specific tests
- `test_direct_referrers.go` - Direct API tests

## Example Output

When pulling an image with referrers enabled, you'll see logs like:

```
INFO[2024-01-01T12:00:00Z] [dallas] EnableReferrersPull config value: true for image "liunancr.azurecr.io/azurelinux/busybox:1.36"
INFO[2024-01-01T12:00:01Z] [dallas] Starting referrers pull for image "liunancr.azurecr.io/azurelinux/busybox:1.36"
INFO[2024-01-01T12:00:02Z] [dallas] 🔍 INSPECTING REFERRER CONTENT: digest=sha256:abc123...
INFO[2024-01-01T12:00:02Z] [dallas] 🔐 MICROSOFT PKCS#7 ARTIFACT detected - this is Azure Linux filesystem signature
INFO[2024-01-01T12:00:02Z] [dallas] 🔑 EROFS ROOT HASH FOUND: bbc5eb630285e358...
INFO[2024-01-01T12:00:03Z] [dallas] Successfully completed referrers pull
```

## Troubleshooting

### Common Issues

#### 1. "no pull hosts: not found" Error

**Problem**: ReferrersFetcher can't find any hosts with referrers capability.

**Solution**: Configure the registry in `hosts.toml`:

```bash
# Create hosts configuration
mkdir -p /etc/containerd/certs.d/<your-registry>
cat > /etc/containerd/certs.d/<your-registry>/hosts.toml << 'EOF'
server = "https://<your-registry>"

[host."https://<your-registry>"]
  capabilities = ["pull", "resolve", "referrers"]
EOF

# Restart containerd to load config
systemctl restart containerd  # or kill and restart ./bin/containerd
```

#### 2. Referrers Not Being Pulled

**Check 1**: Verify `enable_referrers_pull` is enabled:
```bash
grep -A 5 "io.containerd.cri.v1.images" /path/to/config.toml
# Should show: enable_referrers_pull = true
```

**Check 2**: Verify `config_path` is set:
```bash
# Should point to directory containing hosts.toml files
grep "config_path" /path/to/config.toml
```

**Check 3**: Check containerd logs for errors:
```bash
grep -i "referrer\|FetchReferrers" containerd.log | tail -20
```

#### 3. Azure Container Registry Authentication

**Problem**: 401 Unauthorized when fetching referrers.

**Solution**: Authenticate with Azure CLI:
```bash
az acr login --name <registry-name>
# Example: az acr login --name liunancr
```

#### 4. Registry Doesn't Support Referrers API

**Symptom**: Logs show "404 Not Found" from referrers endpoint.

**Expected Behavior**: This is normal! The implementation automatically falls back to:
1. Direct resolution attempts
2. Tag-based discovery patterns

If the image truly has no referrers, you'll see:
```
level=debug msg="found 0 referrers for image..."
```

### Verification Commands

```bash
# Check if referrers capability is enabled for a registry
cat /etc/containerd/certs.d/<registry>/hosts.toml

# Check if referrers are stored
ctr content ls | grep $(ctr images ls -q <image-name>)

# Verify content store structure
ls -la /var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/

# Watch containerd logs during pull
tail -f containerd.log | grep -i referrer

# Test with known working image
crictl pull liunancr.azurecr.io/azurelinux/busybox:1.36
```

### Debug Logging

Enable debug logging to see detailed referrer discovery:

```toml
[debug]
  level = "debug"
```

Look for these log patterns:
- `FetchReferrers` - ReferrersFetcher interface calls
- `Successfully fetched referrers` - Successful API responses
- `no pull hosts` - Missing host configuration
- `found N referrers` - Discovery results

## Contributing

To contribute to referrers functionality:

1. Review the implementation in `internal/cri/server/images/image_pull.go`
2. Add test cases using the existing validation framework
3. Update documentation for new referrer types or discovery patterns
4. Test with real referrer artifacts from various registries

## Related Standards

- [OCI Distribution Specification - Referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers)
- [OCI Image Specification](https://github.com/opencontainers/image-spec)
- [OCI Artifacts Specification](https://github.com/opencontainers/artifacts)
- [Cosign Specification](https://github.com/sigstore/cosign)
- [In-toto Attestation Framework](https://in-toto.readthedocs.io/)
- [Microsoft Kata Containers PR #357](https://github.com/microsoft/kata-containers/pull/357) - Reference implementation

## References

### Implementation Sources

This implementation is based on:

1. **Microsoft Kata Containers Fork** - ReferrersFetcher interface pattern
   - Repository: `github.com/microsoft/kata-containers`
   - PR #357: Adds referrers support using proper interface abstraction

2. **ORAS oci-client Library** - OCI API interaction patterns
   - Repository: `oras.land/oras-go/v2/registry/remote`
   - Provides registry client patterns and authentication handling

3. **containerd v2** - Core remotes and CRI infrastructure
   - Base commit: `29d2a24cd`
   - Microsoft's containerd fork with ReferrersFetcher interface

### Azure Container Registry Support

- **Authentication**: Uses OAuth2 via `az acr login`
- **API Endpoint**: `/v2/<name>/referrers/<digest>`
- **Artifact Types**: Microsoft PKCS#7 signatures for EROFS filesystems
- **Capabilities**: Must be enabled via `hosts.toml` configuration

### Known Registries with Referrers Support

- ✅ **Azure Container Registry (ACR)** - Full support with configuration
- ✅ **Docker Hub** - Supports OCI artifacts (requires paid plan)
- ✅ **GitHub Container Registry (GHCR)** - Native OCI support
- ✅ **Zot Registry** - Open source OCI registry with full support
- ⚠️ **Amazon ECR** - Limited support, check AWS documentation
- ⚠️ **Google Artifact Registry** - Check GCP documentation for OCI artifacts
