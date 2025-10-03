# Verifying OCI Referrers Pull with containerd v2

This guide explains exactly what to look for to confirm that OCI referrers (signatures, attestations, SBOMs) are actually being discovered and pulled by containerd v2.

## 🎯 What to Look For - Quick Checklist

### 1. **Enable Debug Logging First**
Add to your `containerd.toml`:
```toml
[debug]
  level = "debug"
  
[plugins]
  [plugins."io.containerd.cri.v1.images"]
    enable_referrers_pull = true
```

### 2. **Watch the Logs During Image Pull**
Start tailing containerd logs:
```bash
# Watch containerd logs in real-time
journalctl -u containerd -f

# Or if using custom config:
tail -f /var/log/containerd.log
```

Then pull an image and look for these specific log entries:

**✅ PROOF THE REFERRER WAS ACTUALLY PULLED:**
```bash
# Pull the Azure Linux test image
ctr images pull liunancr.azurecr.io/azurelinux/busybox:1.36

# Look for these EXACT log entries that prove referrer was pulled:
```
```
DEBU[...] fetchReferrersByDirectResolution: Starting referrer discovery for digest=sha256:eec430d63f60bfcaf42664dafd179a5975f0c33610c7fc727c8f10ddaad61a06
DEBU[...] fetchReferrersByDirectResolution: Trying known referrers for digest sha256:eec430d...
DEBU[...] fetchReferrersByDirectResolution: Found referrer in known map: sha256:38dfa10d185eb899ff94a02a360f6e431f78232eda2f3b2a56a83d4f8c4c3d76
DEBU[...] fetchReferrersByDirectResolution: Successfully pulled referrer sha256:38dfa10d... (5079 bytes)
```

**🔍 ALTERNATIVE - Dynamic Pattern Discovery (for other images):**
```
DEBU[...] fetchReferrersByDirectResolution: No known referrers, trying dynamic discovery
DEBU[...] discoverReferrersForDigest: Trying pattern-based discovery for sha256:abc123...
DEBU[...] discoverReferrersThroughPatterns: Trying pattern abc123.sig
DEBU[...] discoverReferrersThroughPatterns: Found referrer via pattern: sha256:def456...
DEBU[...] validateReferrerRelationship: Validating referrer sha256:def456... references sha256:abc123...
DEBU[...] fetchReferrersByDirectResolution: Successfully pulled referrer sha256:def456... (X bytes)
```

**❌ NO REFERRERS AVAILABLE (Normal for most images):**
```
DEBU[...] fetchReferrersByDirectResolution: No referrers found for digest sha256:xyz789...
DEBU[...] fetchReferrersByDirectResolution: Falling back to OCI API and tag-based discovery
```

### 3. **CRITICAL: Verify Referrer Content is Actually Stored**
This is the definitive proof that the referrer was pulled:

```bash
# List ALL content in containerd store
ctr content ls

# You MUST see BOTH of these digests for Azure Linux:
# sha256:eec430d63f60bfcaf42664dafd179a5975f0c33610c7fc727c8f10ddaad61a06  (main image)
# sha256:38dfa10d185eb899ff94a02a360f6e431f78232eda2f3b2a56a83d4f8c4c3d76  (referrer)
```

**Expected Output:**
```
DIGEST                                                                  SIZE      AGE             LABELS
sha256:eec430d63f60bfcaf42664dafd179a5975f0c33610c7fc727c8f10ddaad61a06    1.23kB    2 minutes       containerd.io/gc.ref.content.0=sha256:38dfa10d...
sha256:38dfa10d185eb899ff94a02a360f6e431f78232eda2f3b2a56a83d4f8c4c3d76    5.07kB    2 minutes       containerd.io/gc.root=2024-10-01T17:00:00.000Z
```

**If you see BOTH digests → ✅ REFERRER WAS PULLED!**  
**If you only see the main image digest → ❌ REFERRER WAS NOT PULLED**

### 4. **Verify Referrer Content and Relationship**
Double-check the referrer actually references your image:

```bash
# Get the referrer content and check its subject field
ctr content get sha256:38dfa10d185eb899ff94a02a360f6e431f78232eda2f3b2a56a83d4f8c4c3d76 | jq '.subject.digest'

# MUST output exactly:
# "sha256:eec430d63f60bfcaf42664dafd179a5975f0c33610c7fc727c8f10ddaad61a06"
```

**If the subject digest matches your image digest → ✅ VALID REFERRER RELATIONSHIP**

## � Troubleshooting: If Referrer is NOT Pulled

### **❌ Problem: No Referrer Logs at All**
**What to check:**
```bash
# 1. Verify containerd is using your config
containerd config dump | grep enable_referrers_pull
# Should show: enable_referrers_pull = true

# 2. Restart containerd after config changes  
systemctl restart containerd

# 3. Make sure you're using debug logging
grep -i "level.*debug" /etc/containerd/config.toml
```

### **❌ Problem: Authentication Errors in Logs**
**What you'll see:**
```
ERRO[...] failed to pull referrer: 401 Unauthorized
```
**Solutions:**
```bash
# For Azure Container Registry, login first:
az acr login --name liunancr

# Or use credentials directly:
ctr images pull --user <username>:<password> liunancr.azurecr.io/azurelinux/busybox:1.36
```

### **❌ Problem: "fetchReferrersByDirectResolution" Logs Missing**
**This means the function isn't being called at all**
**Check:**
1. You're using the modified `image_pull.go` code
2. You rebuilt containerd with `make bin/containerd`
3. You're running the newly built containerd binary

### **❌ Problem: Referrer Content Not in Store**
**If `ctr content ls` only shows the main image:**
```bash
# Check containerd logs for errors during referrer pull
journalctl -u containerd | grep -i "referrer\|error"

# Verify the referrer digest exists in the registry
# (This proves the referrer exists but wasn't pulled)
```

## 📊 Monitoring Referrer Performance

### **Metrics to Track:**
- **Discovery Time:** How long referrer discovery takes
- **Hit Rate:** Percentage of images with found referrers  
- **Method Distribution:** Known vs Pattern vs Catalog discovery usage
- **Validation Success:** Percentage of discovered referrers that validate

### **Performance Optimization:**
- Add frequently-used images to known referrers map
- Implement caching for discovered referrers
- Configure concurrent discovery limits
- Use registry-specific discovery optimizations

## ✅ Step-by-Step Test Procedure

### **Test with Azure Linux (Known to Have Referrers):**

```bash
# Step 1: Enable debug logging and restart containerd
sudo systemctl restart containerd

# Step 2: Clear any existing content (optional)
ctr content ls  # Note what's there before

# Step 3: Pull the image while watching logs
# Terminal 1: Watch logs
journalctl -u containerd -f | grep -i referrer

# Terminal 2: Pull the image  
ctr images pull liunancr.azurecr.io/azurelinux/busybox:1.36

# Step 4: IMMEDIATELY check content store
ctr content ls | grep -E "(eec430d|38dfa10d)"
```

### **Expected Results if Working:**

**In logs (Terminal 1):**
```
DEBU[...] fetchReferrersByDirectResolution: Starting referrer discovery...
DEBU[...] fetchReferrersByDirectResolution: Successfully pulled referrer sha256:38dfa10d... (5079 bytes)
```

**In content store (Terminal 2):**
```
sha256:eec430d63f60bfcaf42664dafd179a5975f0c33610c7fc727c8f10ddaad61a06    1.23kB
sha256:38dfa10d185eb899ff94a02a360f6e431f78232eda2f3b2a56a83d4f8c4c3d76    5.07kB  <- REFERRER!
```

## 🎯 Definitive Success Criteria

**✅ REFERRER PULL CONFIRMED when you have:**
1. **Both digests in content store** (main image + referrer)
2. **Log entry showing bytes pulled** (5079 bytes for Azure Linux referrer)
3. **Valid subject relationship** (referrer points back to main image)

**❌ REFERRER PULL FAILED when you have:**
1. **Only main image digest** in content store  
2. **No referrer logs** during image pull
3. **Authentication errors** in logs

## � Quick Verification Commands

```bash
# One-liner to check if referrer was pulled for Azure Linux:
ctr content ls | grep -c "38dfa10d" && echo "✅ REFERRER PULLED" || echo "❌ NO REFERRER"

# Verify referrer content and relationship:
ctr content get sha256:38dfa10d185eb899ff94a02a360f6e431f78232eda2f3b2a56a83d4f8c4c3d76 | jq -r '.subject.digest'
# Must output: sha256:eec430d63f60bfcaf42664dafd179a5975f0c33610c7fc727c8f10ddaad61a06

# Check total content count before and after:
echo "Before: $(ctr content ls | wc -l) items"
ctr images pull liunancr.azurecr.io/azurelinux/busybox:1.36
echo "After: $(ctr content ls | wc -l) items"
# Should increase by at least 2 (image + referrer)
```

The **key indicator** is seeing both the main image digest AND the referrer digest in your content store after the pull. If you see both, the referrer was successfully discovered and pulled!
