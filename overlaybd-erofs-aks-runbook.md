# EROFS streaming on AKS — end-to-end runbook

Every command needed to reproduce AKS Artifact Streaming with an EROFS
lower layer, from a blank subscription to a running pod whose rootfs is
backed by `erofs`. Self-contained.

> **Audience.** Validating or demoing EROFS streaming on AKS *today*,
> before the ACR converter exposes `--fstype`.
>
> **Wall time.** ~25 minutes (most of it `az aks create`).
>
> **Need.** Subscription where you can push to a Premium ACR and create
> an `AcrPull` role assignment (Owner / User Access Administrator on the
> ACR scope).
>
> **Dev box prereqs.** Linux (AzL3 or Ubuntu) with `docker`, `kubectl`,
> `jq`, `oras` ≥1.2, `azure-cli`, and the `aks-preview` extension
> (installed in step 1). Run steps 0–7 in one shell so the bash
> variables persist.

---

## 0 — Variables

Set once, reused everywhere.

```bash
# Pick your own names; the rest of the runbook expands these.
sub=b8f169b2-5b23-444a-ae4b-19a31b5e3652       # subscription to operate in
rg=aadagarwal-as-520                    # resource group
aks_loc=westus3                                # AKS location (streaming preview region)
loc=$aks_loc                                   # ACR location — same as AKS so byte-range fetches stay in-region
acr=aadagarwalas520                       # ACR name (must be globally unique, alphanumeric)
cluster=erofs-as-520                          # AKS cluster name
src_image=library/nginx                        # repo path inside the ACR
src_tag=alpine                                 # tag for the source image

az account set -s "$sub"                       # make sure every subsequent command targets the right sub
```

---

## 1 — One-time subscription + CLI prep

```bash
# Register the artifact-streaming preview feature (idempotent; takes a few
# minutes to flip to "Registered" the first time).
az feature register --namespace Microsoft.ContainerService \
  --name ArtifactStreamingPreview
az provider register --namespace Microsoft.ContainerService

# aks-preview gives us the --enable-artifact-streaming flag on `az aks create`.
az extension add --name aks-preview --upgrade -y
```

---

## 2 — Create RG + Premium ACR

```bash
# Resource group to hold ACR + cluster. Single RG keeps cleanup trivial.
az group create -n "$rg" -l "$loc"

# Streaming requires Premium SKU (referrer API + content-trust headers).
az acr create -n "$acr" -g "$rg" --sku Premium -l "$loc"
```

---

## 3 — Install overlaybd convertor on the dev box (AzL3 / Ubuntu)

```bash
# overlaybd ships C++ helpers (overlaybd-create, turboOCI-apply) used by
# the convertor. RPMs on AzL3; the same release page has .deb for Ubuntu.
sudo tdnf install -y \
  https://github.com/containerd/overlaybd/releases/download/v1.0.16/overlaybd-1.0.16-20250818.4601fb2.azurelinux.3.0.x86_64.rpm \
  https://github.com/containerd/accelerated-container-image/releases/download/v1.4.3/overlaybd-snapshotter-1.4.3-20260330130113.43c3295.x86_64.rpm

# Sanity-check: the convertor and its C++ helpers are now on PATH.
ls /opt/overlaybd/bin/overlaybd-create /opt/overlaybd/snapshotter/convertor
```

---

## 4 — Push the source image into the ACR

The convertor pulls *from* `$acr` and pushes back; the upstream image must
already live there.

```bash
# Authenticate docker to ACR.
az acr login -n "$acr"

# Pull upstream image and retag.
docker pull --platform linux/amd64 "nginx:$src_tag"
docker tag "nginx:$src_tag" "$acr.azurecr.io/$src_image:$src_tag"
docker push "$acr.azurecr.io/$src_image:$src_tag"
```

---

## 5 — Convert: TurboOCIv1 + EROFS, push as referrer

```bash
# `--expose-token` gives an ACR-scoped bearer the convertor can pass via -u.
# The "refresh token" warning is misleading; it works as the password when
# paired with the magic GUID username (Azure docker-login convention).
TOKEN=$(az acr login -n "$acr" --expose-token --query accessToken -o tsv)

rm -rf /tmp/obd-work && mkdir -p /tmp/obd-work

# Run as root: the C++ helpers want to write /var/log/overlaybd*.log.
# -i <input-tag>          : tag to convert (required; or use -g <input-digest>).
# --turboOCI <output-tag> : TurboOCIv1 layout (tiny metadata layers, lazy
#                           data fetch).
# --fstype erofs          : tells turboOCI-apply to call LibErofs::extract_tar
# --referrer              : push as an OCI referrer of the source manifest
#                           (auto-enables --oci)
sudo /opt/overlaybd/snapshotter/convertor \
  --repository "$acr.azurecr.io/$src_image" \
  --username "00000000-0000-0000-0000-000000000000:$TOKEN" \
  -i "$src_tag" \
  --turboOCI "${src_tag}_obd-turbo-erofs" \
  --fstype erofs \
  --referrer \
  -d /tmp/obd-work

# Capture the resulting manifest digest for the next step. If multiple
# turbo referrers exist (e.g. from prior --fstype ext4 runs), this picks
# the most recently pushed one whose tag matches our erofs output — verify
# by hand if you've run --fstype both ways against this repo.
ours_digest=$(oras discover --format json "$acr.azurecr.io/$src_image:$src_tag" \
  | jq -r '.manifests[]
      | select(.artifactType=="application/vnd.containerd.overlaybd.turbo.v1+json")
      | .digest' \
  | tail -1)
echo "Our turbo+erofs manifest: $ours_digest"
[[ -n "$ours_digest" ]] || { echo "ERROR: convertor referrer not found"; return 1 2>/dev/null || exit 1; }
```

Optional sanity-check the referrer landed with the right shape:

```bash
# artifactType should be application/vnd.containerd.overlaybd.turbo.v1+json.
# Top-level "overlaybd/version" annotation is typically null — the
# "0.1.0-turbo.ociv1" string lives on each layer's annotations.
oras manifest fetch "$acr.azurecr.io/$src_image@$ours_digest" | jq '{
  artifactType,
  version: .annotations."overlaybd/version",
  sample_layer_annotations: .layers[1].annotations
}'
```

Strongest proof that `--fstype erofs` actually took effect (the manifest /
layer annotations are fs-type-agnostic, so you have to inspect the blob):

```bash
# Pull layer[1] and list its tar contents. An erofs conversion has
# `erofs.fs.meta` inside each layer tar; an ext4 conversion would have
# `ext4.fs.meta` instead. Same blobs otherwise.
layer_digest=$(oras manifest fetch "$acr.azurecr.io/$src_image@$ours_digest" \
  | jq -r '.layers[1].digest')
mkdir -p /tmp/erofs-check && cd /tmp/erofs-check
oras blob fetch --output layer1.tar.gz "$acr.azurecr.io/$src_image@$layer_digest"
tar tzf layer1.tar.gz
#   .turbo.ociv1          # TurboOCIv1 sentinel (fs-type agnostic)
#   erofs.fs.meta         # ← the success signal
#   gzip.meta             # per-layer compression sidecar
cd -
```

---

## 6 — Rebrand the manifest with the Azure artifactType

This is the trick that makes `acr-mirror` pick our manifest. The recognizer
is a pure exact-string match on `artifactType` — no payload validation —
so we keep the same blobs and only mutate two top-level fields.

```bash
mkdir -p /tmp/disguise && cd /tmp/disguise

# Pull the manifest JSON we just pushed.
oras manifest fetch "$acr.azurecr.io/$src_image@$ours_digest" > erofs.json

# Swap artifactType + add the four streaming.* annotations that Azure's
# own wrapper sets. The `subject` field is preserved automatically.
jq '
  .artifactType = "application/vnd.azure.artifact.streaming.v1"
  | .annotations = {
      "streaming.format":        "overlaybd",
      "streaming.platform.arch": "amd64",
      "streaming.platform.os":   "linux",
      "streaming.version":       "v1"
    }
' erofs.json > disguised.json

# Push the rebranded manifest. Tag is cosmetic — what makes acr-mirror
# find it is the preserved `subject` field pointing at the source image.
oras manifest push \
  --media-type application/vnd.oci.image.manifest.v1+json \
  "$acr.azurecr.io/$src_image:${src_tag}-disguised-erofs" \
  disguised.json

# Compute the digest locally — more portable than relying on oras flags.
disguised_digest="sha256:$(sha256sum disguised.json | awk '{print $1}')"
echo "Disguised erofs manifest: $disguised_digest"
```

---

## 7 — Make sure no competing Azure ext4 wrapper exists

If ACR ever auto-converted this image, delete that wrapper so acr-mirror
only has our erofs one to choose. **Order matters here:** disable the
auto-converter *first*, otherwise it can re-create the wrapper between
our delete and the next push.

```bash
# 1) Disable the auto-converter so deletes stick. (Repo must exist; safe
#    no-op on a repo that has never had streaming enabled.)
az acr artifact-streaming update -n "$acr" --repository "$src_image" \
  --enable-streaming false 2>/dev/null || true

# 2) Find any other referrer with the Azure artifactType.
azure_ref=$(oras discover --format json "$acr.azurecr.io/$src_image:$src_tag" \
  | jq -r --arg ours "$disguised_digest" '.manifests[]
      | select(.artifactType=="application/vnd.azure.artifact.streaming.v1")
      | select(.digest != $ours)
      | .digest')

# 3) Delete only if there is one (it is fine if there is none).
if [[ -n "$azure_ref" ]]; then
  oras manifest delete --force "$acr.azurecr.io/$src_image@$azure_ref"
fi

# 4) Optional: delete the now-orphan upstream-typed referrer too. Harmless
#    if left behind (acr-mirror ignores it) but it's dead data.
oras manifest delete --force "$acr.azurecr.io/$src_image@$ours_digest" || true

# 5) Wait for ACR's Referrers API to converge so the next pull sees our
#    disguised manifest. Usually instant, occasionally a few seconds.
for _ in $(seq 1 24); do
  oras discover --format json "$acr.azurecr.io/$src_image:$src_tag" \
    | jq -e --arg d "$disguised_digest" '.manifests[] | select(.digest==$d)' \
    >/dev/null && break
  sleep 5
done
```

---

## 8 — Create the AKS cluster, then enable streaming on the system pool

AKS uses two managed identities: a control-plane (cluster) MSI and a
per-nodepool kubelet MSI. `acr-mirror` authenticates as the **kubelet**
MSI, so that's the identity that needs `AcrPull` on the ACR.
`--attach-acr` is designed to grant `AcrPull` on the kubelet MSI and
usually does — step 9 is an explicit idempotent fallback for the cases
where it races or silently no-ops.

In `aks-preview` ≥20.0.0b1 the `--enable-artifact-streaming` flag is
**only** on `az aks nodepool {add,update}`, not `az aks create`. So we
create the cluster, then flip streaming on the system pool.

```bash
# --os-sku AzureLinux: AzL3 nodes ship overlaybd v1.0.16 + snapshotter v1.4.2.
# --attach-acr:        asks AKS to grant AcrPull on the kubelet MSI.
#                      Usually works; step 9 makes it explicit & idempotent.
az aks create -g "$rg" -n "$cluster" -l "$aks_loc" \
  --os-sku AzureLinux \
  --node-count 1 \
  --node-vm-size Standard_D4ds_v5 \
  --attach-acr "$acr" \
  --generate-ssh-keys

# Enable artifact streaming on the system pool. This provisions
# acr-mirror.service + the hosts.toml that routes *.azurecr.io through
# localhost:8578 on every node in the pool.
sys_pool=$(az aks nodepool list -g "$rg" --cluster-name "$cluster" \
  --query "[?mode=='System'].name | [0]" -o tsv)
az aks nodepool update -g "$rg" --cluster-name "$cluster" -n "$sys_pool" \
  --enable-artifact-streaming

az aks get-credentials -g "$rg" -n "$cluster" --overwrite-existing
```

---

## 9 — Make sure the kubelet identity has AcrPull on the ACR

`acr-mirror` authenticates to ACR with the kubelet managed identity (not
the pod's imagePullSecret). Without `AcrPull`, `acr-mirror` returns
503/401 and containerd silently falls through to a plain OCI pull.

`--attach-acr` in step 8 normally creates this assignment for you;
verifying it empirically on this cluster showed exactly one `AcrPull`
assignment on the kubelet MSI, created during `az aks create`. So in the
happy path this step is a no-op. We run it anyway as cheap, idempotent
insurance against the known sharp edges: RBAC-propagation races, missing
`Microsoft.Authorization/roleAssignments/write` on the ACR scope (which
makes `--attach-acr` silently skip), BYO kubelet identity, and
cross-subscription ACR.

```bash
# kubelet identity is a separate MSI from the cluster (control-plane) MSI.
# This is the identity acr-mirror uses to pull from ACR.
kubelet_obj=$(az aks show -g "$rg" -n "$cluster" \
  --query identityProfile.kubeletidentity.objectId -o tsv)
acr_id=$(az acr show -n "$acr" --query id -o tsv)

# Idempotent: `|| true` so re-runs don't fail when the assignment already exists.
az role assignment create \
  --role AcrPull \
  --assignee-object-id "$kubelet_obj" \
  --assignee-principal-type ServicePrincipal \
  --scope "$acr_id" || true
```

---

## 10 — Deploy the pod

```bash
kubectl run nginx-test \
  --image="$acr.azurecr.io/$src_image:$src_tag" \
  --restart=Never
kubectl wait --for=condition=ready pod/nginx-test --timeout=180s
```

---

## 11 — Verify streaming engaged with EROFS

```bash
node=$(kubectl get pod nginx-test -o jsonpath='{.spec.nodeName}')

# Privileged debug container that can chroot into the node's filesystem.
kubectl debug node/$node -it \
  --image=mcr.microsoft.com/azurelinux/base/core:3.0 -- chroot /host bash
```

Inside the chroot, run each block and check the expected output:

```bash
# 1) A TCMU device backing an overlaybd snapshot should exist. The disk
#    letter is VM-size-dependent (often /dev/sdb on D-series, /dev/sdc on
#    others) — match the mount path instead.
grep '/var/lib/containerd/io.containerd.snapshotter.v1.overlaybd/snapshots/.*/block/mountpoint' \
  /proc/mounts
#   /dev/sdb /var/lib/containerd/io.containerd.snapshotter.v1.overlaybd/snapshots/<N>/block/mountpoint \
#     erofs ro,relatime,user_xattr,acl,cache_strategy=readaround 0 0

# 2) The mount type column above should read `erofs`, not `ext4`. This is
#    the success signal.
grep '/var/lib/containerd/io.containerd.snapshotter.v1.overlaybd/snapshots/.*/block/mountpoint' \
  /proc/mounts | awk '{print $3}' | sort -u
#   erofs

# 3) Per-layer erofs.fs.meta files should be present (8 for nginx:alpine).
find /var/lib/containerd/io.containerd.snapshotter.v1.overlaybd \
  -name 'erofs.fs.meta' | wc -l
#   8

# 4) acr-mirror's journal should show it teleported our disguised manifest digest.
journalctl -u acr-mirror -n 200 --no-pager | grep -i teleport
#   ...Finished teleporting manifest ... /v2/library/nginx/manifests/sha256:5b8d7286...
```

If `/proc/mounts` shows `type ext4` instead of `type erofs`, something is
serving an ext4 wrapper. Re-run step 7 and re-pull (`kubectl delete pod
nginx-test && kubectl run ...`).

If `/proc/mounts` shows no `/dev/sd*` at all (only `overlay`), streaming
did not engage. The usual cause is missing AcrPull — re-check step 9 and
look in `journalctl -u acr-mirror` for `401`/`503`.

### 11b — Extended inspection (optional but illuminating)

Useful when you want to *understand* what the streaming stack is doing,
not just confirm it worked. All run on the node via the same `chroot
/host` debug pod from step 11 (or pipe through `kubectl exec` non-interactively).

```bash
# A) Functional test — prove the erofs-mounted rootfs actually serves traffic.
#    nginx reads /usr/share/nginx/html/index.html through the overlay rootfs,
#    whose lowerdir is the erofs mount of the TCMU block device.
pod_ip=$(kubectl get pod nginx-test -o jsonpath='{.status.podIP}')   # run on dev box, not node
curl -sS -o /dev/null -w 'HTTP %{http_code}  size=%{size_download}\n' "http://$pod_ip/"
#   HTTP 200  size=896

# B) Lazy-fetch proof — the virtual block device is huge, real cache is tiny.
#    The kernel sees /dev/sdb as a 64 GiB disk; the erofs superblock reports
#    only the populated blocks. The gap is what "streaming" means.
lsblk -b -o NAME,SIZE,TYPE /dev/sdb
#   sdb  68719476736 disk          (= 64 GiB virtual address space)
stat -f /var/lib/containerd/io.containerd.snapshotter.v1.overlaybd/snapshots/*/block/mountpoint \
  | grep -E 'Type|Block size|Blocks'
#   Type: erofs
#   Block size: 4096       Fundamental block size: 4096
#   Blocks: Total: 15985 ...    (~62 MB actually populated)

# C) TCMU backing — /dev/sdb is a userspace iSCSI target, not a real disk.
#    Vendor/model 'LIO-ORG / TCMU device' is the smoking gun. The configfs
#    path's dev_<N> matches the snapshot id from /proc/mounts above.
cat /sys/block/sdb/device/{vendor,model,rev} | tr -d '\n'; echo
#   LIO-ORG TCMU device     0002
find /sys/kernel/config/target/core -maxdepth 3 -type d | head -10
#   /sys/kernel/config/target/core/user_999999999/dev_120/...

# D) The two userspace daemons that make this work.
ps -eo pid,comm,args | grep -E 'overlaybd|tcmu' | grep -v grep
#   <pid> overlaybd-tcmu   /opt/overlaybd/bin/overlaybd-tcmu
#   <pid> overlaybd-snaps  /opt/overlaybd/snapshotter/overlaybd-snapshotter
systemctl is-active overlaybd-tcmu overlaybd-snapshotter acr-mirror
#   active
#   active
#   active

# E) hosts.toml mirror config — why containerd asks acr-mirror instead of ACR.
cat /etc/containerd/certs.d/_default/hosts.toml 2>/dev/null | head -20
#   server = "https://_default"
#   [host."http://localhost:8578"]
#     capabilities = ["pull", "resolve"]
#     override_path = true
```

Why each check is interesting:

- **A** rules out "the pod is happy but the data isn't real" — it's reading
  bytes out of the EROFS image, lazily, with no surprises.
- **B** is the single best argument for streaming: the kernel addresses
  a 64 GiB sparse device but only ~62 MB is actually present. A normal
  OCI pull would have downloaded all ~50 MB up front before container
  start; with streaming, blocks materialize as nginx touches them.
- **C/D** confirm the userspace path: overlaybd-snapshotter feeds containerd,
  overlaybd-tcmu services the kernel's block-device reads through TCMU. The
  `dev_<N>` ↔ snapshot id correlation proves the wiring is end-to-end.
- **E** explains why ACR pulls hit `localhost:8578` first: the AKS-baked
  `hosts.toml` rewrites every `*.azurecr.io` resolve through acr-mirror,
  which is what gives acr-mirror the chance to swap the manifest.

---

## 12 — Tear down

```bash
kubectl delete pod nginx-test --ignore-not-found
az aks delete -g "$rg" -n "$cluster" --yes --no-wait
az group delete -n "$rg" --yes --no-wait
```

---

## Why each step exists

- **1–4** — put the source image inside a Premium ACR (streaming uses
  ACR's referrer API + OAuth).
- **5** — produce the EROFS payload: a TurboOCIv1 manifest whose layer
  tars contain `erofs.fs.meta`. This is what AKS will mount.
- **6** — the workaround. ACR's converter hardcodes ext4 and `acr-mirror`
  only matches `application/vnd.azure.artifact.streaming.v1`, so we
  rename our manifest's artifactType to that string. Same blobs, new
  manifest digest, `acr-mirror` serves it.
- **7** — delete any pre-existing ACR ext4 wrapper that would otherwise
  beat ours.
- **8–9** — AKS cluster where every node has `acr-mirror` on
  `localhost:8578` with `hosts.toml` routing `*.azurecr.io` through it,
  and `acr-mirror` can authenticate to ACR (AcrPull on the *kubelet*
  MSI, which `--attach-acr` normally grants; step 9 makes it explicit).
- **10** — deploy a pod, triggering the streaming pull.
- **11** — confirm the kernel actually mounted `type erofs` on the TCMU
  device (a plain OCI pull would also produce a running pod).
- **12** — destructive teardown.
