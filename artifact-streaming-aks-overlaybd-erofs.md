# EROFS streaming on AKS — verified working

**TL;DR:** Yes, EROFS-on-overlaybd works on AKS Artifact Streaming today.
ACR's image converter is the only blocker.

## Proof

Full commands + verification:
[overlaybd-erofs-aks-runbook.md](overlaybd-erofs-aks-runbook.md).

## Background in one paragraph

AKS Artifact Streaming works in two halves. **(a)** ACR converts your
image into a streaming-friendly sibling artifact and attaches it to the
original via an OCI *referrer* (a manifest that points back at the
source by digest). **(b)** On each node, a small agent (`acr-mirror`)
intercepts pulls, finds that sibling via the Referrers API, and streams
it. The conversion is filesystem-specific: today ACR's converter only
emits **ext4**. We want **EROFS**.

## Workaround (why it's not clean)

1. **Convert the image to EROFS locally, outside ACR.**
   We run the open-source `overlaybd convertor` ourselves with
   `--fstype erofs`, then push the result to ACR as a referrer of the
   source image. We have to do this because ACR's hosted converter is
   hardcoded to ext4 — no flag to pick EROFS. (The newer overlaybd
   builder *does* support EROFS; ACR just doesn't call it.)

2. **Rename a label on the resulting manifest before pushing.**
   `acr-mirror` only streams referrers whose `artifactType` field is
   exactly `application/vnd.azure.artifact.streaming.v1` (an
   Azure-internal label). The converter writes a different, upstream
   label, which `acr-mirror` ignores — so without the rename it never
   notices our EROFS artifact and the pull silently falls back to a
   normal (non-streamed) image pull. Same image bytes, just a different
   label on the manifest.

## What ACR/AKS need to change so this workaround goes away

- **ACR:** add an `--fstype erofs` option to
  `az acr artifact-streaming create` and route it through the newer
  overlaybd builder that already supports EROFS. (ACR stamps its
  existing Azure-internal artifactType on the result, so `acr-mirror`
  picks it up unchanged — no node-side changes needed.)

