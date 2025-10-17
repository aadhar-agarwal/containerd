/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the 	pullReporter.start(pctx)
	image, err := c.client.Pull(pctx, ref, pullOpts...)
	pcancel()
	if err != nil {
		return "", fmt.Errorf("failed to pull and unpack image %q: %w", ref, err)
	}
	span.AddEvent("Pull and unpack image complete")

	configDesc, err := image.Config(ctx)
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package images

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/imgcrypt/v2"
	"github.com/containerd/imgcrypt/v2/images/encryption"
	"github.com/containerd/log"
	distribution "github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	containerdimages "github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/core/remotes/docker/config"
	"github.com/containerd/containerd/v2/internal/cri/annotations"
	criconfig "github.com/containerd/containerd/v2/internal/cri/config"
	crilabels "github.com/containerd/containerd/v2/internal/cri/labels"
	"github.com/containerd/containerd/v2/internal/cri/util"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/pkg/tracing"
)

// For image management:
// 1) We have an in-memory metadata index to:
//   a. Maintain ImageID -> RepoTags, ImageID -> RepoDigset relationships; ImageID
//   is the digest of image config, which conforms to oci image spec.
//   b. Cache constant and useful information such as image chainID, config etc.
//   c. An image will be added into the in-memory metadata only when it's successfully
//   pulled and unpacked.
//
// 2) We use containerd image metadata store and content store:
//   a. To resolve image reference (digest/tag) locally. During pulling image, we
//   normalize the image reference provided by user, and put it into image metadata
//   store with resolved descriptor. For the other operations, if image id is provided,
//   we'll access the in-memory metadata index directly; if image reference is
//   provided, we'll normalize it, resolve it in containerd image metadata store
//   to get the image id.
//   b. As the backup of in-memory metadata in 1). During startup, the in-memory
//   metadata could be re-constructed from image metadata store + content store.
//
// Several problems with current approach:
// 1) An entry in containerd image metadata store doesn't mean a "READY" (successfully
// pulled and unpacked) image. E.g. during pulling, the client gets killed. In that case,
// if we saw an image without snapshots or with in-complete contents during startup,
// should we re-pull the image? Or should we remove the entry?
//
// yanxuean: We can't delete image directly, because we don't know if the image
// is pulled by us. There are resource leakage.
//
// 2) Containerd suggests user to add entry before pulling the image. However if
// an error occurs during the pulling, should we remove the entry from metadata
// store? Or should we leave it there until next startup (resource leakage)?
//
// 3) The cri plugin only exposes "READY" (successfully pulled and unpacked) images
// to the user, which are maintained in the in-memory metadata index. However, it's
// still possible that someone else removes the content or snapshot by-pass the cri plugin,
// how do we detect that and update the in-memory metadata correspondingly? Always
// check whether corresponding snapshot is ready when reporting image status?
//
// 4) Is the content important if we cached necessary information in-memory
// after we pull the image? How to manage the disk usage of contents? If some
// contents are missing but snapshots are ready, is the image still "READY"?

// PullImage pulls an image with authentication config.
func (c *GRPCCRIImageService) PullImage(ctx context.Context, r *runtime.PullImageRequest) (_ *runtime.PullImageResponse, err error) {
	imageRef := r.GetImage().GetImage()

	credentials := func(host string) (string, string, error) {
		hostauth := r.GetAuth()
		if hostauth == nil {
			config := c.config.Registry.Configs[host]
			if config.Auth != nil {
				hostauth = toRuntimeAuthConfig(*config.Auth)
			}
		}
		return ParseAuth(hostauth, host)
	}

	ref, err := c.CRIImageService.PullImage(ctx, imageRef, credentials, r.SandboxConfig, r.GetImage().GetRuntimeHandler())
	if err != nil {
		return nil, err
	}
	return &runtime.PullImageResponse{ImageRef: ref}, nil
}

func (c *CRIImageService) PullImage(ctx context.Context, name string, credentials func(string) (string, string, error), sandboxConfig *runtime.PodSandboxConfig, runtimeHandler string) (_ string, err error) {
	span := tracing.SpanFromContext(ctx)
	defer func() {
		// TODO: add domain label for imagePulls metrics, and we may need to provide a mechanism
		// for the user to configure the set of registries that they are interested in.
		if err != nil {
			imagePulls.WithValues("failure").Inc()
		} else {
			imagePulls.WithValues("success").Inc()
		}
	}()

	inProgressImagePulls.Inc()
	defer inProgressImagePulls.Dec()
	startTime := time.Now()

	namedRef, err := distribution.ParseDockerRef(name)
	if err != nil {
		return "", fmt.Errorf("failed to parse image reference %q: %w", name, err)
	}
	ref := namedRef.String()
	if ref != name {
		log.G(ctx).Debugf("PullImage using normalized image ref: %q", ref)
	}

	imagePullProgressTimeout, err := time.ParseDuration(c.config.ImagePullProgressTimeout)
	if err != nil {
		return "", fmt.Errorf("failed to parse image_pull_progress_timeout %q: %w", c.config.ImagePullProgressTimeout, err)
	}

	var (
		pctx, pcancel = context.WithCancel(ctx)

		pullReporter = newPullProgressReporter(ref, pcancel, imagePullProgressTimeout)

		resolver = docker.NewResolver(docker.ResolverOptions{
			Headers: c.config.Registry.Headers,
			Hosts:   c.registryHosts(ctx, credentials, pullReporter.optionUpdateClient),
		})
		isSchema1    bool
		imageHandler containerdimages.HandlerFunc = func(_ context.Context,
			desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			if desc.MediaType == containerdimages.MediaTypeDockerSchema1Manifest {
				isSchema1 = true
			}
			return nil, nil
		}
	)

	defer pcancel()
	snapshotter, err := c.snapshotterFromPodSandboxConfig(ctx, ref, sandboxConfig)
	if err != nil {
		return "", err
	}
	log.G(ctx).Debugf("PullImage %q with snapshotter %s", ref, snapshotter)
	span.SetAttributes(
		tracing.Attribute("image.ref", ref),
		tracing.Attribute("snapshotter.name", snapshotter),
	)

	labels := c.getLabels(ctx, ref)

	pullOpts := []containerd.RemoteOpt{
		containerd.WithSchema1Conversion, //nolint:staticcheck // Ignore SA1019. Need to keep deprecated package for compatibility.
		containerd.WithResolver(resolver),
		containerd.WithPullSnapshotter(snapshotter),
		containerd.WithPullUnpack,
		containerd.WithPullLabels(labels),
		containerd.WithMaxConcurrentDownloads(c.config.MaxConcurrentDownloads),
		containerd.WithImageHandler(imageHandler),
		containerd.WithUnpackOpts([]containerd.UnpackOpt{
			containerd.WithUnpackDuplicationSuppressor(c.unpackDuplicationSuppressor),
			containerd.WithUnpackApplyOpts(diff.WithSyncFs(c.config.ImagePullWithSyncFs)),
		}),
	}

	// Temporarily removed for v2 upgrade
	//pullOpts = append(pullOpts, c.encryptedImagesPullOpts()...)
	if !c.config.DisableSnapshotAnnotations {
		pullOpts = append(pullOpts,
			containerd.WithImageHandlerWrapper(snpkg.AppendInfoHandlerWrapper(ref)))
	}

	if c.config.DiscardUnpackedLayers {
		// Allows GC to clean layers up from the content store after unpacking
		pullOpts = append(pullOpts,
			containerd.WithChildLabelMap(containerdimages.ChildGCLabelsFilterLayers))
	}

	pullReporter.start(pctx)
	image, err := c.client.Pull(pctx, ref, pullOpts...)
	pcancel()
	if err != nil {
		return "", fmt.Errorf("failed to pull and unpack image %q: %w", ref, err)
	}
	span.AddEvent("Pull and unpack image complete")

	configDesc, err := image.Config(ctx)
	if err != nil {
		return "", fmt.Errorf("get image config descriptor: %w", err)
	}
	imageID := configDesc.Digest.String()

	repoDigest, repoTag := util.GetRepoDigestAndTag(namedRef, image.Target().Digest, isSchema1)
	for _, r := range []string{imageID, repoTag, repoDigest} {
		if r == "" {
			continue
		}
		if err := c.createOrUpdateImageReference(ctx, r, image.Target(), labels); err != nil {
			return "", fmt.Errorf("failed to create image reference %q: %w", r, err)
		}
		// Update image store to reflect the newest state in containerd.
		// No need to use `updateImage`, because the image reference must
		// have been managed by the cri plugin.
		// TODO: Use image service directly
		if err := c.imageStore.Update(ctx, r); err != nil {
			return "", fmt.Errorf("failed to update image store %q: %w", r, err)
		}
	}

	const mbToByte = 1024 * 1024
	size, _ := image.Size(ctx)
	imagePullingSpeed := float64(size) / mbToByte / time.Since(startTime).Seconds()
	imagePullThroughput.Observe(imagePullingSpeed)

	log.G(ctx).Infof("Pulled image %q with image id %q, repo tag %q, repo digest %q, size %q in %s", name, imageID,
		repoTag, repoDigest, strconv.FormatInt(size, 10), time.Since(startTime))
	// NOTE(random-liu): the actual state in containerd is the source of truth, even we maintain
	// in-memory image store, it's only for in-memory indexing. The image could be removed
	// by someone else anytime, before/during/after we create the metadata. We should always
	// check the actual state in containerd before using the image or returning status of the
	// image.

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

	return imageID, nil
}

// ParseAuth parses AuthConfig and returns username and password/secret required by containerd.
func ParseAuth(auth *runtime.AuthConfig, host string) (string, string, error) {
	if auth == nil {
		return "", "", nil
	}
	if auth.ServerAddress != "" {
		// Do not return the auth info when server address doesn't match.
		u, err := url.Parse(auth.ServerAddress)
		if err != nil {
			return "", "", fmt.Errorf("parse server address: %w", err)
		}
		if host != u.Host {
			return "", "", nil
		}
	}
	if auth.Username != "" {
		return auth.Username, auth.Password, nil
	}
	if auth.IdentityToken != "" {
		return "", auth.IdentityToken, nil
	}
	if auth.Auth != "" {
		decLen := base64.StdEncoding.DecodedLen(len(auth.Auth))
		decoded := make([]byte, decLen)
		_, err := base64.StdEncoding.Decode(decoded, []byte(auth.Auth))
		if err != nil {
			return "", "", err
		}
		user, passwd, ok := strings.Cut(string(decoded), ":")
		if !ok {
			return "", "", fmt.Errorf("invalid decoded auth: %q", decoded)
		}
		return user, strings.Trim(passwd, "\x00"), nil
	}
	// TODO(random-liu): Support RegistryToken.
	// An empty auth config is valid for anonymous registry
	return "", "", nil
}

// createOrUpdateImageReference creates or updates image reference inside containerd image store.
// Note that because create and update are not finished in one transaction, there could be race. E.g.
// the image reference is deleted by someone else after create returns already exists, but before update
// happens.
func (c *CRIImageService) createOrUpdateImageReference(ctx context.Context, name string, desc ocispec.Descriptor, labels map[string]string) error {
	img := containerdimages.Image{
		Name:   name,
		Target: desc,
		// Add a label to indicate that the image is managed by the cri plugin.
		Labels: labels,
	}
	// TODO(random-liu): Figure out which is the more performant sequence create then update or
	// update then create.
	// TODO: Call CRIImageService directly
	_, err := c.images.Create(ctx, img)
	if err == nil {
		return nil
	} else if !errdefs.IsAlreadyExists(err) {
		return err
	}
	// Retrieve oldImg from image store here because Create routine returns an
	// empty image on ErrAlreadyExists
	oldImg, err := c.images.Get(ctx, name)
	if err != nil {
		return err
	}
	fieldpaths := []string{"target"}
	if oldImg.Labels[crilabels.ImageLabelKey] != labels[crilabels.ImageLabelKey] {
		fieldpaths = append(fieldpaths, "labels."+crilabels.ImageLabelKey)
	}
	if oldImg.Labels[crilabels.PinnedImageLabelKey] != labels[crilabels.PinnedImageLabelKey] &&
		labels[crilabels.PinnedImageLabelKey] == crilabels.PinnedImageLabelValue {
		fieldpaths = append(fieldpaths, "labels."+crilabels.PinnedImageLabelKey)
	}
	if oldImg.Target.Digest == img.Target.Digest && len(fieldpaths) < 2 {
		return nil
	}
	_, err = c.images.Update(ctx, img, fieldpaths...)
	return err
}

// getLabels get image labels to be added on CRI image
func (c *CRIImageService) getLabels(ctx context.Context, name string) map[string]string {
	labels := map[string]string{crilabels.ImageLabelKey: crilabels.ImageLabelValue}
	for _, pinned := range c.config.PinnedImages {
		if pinned == name {
			labels[crilabels.PinnedImageLabelKey] = crilabels.PinnedImageLabelValue
		}
	}
	return labels
}

// updateImage updates image store to reflect the newest state of an image reference
// in containerd. If the reference is not managed by the cri plugin, the function also
// generates necessary metadata for the image and make it managed.
func (c *CRIImageService) UpdateImage(ctx context.Context, r string) error {
	// TODO: Use image service
	img, err := c.client.GetImage(ctx, r)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return fmt.Errorf("get image by reference: %w", err)
		}
		// If the image is not found, we should continue updating the cache,
		// so that the image can be removed from the cache.
		if err := c.imageStore.Update(ctx, r); err != nil {
			return fmt.Errorf("update image store for %q: %w", r, err)
		}
		return nil
	}

	labels := img.Labels()
	criLabels := c.getLabels(ctx, r)
	for key, value := range criLabels {
		if labels[key] != value {
			// Make sure the image has the image id as its unique
			// identifier that references the image in its lifetime.
			configDesc, err := img.Config(ctx)
			if err != nil {
				return fmt.Errorf("get image id: %w", err)
			}
			id := configDesc.Digest.String()
			if err := c.createOrUpdateImageReference(ctx, id, img.Target(), criLabels); err != nil {
				return fmt.Errorf("create image id reference %q: %w", id, err)
			}
			if err := c.imageStore.Update(ctx, id); err != nil {
				return fmt.Errorf("update image store for %q: %w", id, err)
			}
			// The image id is ready, add the label to mark the image as managed.
			if err := c.createOrUpdateImageReference(ctx, r, img.Target(), criLabels); err != nil {
				return fmt.Errorf("create managed label: %w", err)
			}
			break
		}
	}
	if err := c.imageStore.Update(ctx, r); err != nil {
		return fmt.Errorf("update image store for %q: %w", r, err)
	}
	return nil
}

func hostDirFromRoots(roots []string) func(string) (string, error) {
	rootfn := make([]func(string) (string, error), len(roots))
	for i := range roots {
		rootfn[i] = config.HostDirFromRoot(roots[i])
	}
	return func(host string) (dir string, err error) {
		for _, fn := range rootfn {
			dir, err = fn(host)
			if (err != nil && !errdefs.IsNotFound(err)) || (dir != "") {
				break
			}
		}
		return
	}
}

// registryHosts is the registry hosts to be used by the resolver.
func (c *CRIImageService) registryHosts(ctx context.Context, credentials func(host string) (string, string, error), updateClientFn config.UpdateClientFunc) docker.RegistryHosts {
	paths := filepath.SplitList(c.config.Registry.ConfigPath)
	if len(paths) > 0 {
		hostOptions := config.HostOptions{
			UpdateClient: updateClientFn,
		}
		hostOptions.Credentials = credentials
		hostOptions.HostDir = hostDirFromRoots(paths)

		return config.ConfigureHosts(ctx, hostOptions)
	}

	return func(host string) ([]docker.RegistryHost, error) {
		var registries []docker.RegistryHost

		endpoints, err := c.registryEndpoints(host)
		if err != nil {
			return nil, fmt.Errorf("get registry endpoints: %w", err)
		}
		for _, e := range endpoints {
			u, err := url.Parse(e)
			if err != nil {
				return nil, fmt.Errorf("parse registry endpoint %q from mirrors: %w", e, err)
			}

			var (
				transport = newTransport()
				client    = &http.Client{Transport: transport}
				config    = c.config.Registry.Configs[u.Host]
			)

			if docker.IsLocalhost(host) && u.Scheme == "http" {
				// Skipping TLS verification for localhost
				transport.TLSClientConfig = &tls.Config{
					InsecureSkipVerify: true,
				}
			}

			// Make a copy of `credentials`, so that different authorizers would not reference
			// the same credentials variable.
			credentials := credentials
			if credentials == nil && config.Auth != nil {
				auth := toRuntimeAuthConfig(*config.Auth)
				credentials = func(host string) (string, string, error) {
					return ParseAuth(auth, host)
				}

			}

			if updateClientFn != nil {
				if err := updateClientFn(client); err != nil {
					return nil, fmt.Errorf("failed to update http client: %w", err)
				}
			}

			authorizer := docker.NewDockerAuthorizer(
				docker.WithAuthClient(client),
				docker.WithAuthCreds(credentials))

			if u.Path == "" {
				u.Path = "/v2"
			}

			registries = append(registries, docker.RegistryHost{
				Client:       client,
				Authorizer:   authorizer,
				Host:         u.Host,
				Scheme:       u.Scheme,
				Path:         u.Path,
				Capabilities: docker.HostCapabilityResolve | docker.HostCapabilityPull,
			})
		}
		return registries, nil
	}
}

// toRuntimeAuthConfig converts cri plugin auth config to runtime auth config.
func toRuntimeAuthConfig(a criconfig.AuthConfig) *runtime.AuthConfig {
	return &runtime.AuthConfig{
		Username:      a.Username,
		Password:      a.Password,
		Auth:          a.Auth,
		IdentityToken: a.IdentityToken,
	}
}

// defaultScheme returns the default scheme for a registry host.
func defaultScheme(host string) string {
	if docker.IsLocalhost(host) {
		return "http"
	}
	return "https"
}

// addDefaultScheme returns the endpoint with default scheme
func addDefaultScheme(endpoint string) (string, error) {
	if strings.Contains(endpoint, "://") {
		return endpoint, nil
	}
	ue := "dummy://" + endpoint
	u, err := url.Parse(ue)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s://%s", defaultScheme(u.Host), endpoint), nil
}

// registryEndpoints returns endpoints for a given host.
// It adds default registry endpoint if it does not exist in the passed-in endpoint list.
// It also supports wildcard host matching with `*`.
func (c *CRIImageService) registryEndpoints(host string) ([]string, error) {
	var endpoints []string
	_, ok := c.config.Registry.Mirrors[host]
	if ok {
		endpoints = c.config.Registry.Mirrors[host].Endpoints
	} else {
		endpoints = c.config.Registry.Mirrors["*"].Endpoints
	}
	defaultHost, err := docker.DefaultHost(host)
	if err != nil {
		return nil, fmt.Errorf("get default host: %w", err)
	}
	for i := range endpoints {
		en, err := addDefaultScheme(endpoints[i])
		if err != nil {
			return nil, fmt.Errorf("parse endpoint url: %w", err)
		}
		endpoints[i] = en
	}
	for _, e := range endpoints {
		u, err := url.Parse(e)
		if err != nil {
			return nil, fmt.Errorf("parse endpoint url: %w", err)
		}
		if u.Host == host {
			// Do not add default if the endpoint already exists.
			return endpoints, nil
		}
	}
	return append(endpoints, defaultScheme(defaultHost)+"://"+defaultHost), nil
}

// newTransport returns a new HTTP transport used to pull image.
// TODO(random-liu): Create a library and share this code with `ctr`.
func newTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:       30 * time.Second,
			KeepAlive:     30 * time.Second,
			FallbackDelay: 300 * time.Millisecond,
		}).DialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
	}
}

// encryptedImagesPullOpts returns the necessary list of pull options required
// for decryption of encrypted images based on the cri decryption configuration.
// Temporarily removed for v2 upgrade
func (c *CRIImageService) encryptedImagesPullOpts() []containerd.RemoteOpt {
	if c.config.ImageDecryption.KeyModel == criconfig.KeyModelNode {
		ltdd := imgcrypt.Payload{}
		decUnpackOpt := encryption.WithUnpackConfigApplyOpts(encryption.WithDecryptedUnpack(&ltdd))
		opt := containerd.WithUnpackOpts([]containerd.UnpackOpt{decUnpackOpt})
		return []containerd.RemoteOpt{opt}
	}
	return nil
}

const (
	// defaultPullProgressReportInterval represents that how often the
	// reporter checks that pull progress.
	defaultPullProgressReportInterval = 10 * time.Second
)

// pullProgressReporter is used to check single PullImage progress.
type pullProgressReporter struct {
	ref         string
	cancel      context.CancelFunc
	reqReporter pullRequestReporter
	timeout     time.Duration
}

func newPullProgressReporter(ref string, cancel context.CancelFunc, timeout time.Duration) *pullProgressReporter {
	return &pullProgressReporter{
		ref:         ref,
		cancel:      cancel,
		reqReporter: pullRequestReporter{},
		timeout:     timeout,
	}
}

func (reporter *pullProgressReporter) optionUpdateClient(client *http.Client) error {
	client.Transport = &pullRequestReporterRoundTripper{
		rt:          client.Transport,
		reqReporter: &reporter.reqReporter,
	}
	return nil
}

func (reporter *pullProgressReporter) start(ctx context.Context) {
	if reporter.timeout == 0 {
		log.G(ctx).Infof("no timeout and will not start pulling image %s reporter", reporter.ref)
		return
	}

	go func() {
		var (
			reportInterval = defaultPullProgressReportInterval

			lastSeenBytesRead = uint64(0)
			lastSeenTimestamp = time.Now()
		)

		// check progress more frequently if timeout < default internal
		if reporter.timeout < reportInterval {
			reportInterval = reporter.timeout / 2
		}

		var ticker = time.NewTicker(reportInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				activeReqs, bytesRead := reporter.reqReporter.status()

				log.G(ctx).WithField("ref", reporter.ref).
					WithField("activeReqs", activeReqs).
					WithField("totalBytesRead", bytesRead).
					WithField("lastSeenBytesRead", lastSeenBytesRead).
					WithField("lastSeenTimestamp", lastSeenTimestamp.Format(time.RFC3339)).
					WithField("reportInterval", reportInterval).
					Debugf("progress for image pull")

				if activeReqs == 0 || bytesRead > lastSeenBytesRead {
					lastSeenBytesRead = bytesRead
					lastSeenTimestamp = time.Now()
					continue
				}

				if time.Since(lastSeenTimestamp) > reporter.timeout {
					log.G(ctx).Errorf("cancel pulling image %s because of no progress in %v", reporter.ref, reporter.timeout)
					reporter.cancel()
					return
				}
			case <-ctx.Done():
				activeReqs, bytesRead := reporter.reqReporter.status()
				log.G(ctx).Infof("stop pulling image %s: active requests=%v, bytes read=%v", reporter.ref, activeReqs, bytesRead)
				return
			}
		}
	}()
}

// countingReadCloser wraps http.Response.Body with pull request reporter,
// which is used by pullRequestReporterRoundTripper.
type countingReadCloser struct {
	once sync.Once

	rc          io.ReadCloser
	reqReporter *pullRequestReporter
}

// Read reads bytes from original io.ReadCloser and increases bytes in
// pull request reporter.
func (r *countingReadCloser) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	r.reqReporter.incByteRead(uint64(n))
	return n, err
}

// Close closes the original io.ReadCloser and only decreases the number of
// active pull requests once.
func (r *countingReadCloser) Close() error {
	err := r.rc.Close()
	r.once.Do(r.reqReporter.decRequest)
	return err
}

// pullRequestReporter is used to track the progress per each criapi.PullImage.
type pullRequestReporter struct {
	// activeReqs indicates that current number of active pulling requests,
	// including auth requests.
	activeReqs int32
	// totalBytesRead indicates that the total bytes has been read from
	// remote registry.
	totalBytesRead uint64
}

func (reporter *pullRequestReporter) incRequest() {
	atomic.AddInt32(&reporter.activeReqs, 1)
}

func (reporter *pullRequestReporter) decRequest() {
	atomic.AddInt32(&reporter.activeReqs, -1)
}

func (reporter *pullRequestReporter) incByteRead(nr uint64) {
	atomic.AddUint64(&reporter.totalBytesRead, nr)
}

func (reporter *pullRequestReporter) status() (currentReqs int32, totalBytesRead uint64) {
	currentReqs = atomic.LoadInt32(&reporter.activeReqs)
	totalBytesRead = atomic.LoadUint64(&reporter.totalBytesRead)
	return currentReqs, totalBytesRead
}

// pullRequestReporterRoundTripper wraps http.RoundTripper with pull request
// reporter which is used to track the progress of active http request with
// counting readable http.Response.Body.
//
// NOTE:
//
// Although containerd provides ingester manager to track the progress
// of pulling request, for example `ctr image pull` shows the console progress
// bar, it needs more CPU resources to open/read the ingested files with
// acquiring containerd metadata plugin's boltdb lock.
//
// Before sending HTTP request to registry, the containerd.Client.Pull library
// will open writer by containerd ingester manager. Based on this, the
// http.RoundTripper wrapper can track the active progress with lower overhead
// even if the ref has been locked in ingester manager by other Pull request.
type pullRequestReporterRoundTripper struct {
	rt http.RoundTripper

	reqReporter *pullRequestReporter
}

func (rt *pullRequestReporterRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.reqReporter.incRequest()

	resp, err := rt.rt.RoundTrip(req)
	if err != nil {
		rt.reqReporter.decRequest()
		return nil, err
	}

	resp.Body = &countingReadCloser{
		rc:          resp.Body,
		reqReporter: rt.reqReporter,
	}
	return resp, err
}

// Given that runtime information is not passed from PullImageRequest, we depend on an experimental annotation
// passed from pod sandbox config to get the runtimeHandler. The annotation key is specified in configuration.
// Once we know the runtime, try to override default snapshotter if it is set for this runtime.
// See https://github.com/containerd/containerd/issues/6657
func (c *CRIImageService) snapshotterFromPodSandboxConfig(ctx context.Context, imageRef string,
	s *runtime.PodSandboxConfig) (string, error) {
	snapshotter := c.config.Snapshotter
	if s == nil || s.Annotations == nil {
		return snapshotter, nil
	}

	// TODO(kiashok): honor the new CRI runtime handler field added to v0.29.0
	// for image pull per runtime class support.
	runtimeHandler, ok := s.Annotations[annotations.RuntimeHandler]
	if !ok {
		return snapshotter, nil
	}

	// TODO: Ensure error is returned if runtime not found?
	if c.runtimePlatforms != nil {
		if p, ok := c.runtimePlatforms[runtimeHandler]; ok && p.Snapshotter != snapshotter {
			snapshotter = p.Snapshotter
			log.G(ctx).Infof("experimental: PullImage %q for runtime %s, using snapshotter %s", imageRef, runtimeHandler, snapshotter)
		}
	}

	return snapshotter, nil
}

// pullReferrers fetches and stores referrers (signatures, attestations, etc.) for the given image
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
			// Continue with other referrers even if one fails
		} else {
			log.G(ctx).Debugf("Successfully pulled referrer %s", refDesc.Digest)
		}
	}
	
	log.G(ctx).Infof("Successfully pulled %d referrers for image %q", len(referrersIndex.Manifests), ref)
	return nil
}

// fetchReferrersByDirectResolution uses direct referrer resolution (works with Azure Container Registry)
// discoverReferrersForDigest attempts to dynamically discover referrers for a given digest
// This works with registries that don't properly implement OCI Referrers API but store referrers as regular manifests

// discoverReferrersThroughCatalog uses registry catalog API to find all manifests that reference the target digest
// discoverReferrersThroughPatterns tries common referrer naming patterns
// This method attempts to list manifests in the repository and find those that reference the target digest
// validateReferrerRelationship checks if a referrer manifest actually references the target digest
// This can be configured via containerd config, environment variables, or external configuration
// fetchReferrersAPIWithResolver uses the OCI Distribution Spec referrers API via the ReferrersFetcher interface

// fetchReferrersByTags fallback method using tag-based discovery
// fetchReferrersByTagsWithResolver uses resolver for tag-based discovery
// pullSingleReferrer pulls a single referrer artifact
func (c *CRIImageService) pullSingleReferrer(ctx context.Context, fetcher remotes.Fetcher, originalRef string, desc ocispec.Descriptor) error {
	log.G(ctx).Debugf("Pulling referrer %s", desc.Digest)
	
	// Fetch the referrer manifest
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("failed to fetch referrer manifest: %w", err)
	}
	log.G(ctx).Debugf("Successfully fetched referrer manifest")
	defer rc.Close()
	
	// Store the referrer in containerd's content store
	cs := c.content
	
	// Check if content already exists
	if _, err := cs.Info(ctx, desc.Digest); err == nil {
		log.G(ctx).Debugf("Referrer %s already exists in content store", desc.Digest)
	} else {
		// Content doesn't exist, need to store it
		writer, err := cs.Writer(ctx, content.WithDescriptor(desc), content.WithRef(desc.Digest.String()))
		if err != nil {
			return fmt.Errorf("failed to create writer for referrer: %w", err)
		}
		defer writer.Close()
		
		if _, err := io.Copy(writer, rc); err != nil {
			return fmt.Errorf("failed to write referrer content: %w", err)
		}
		
		if err := writer.Commit(ctx, desc.Size, desc.Digest); err != nil {
			return fmt.Errorf("failed to commit referrer: %w", err)
		}
		log.G(ctx).Debugf("Successfully stored referrer %s", desc.Digest)
	}
	
	// If it's a manifest, pull its layers too
	if containerdimages.IsManifestType(desc.MediaType) {
		if err := c.pullReferrerLayers(ctx, fetcher, desc); err != nil {
			return fmt.Errorf("failed to pull referrer layers: %w", err)
		}
		
		// Extract signature metadata for EROFS snapshotter
		if err := c.extractAndStoreSignatureMetadata(ctx, originalRef, desc); err != nil {
			log.G(ctx).WithError(err).Warnf("Failed to extract signature metadata")
			// Don't fail the pull if signature extraction fails
		}
	}
	
	log.G(ctx).Debugf("Successfully pulled referrer %s", desc.Digest)
	return nil
}

// inspectAndLogReferrerContent analyzes referrer content to show what's inside
func (c *CRIImageService) pullReferrerLayers(ctx context.Context, fetcher remotes.Fetcher, manifestDesc ocispec.Descriptor) error {
	cs := c.content
	
	// Read the manifest
	manifestData, err := content.ReadBlob(ctx, cs, manifestDesc)
	if err != nil {
		return fmt.Errorf("failed to read referrer manifest: %w", err)
	}
	
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("failed to unmarshal referrer manifest: %w", err)
	}
	
	// Pull config if present
	if manifest.Config.Size > 0 {
		if err := c.pullReferrerBlob(ctx, fetcher, manifest.Config); err != nil {
			return fmt.Errorf("failed to pull referrer config: %w", err)
		}
	}
	
	// Pull layers
	for _, layer := range manifest.Layers {
		if err := c.pullReferrerBlob(ctx, fetcher, layer); err != nil {
			return fmt.Errorf("failed to pull referrer layer %s: %w", layer.Digest, err)
		}
	}
	
	return nil
}

// pullReferrerBlob pulls a single blob (config or layer) for a referrer
func (c *CRIImageService) pullReferrerBlob(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor) error {
	cs := c.content
	
	// Check if we already have this blob
	if _, err := cs.Info(ctx, desc.Digest); err == nil {
		log.G(ctx).Debugf("Referrer blob %s already exists, skipping", desc.Digest)
		return nil
	}
	
	// Fetch the blob
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("failed to fetch referrer blob: %w", err)
	}
	defer rc.Close()
	
	// Store the blob
	writer, err := cs.Writer(ctx, content.WithDescriptor(desc), content.WithRef(desc.Digest.String()))
	if err != nil {
		return fmt.Errorf("failed to create writer for referrer blob: %w", err)
	}
	defer writer.Close()
	
	if _, err := io.Copy(writer, rc); err != nil {
		return fmt.Errorf("failed to write referrer blob: %w", err)
	}
	
	if err := writer.Commit(ctx, desc.Size, desc.Digest); err != nil {
		return fmt.Errorf("failed to commit referrer blob: %w", err)
	}
	
	return nil
}

// extractAndStoreSignatureMetadata extracts signature metadata from referrer manifests
// and writes them to the filesystem for the EROFS snapshotter to consume
func (c *CRIImageService) extractAndStoreSignatureMetadata(ctx context.Context, imageRef string, manifestDesc ocispec.Descriptor) error {
	cs := c.content
	
	// Read the referrer manifest from content store
	manifestData, err := content.ReadBlob(ctx, cs, manifestDesc)
	if err != nil {
		return fmt.Errorf("failed to read referrer manifest: %w", err)
	}
	
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("failed to unmarshal referrer manifest: %w", err)
	}
	
	// Check if this is a Microsoft PKCS#7 signature artifact (Azure Linux filesystem signatures)
	if manifest.ArtifactType != "application/vnd.oci.mt.pkcs7" {
		log.G(ctx).Debugf("Skipping non-PKCS#7 artifact: %s", manifest.ArtifactType)
		return nil
	}
	
	// Build LayerInfo structures for each layer
	var layerInfos []map[string]interface{}
	
	for _, layer := range manifest.Layers {
		// Extract metadata from layer annotations
		if layer.Annotations == nil {
			log.G(ctx).Debugf("Layer %s has no annotations, skipping", layer.Digest)
			continue
		}
		
		// Get the filesystem layer digest this signature refers to
		layerDigest, ok := layer.Annotations["image.layer.digest"]
		if !ok {
			log.G(ctx).Debugf("Layer %s missing 'image.layer.digest' annotation, skipping", layer.Digest)
			continue
		}
		
		// Get the EROFS root hash
		rootHash, ok := layer.Annotations["image.layer.root_hash"]
		if !ok {
			log.G(ctx).Debugf("Layer %s missing 'image.layer.root_hash' annotation, skipping", layer.Digest)
			continue
		}
		
		// Read the signature blob from content store
		signatureData, err := content.ReadBlob(ctx, cs, layer)
		if err != nil {
			log.G(ctx).WithError(err).Debugf("Failed to read signature blob for layer %s, skipping", layer.Digest)
			continue
		}
		
		// The signature is stored as raw PKCS#7 DER bytes, encode to base64 for JSON storage
		signatureBase64 := base64.StdEncoding.EncodeToString(signatureData)
		
		// Build LayerInfo structure matching what EROFS snapshotter expects
		layerInfo := map[string]interface{}{
			"digest":     layerDigest,
			"root_hash":  rootHash,
			"signature":  signatureBase64,
		}
		layerInfos = append(layerInfos, layerInfo)
	}
	
	if len(layerInfos) == 0 {
		log.G(ctx).Debugf("No valid layer info extracted from referrer manifest")
		return nil
	}
	
	// Write to filesystem in signature-manifests directory
	if len(c.imageFSPaths) == 0 {
		return fmt.Errorf("no snapshotter paths configured")
	}
	
	successCount := 0
	for snapshotterName, snapshotterPath := range c.imageFSPaths {
		// Create signature-manifests directory if it doesn't exist
		sigManifestDir := filepath.Join(snapshotterPath, "signature-manifests")
		if err := os.MkdirAll(sigManifestDir, 0755); err != nil {
			log.G(ctx).WithError(err).Debugf("Failed to create signature-manifests dir for snapshotter %s", snapshotterName)
			continue
		}
		
		// Use a well-known filename: signatures.json (append to existing file)
		filePath := filepath.Join(sigManifestDir, "signatures.json")
		
		// Read existing signatures.json if it exists
		var existingManifests []map[string]interface{}
		if existingData, err := os.ReadFile(filePath); err == nil {
			if err := json.Unmarshal(existingData, &existingManifests); err != nil {
				log.G(ctx).WithError(err).Debugf("Failed to parse existing signatures.json, will overwrite")
				existingManifests = nil
			}
		}
		
		// Merge new layer info with existing entries
		// Build a map of existing digests to avoid duplicates
		existingDigests := make(map[string]bool)
		if len(existingManifests) > 0 {
			for _, manifest := range existingManifests {
				if layersInterface, ok := manifest["layers"]; ok {
					if layers, ok := layersInterface.([]interface{}); ok {
						for _, layerInterface := range layers {
							if layer, ok := layerInterface.(map[string]interface{}); ok {
								if digest, ok := layer["digest"].(string); ok {
									existingDigests[digest] = true
								}
							}
						}
					}
				}
			}
		}
		
		// Add only new layers that don't already exist
		mergedLayers := []map[string]interface{}{}
		
		// First, add all layers from existing manifests
		if len(existingManifests) > 0 {
			for _, manifest := range existingManifests {
				if layersInterface, ok := manifest["layers"]; ok {
					if layers, ok := layersInterface.([]interface{}); ok {
						for _, layerInterface := range layers {
							if layer, ok := layerInterface.(map[string]interface{}); ok {
								mergedLayers = append(mergedLayers, layer)
							}
						}
					}
				}
			}
		}
		
		// Then add new layers if they don't already exist
		for _, newLayer := range layerInfos {
			digest := newLayer["digest"].(string)
			if !existingDigests[digest] {
				mergedLayers = append(mergedLayers, newLayer)
			}
		}
		
		// Build final structure with all layers in a single ImageInfo
		finalManifest := []map[string]interface{}{
			{
				"layers": mergedLayers,
			},
		}
		
		// Marshal merged data to JSON
		mergedJSON, err := json.MarshalIndent(finalManifest, "", "  ")
		if err != nil {
			log.G(ctx).WithError(err).Debugf("Failed to marshal merged data")
			continue
		}
		
		// Write the merged JSON file
		if err := os.WriteFile(filePath, mergedJSON, 0644); err != nil {
			log.G(ctx).WithError(err).Debugf("Failed to write signature manifest to %s", filePath)
			continue
		}
		
		log.G(ctx).Debugf("Wrote signature manifest to %s (%d layers)", filePath, len(mergedLayers))
		successCount++
	}
	
	if successCount == 0 {
		return fmt.Errorf("failed to write signature manifest to any snapshotter")
	}
	
	log.G(ctx).Infof("Successfully extracted and stored signature metadata for %d layers across %d snapshotters", len(layerInfos), successCount)
	return nil
}
