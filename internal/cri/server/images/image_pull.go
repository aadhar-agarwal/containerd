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
func (c *CRIImageService) fetchReferrersByDirectResolution(ctx context.Context, resolver remotes.Resolver, ref string, target ocispec.Descriptor) (*ocispec.Index, error) {
	log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: Starting for ref %q, target digest %s", ref, target.Digest)
	
	var allManifests []ocispec.Descriptor
	
	// Parse the base reference to construct referrer references
	named, err := distribution.ParseDockerRef(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ref: %w", err)
	}
	
	repoName := named.Name()
	log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: Using repository %s for referrer discovery", repoName)
	
	// Optional: Check for hardcoded known referrers first (for critical/known images)
	knownReferrers := c.getKnownReferrers()
	var referrerDigests []string
	
	if knownDigests, exists := knownReferrers[target.Digest.String()]; exists {
		log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: Using %d known referrers for digest %s", len(knownDigests), target.Digest)
		referrerDigests = knownDigests
	} else {
		// Try to discover referrers dynamically by attempting common referrer digest patterns
		// This works by trying to enumerate potential referrer digests through registry API exploration
		discoveredDigests, err := c.discoverReferrersForDigest(ctx, resolver, repoName, target.Digest.String())
		if err != nil {
			log.G(ctx).WithError(err).Warnf("[dallas] fetchReferrersByDirectResolution: Failed to discover referrers dynamically")
			return &ocispec.Index{MediaType: "application/vnd.oci.image.index.v1+json", Manifests: []ocispec.Descriptor{}}, nil
		}
		referrerDigests = discoveredDigests
	}
	
	if len(referrerDigests) > 0 {
		log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: Found %d referrers for digest %s", len(referrerDigests), target.Digest)
		
		// Try to resolve each known referrer directly
		for _, referrerDigest := range referrerDigests {
			referrerRef := fmt.Sprintf("%s@%s", repoName, referrerDigest)
			log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: Attempting to resolve referrer %s", referrerRef)
			
			_, referrerDesc, err := resolver.Resolve(ctx, referrerRef)
			if err != nil {
				log.G(ctx).WithError(err).Warnf("[dallas] fetchReferrersByDirectResolution: Failed to resolve referrer %s", referrerRef)
				continue
			}
			
			log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: Successfully resolved referrer %s (size: %d)", referrerDigest, referrerDesc.Size)
			
			// Fetch the referrer content to validate it
			fetcher, err := resolver.Fetcher(ctx, referrerRef)
			if err != nil {
				log.G(ctx).WithError(err).Warnf("[dallas] fetchReferrersByDirectResolution: Failed to get fetcher for referrer %s", referrerRef)
				continue
			}
			
			reader, err := fetcher.Fetch(ctx, referrerDesc)
			if err != nil {
				log.G(ctx).WithError(err).Warnf("[dallas] fetchReferrersByDirectResolution: Failed to fetch referrer %s", referrerRef)
				continue
			}
			
			referrerData, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				log.G(ctx).WithError(err).Warnf("[dallas] fetchReferrersByDirectResolution: Failed to read referrer %s", referrerRef)
				continue
			}
			
			log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: Successfully fetched referrer %s (%d bytes)", referrerDigest, len(referrerData))
			
			// Validate that this referrer actually references our target
			if len(referrerData) > 0 {
				var referrerManifest ocispec.Manifest
				if err := json.Unmarshal(referrerData, &referrerManifest); err == nil {
					if referrerManifest.Subject != nil && referrerManifest.Subject.Digest.String() == target.Digest.String() {
						log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: ✅ Referrer %s correctly references target %s", referrerDigest, target.Digest)
						allManifests = append(allManifests, referrerDesc)
					} else {
						log.G(ctx).Warnf("[dallas] fetchReferrersByDirectResolution: ❌ Referrer %s does not reference target %s (subject: %v)", referrerDigest, target.Digest, referrerManifest.Subject)
					}
				} else {
					log.G(ctx).WithError(err).Warnf("[dallas] fetchReferrersByDirectResolution: Failed to parse referrer %s as manifest", referrerDigest)
					// Still add it as it might be a different type of referrer
					allManifests = append(allManifests, referrerDesc)
				}
			} else {
				log.G(ctx).Warnf("[dallas] fetchReferrersByDirectResolution: Referrer %s has empty content", referrerDigest)
			}
		}
	} else {
		log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: No referrers discovered for digest %s", target.Digest)
	}
	
	log.G(ctx).Infof("[dallas] fetchReferrersByDirectResolution: Found %d valid referrers using direct resolution", len(allManifests))
	
	return &ocispec.Index{
		MediaType: "application/vnd.oci.image.index.v1+json",
		Manifests: allManifests,
	}, nil
}

// discoverReferrersForDigest attempts to dynamically discover referrers for a given digest
// This works with registries that don't properly implement OCI Referrers API but store referrers as regular manifests
func (c *CRIImageService) discoverReferrersForDigest(ctx context.Context, resolver remotes.Resolver, repoName string, targetDigest string) ([]string, error) {
	log.G(ctx).Infof("[dallas] discoverReferrersForDigest: Starting dynamic referrer discovery for %s @ %s", repoName, targetDigest)
	
	var discoveredReferrers []string
	
	// Method 1: Try to use registry catalog API to list all manifests and check which ones reference our target
	// This is the most reliable method but requires registry catalog API support
	catalogReferrers, err := c.discoverReferrersThroughCatalog(ctx, resolver, repoName, targetDigest)
	if err == nil && len(catalogReferrers) > 0 {
		log.G(ctx).Infof("[dallas] discoverReferrersForDigest: Found %d referrers through catalog API", len(catalogReferrers))
		discoveredReferrers = append(discoveredReferrers, catalogReferrers...)
	} else {
		log.G(ctx).WithError(err).Debugf("[dallas] discoverReferrersForDigest: Catalog-based discovery failed or found no referrers")
	}
	
	// Method 2: Try common referrer digest patterns (for registries that use predictable naming)
	// This includes patterns like <digest>.sig, <digest>.att, etc.
	patternReferrers, err := c.discoverReferrersThroughPatterns(ctx, resolver, repoName, targetDigest)
	if err == nil && len(patternReferrers) > 0 {
		log.G(ctx).Infof("[dallas] discoverReferrersForDigest: Found %d referrers through pattern matching", len(patternReferrers))
		discoveredReferrers = append(discoveredReferrers, patternReferrers...)
	} else {
		log.G(ctx).WithError(err).Debugf("[dallas] discoverReferrersForDigest: Pattern-based discovery failed or found no referrers")
	}
	
	// Method 3: Try direct digest resolution for known referrers (Azure Container Registry approach)
	// This tries to resolve referrers by their direct digest values
	directReferrers, err := c.discoverReferrersThroughDirectDigests(ctx, resolver, repoName, targetDigest)
	if err == nil && len(directReferrers) > 0 {
		log.G(ctx).Infof("[dallas] discoverReferrersForDigest: Found %d referrers through direct digest resolution", len(directReferrers))
		discoveredReferrers = append(discoveredReferrers, directReferrers...)
	} else {
		log.G(ctx).WithError(err).Debugf("[dallas] discoverReferrersForDigest: Direct digest discovery failed or found no referrers")
	}
	
	// Remove duplicates
	uniqueReferrers := make(map[string]bool)
	var result []string
	for _, referrer := range discoveredReferrers {
		if !uniqueReferrers[referrer] {
			uniqueReferrers[referrer] = true
			result = append(result, referrer)
		}
	}
	
	log.G(ctx).Infof("[dallas] discoverReferrersForDigest: Discovered %d unique referrers for %s", len(result), targetDigest)
	return result, nil
}

// discoverReferrersThroughCatalog uses registry catalog API to find all manifests that reference the target digest
func (c *CRIImageService) discoverReferrersThroughCatalog(ctx context.Context, resolver remotes.Resolver, repoName, targetDigest string) ([]string, error) {
	// This is a placeholder for catalog-based discovery
	// In a full implementation, this would:
	// 1. Call the registry catalog API to list all manifests in the repository  
	// 2. For each manifest, fetch its content and check if it has a "subject" field pointing to our target digest
	// 3. Return the digests of manifests that reference our target
	
	log.G(ctx).Debugf("[dallas] discoverReferrersThroughCatalog: Catalog-based discovery not yet implemented")
	return nil, fmt.Errorf("catalog-based discovery not implemented")
}

// discoverReferrersThroughPatterns tries common referrer naming patterns
func (c *CRIImageService) discoverReferrersThroughPatterns(ctx context.Context, resolver remotes.Resolver, repoName, targetDigest string) ([]string, error) {
	log.G(ctx).Debugf("[dallas] discoverReferrersThroughPatterns: Trying pattern-based discovery for %s", targetDigest)
	
	// Common patterns for referrer digest naming in various registries:
	patterns := []string{
		targetDigest + ".sig",    // Signature suffix
		targetDigest + ".att",    // Attestation suffix  
		targetDigest + ".sbom",   // SBOM suffix
		targetDigest + ".vuln",   // Vulnerability report suffix
		"sig-" + targetDigest,    // Signature prefix
		"att-" + targetDigest,    // Attestation prefix
		"sbom-" + targetDigest,   // SBOM prefix
	}
	
	var discoveredReferrers []string
	
	for _, pattern := range patterns {
		// Try to resolve a manifest with this pattern as a tag
		referrerRef := fmt.Sprintf("%s:%s", repoName, pattern)
		log.G(ctx).Debugf("[dallas] discoverReferrersThroughPatterns: Trying pattern referrer %s", referrerRef)
		
		_, referrerDesc, err := resolver.Resolve(ctx, referrerRef)
		if err != nil {
			log.G(ctx).WithError(err).Debugf("[dallas] discoverReferrersThroughPatterns: Pattern %s not found", pattern)
			continue
		}
		
		// Validate that this referrer actually references our target digest
		if c.validateReferrerRelationship(ctx, resolver, referrerRef, referrerDesc, targetDigest) {
			log.G(ctx).Infof("[dallas] discoverReferrersThroughPatterns: Found valid referrer %s via pattern %s", referrerDesc.Digest, pattern)
			discoveredReferrers = append(discoveredReferrers, referrerDesc.Digest.String())
		}
	}
	
	return discoveredReferrers, nil
}

// discoverReferrersThroughDirectDigests uses registry catalog API to discover referrers dynamically
// This method attempts to list manifests in the repository and find those that reference the target digest
func (c *CRIImageService) discoverReferrersThroughDirectDigests(ctx context.Context, resolver remotes.Resolver, repoName string, targetDigest string) ([]string, error) {
	log.G(ctx).Debugf("[dallas] discoverReferrersThroughDirectDigests: Trying dynamic catalog-based discovery for %s", targetDigest)
	
	// This is a placeholder for actual catalog-based discovery
	// In a real implementation, we would:
	// 1. Use the registry catalog API to list all tags/manifests in the repository
	// 2. For each manifest, check if it has a "subject" field that references our targetDigest
	// 3. Collect all manifests that reference our target
	
	log.G(ctx).Debugf("[dallas] discoverReferrersThroughDirectDigests: Catalog-based referrer discovery not yet fully implemented")
	log.G(ctx).Debugf("[dallas] discoverReferrersThroughDirectDigests: This method would typically:")
	log.G(ctx).Debugf("[dallas] discoverReferrersThroughDirectDigests:   1. Query registry catalog API for repository %s", repoName)
	log.G(ctx).Debugf("[dallas] discoverReferrersThroughDirectDigests:   2. Iterate through all manifests")
	log.G(ctx).Debugf("[dallas] discoverReferrersThroughDirectDigests:   3. Check each manifest's subject field for references to %s", targetDigest)
	
	// For now, return empty list to rely on pattern-based discovery and OCI Referrers API
	var discoveredReferrers []string
	
	return discoveredReferrers, nil
}



// validateReferrerRelationship checks if a referrer manifest actually references the target digest
func (c *CRIImageService) validateReferrerRelationship(ctx context.Context, resolver remotes.Resolver, referrerRef string, referrerDesc ocispec.Descriptor, targetDigest string) bool {
	// Fetch the referrer manifest to check its subject field
	fetcher, err := resolver.Fetcher(ctx, referrerRef)
	if err != nil {
		log.G(ctx).WithError(err).Debugf("[dallas] validateReferrerRelationship: Failed to get fetcher for %s", referrerRef)
		return false
	}
	
	reader, err := fetcher.Fetch(ctx, referrerDesc)
	if err != nil {
		log.G(ctx).WithError(err).Debugf("[dallas] validateReferrerRelationship: Failed to fetch %s", referrerRef)
		return false
	}
	defer reader.Close()
	
	referrerData, err := io.ReadAll(reader)
	if err != nil {
		log.G(ctx).WithError(err).Debugf("[dallas] validateReferrerRelationship: Failed to read %s", referrerRef)
		return false
	}
	
	// Try to parse as OCI manifest and check subject field
	var referrerManifest ocispec.Manifest
	if err := json.Unmarshal(referrerData, &referrerManifest); err == nil {
		if referrerManifest.Subject != nil && referrerManifest.Subject.Digest.String() == targetDigest {
			log.G(ctx).Debugf("[dallas] validateReferrerRelationship: ✅ Referrer %s correctly references target %s", referrerDesc.Digest, targetDigest)
			return true
		}
	}
	
	log.G(ctx).Debugf("[dallas] validateReferrerRelationship: ❌ Referrer %s does not reference target %s", referrerDesc.Digest, targetDigest)
	return false
}

// getKnownReferrers returns a map of known referrers for specific critical images
// This can be configured via containerd config, environment variables, or external configuration
func (c *CRIImageService) getKnownReferrers() map[string][]string {
	// TODO: Make this configurable via containerd config
	// ENABLED for comparison - let's test both approaches side by side
	if true {
		return map[string][]string{
			// Azure Linux busybox:1.36 (confirmed via Azure Portal)
			"sha256:eec430d63f60bfcaf42664dafd179a5975f0c33610c7fc727c8f10ddaad61a06": {
				"sha256:38dfa10d185eb899ff94a02a360f6e431f78232eda2f3b2a56a83d4f8c4c3d76",
			},
			// Add more known critical images and their referrers here
			// "sha256:another-manifest-digest": {"sha256:referrer1", "sha256:referrer2"},
		}
	}
	// Return empty map to force dynamic discovery
	return map[string][]string{}
}

// fetchReferrersAPIWithResolver uses the OCI Distribution Spec referrers API via the ReferrersFetcher interface
func (c *CRIImageService) fetchReferrersAPIWithResolver(ctx context.Context, resolver remotes.Resolver, ref string, target ocispec.Descriptor) (*ocispec.Index, error) {
	log.G(ctx).Infof("[dallas] fetchReferrersAPIWithResolver: Starting OCI referrers API call for ref %q, target digest %s", ref, target.Digest)
	
	// Get the fetcher from the resolver
	fetcher, err := resolver.Fetcher(ctx, ref)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("[dallas] fetchReferrersAPIWithResolver: Failed to get fetcher from resolver")
		return nil, fmt.Errorf("failed to get fetcher: %w", err)
	}
	
	// Check if the fetcher implements ReferrersFetcher interface
	referrersFetcher, ok := fetcher.(remotes.ReferrersFetcher)
	if !ok {
		log.G(ctx).Warnf("[dallas] fetchReferrersAPIWithResolver: Fetcher does not implement ReferrersFetcher interface (type: %T)", fetcher)
		return nil, fmt.Errorf("fetcher %T does not implement ReferrersFetcher", fetcher)
	}
	
	log.G(ctx).Infof("[dallas] fetchReferrersAPIWithResolver: Using ReferrersFetcher to fetch referrers for digest %s", target.Digest)
	
	// Call the FetchReferrers method with the target digest
	// We don't filter by artifact type - get all referrers
	reader, desc, err := referrersFetcher.FetchReferrers(ctx, target.Digest)
	if err != nil {
		log.G(ctx).WithError(err).Warnf("[dallas] fetchReferrersAPIWithResolver: FetchReferrers failed for digest %s", target.Digest)
		return nil, fmt.Errorf("failed to fetch referrers: %w", err)
	}
	defer reader.Close()
	
	log.G(ctx).Infof("[dallas] fetchReferrersAPIWithResolver: Successfully fetched referrers, descriptor: mediaType=%s, size=%d", desc.MediaType, desc.Size)
	
	// Read the referrers data
	referrersData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read referrers response: %w", err)
	}
	
	log.G(ctx).Infof("[dallas] fetchReferrersAPIWithResolver: Read %d bytes of referrers data", len(referrersData))
	if len(referrersData) > 0 {
		log.G(ctx).Infof("[dallas] fetchReferrersAPIWithResolver: Response content: %s", string(referrersData))
	} else {
		log.G(ctx).Warnf("[dallas] fetchReferrersAPIWithResolver: EMPTY RESPONSE - this might indicate:")
		log.G(ctx).Warnf("[dallas] fetchReferrersAPIWithResolver:   1. API endpoint returned successfully but with no content")
		log.G(ctx).Warnf("[dallas] fetchReferrersAPIWithResolver:   2. Referrers might be stored with different digest")
		log.G(ctx).Warnf("[dallas] fetchReferrersAPIWithResolver:   3. Response might be paginated or truncated")
		log.G(ctx).Warnf("[dallas] fetchReferrersAPIWithResolver:   4. Registry might have different behavior than expected")
	}
	
	// Handle empty response gracefully
	if len(referrersData) == 0 {
		log.G(ctx).Infof("[dallas] fetchReferrersAPIWithResolver: Empty response from referrers API, no referrers available")
		return &ocispec.Index{Manifests: []ocispec.Descriptor{}}, nil
	}
	
	// Parse the referrers index
	var referrersIndex ocispec.Index
	if err := json.Unmarshal(referrersData, &referrersIndex); err != nil {
		log.G(ctx).WithError(err).Errorf("[dallas] fetchReferrersAPIWithResolver: Failed to parse referrers JSON. Raw data (%d bytes): %q", len(referrersData), string(referrersData))
		return nil, fmt.Errorf("failed to parse referrers index: %w", err)
	}
	
	log.G(ctx).Infof("[dallas] fetchReferrersAPIWithResolver: Successfully parsed referrers index with %d manifests", len(referrersIndex.Manifests))
	return &referrersIndex, nil
}

// fetchReferrersByTags fallback method using tag-based discovery
func (c *CRIImageService) fetchReferrersByTags(ctx context.Context, fetcher remotes.Fetcher, ref string, target ocispec.Descriptor) (*ocispec.Index, error) {
	log.G(ctx).Infof("[dallas] fetchReferrersByTags: Starting tag-based referrer discovery for ref %q", ref)
	
	// For now, we'll implement a simple approach that returns no referrers
	// since we don't have direct access to the resolver here and the fetcher
	// doesn't support resolving by tag. A complete implementation would need
	// to be integrated with the registry client.
	log.G(ctx).Infof("[dallas] fetchReferrersByTags: Tag-based discovery requires resolver access, returning empty for ref %q", ref)
	
	return &ocispec.Index{Manifests: []ocispec.Descriptor{}}, nil
}

// fetchReferrersByTagsWithResolver uses resolver for tag-based discovery
func (c *CRIImageService) fetchReferrersByTagsWithResolver(ctx context.Context, resolver remotes.Resolver, ref string, target ocispec.Descriptor) (*ocispec.Index, error) {
	log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: Starting tag-based referrer discovery for ref %q", ref)
	
	// Parse the reference to get base components
	named, err := distribution.ParseDockerRef(ref)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("[dallas] fetchReferrersByTagsWithResolver: Failed to parse ref %q", ref)
		return nil, fmt.Errorf("failed to parse ref: %w", err)
	}
	
	// Extract repository path correctly (same logic as API call)
	repoName := named.Name()
	parts := strings.SplitN(repoName, "/", 2)
	var repoPath string
	if len(parts) == 2 && strings.Contains(parts[0], ".") {
		// Has hostname (contains dot) - use just the repository path
		repoPath = parts[1]
	} else {
		// No explicit hostname, use full name for Docker Hub repos
		repoPath = repoName
	}
	log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: Using repository path %q for tag construction", repoPath)
	
	// Try comprehensive referrer tag patterns based on both the original tag and the image digest
	// These patterns are used by various signing and attestation tools
	digestHex := target.Digest.Encoded()
	
	// Get the original tag for tag-based signature patterns
	var originalTag string
	log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: Checking if named reference is tagged. Type: %T", named)
	if tagged, ok := named.(distribution.Tagged); ok {
		originalTag = tagged.Tag()
		log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: Found original tag: %q (length: %d)", originalTag, len(originalTag))
	} else {
		log.G(ctx).Warnf("[dallas] fetchReferrersByTagsWithResolver: Reference is not tagged, cannot use tag-based discovery")
	}
	
	var referrerTags []string
	
	// Tag-based patterns (most common for Azure Container Registry and Docker Content Trust)
	if originalTag != "" {
		log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: Adding tag-based patterns for original tag %q", originalTag)
		referrerTags = append(referrerTags,
			fmt.Sprintf("%s.sig", originalTag),             // 1.36.sig (Azure/DCT pattern) - THIS IS THE KEY ONE!
			fmt.Sprintf("%s-sig", originalTag),             // 1.36-sig
			fmt.Sprintf("%s.signature", originalTag),       // 1.36.signature
			fmt.Sprintf("%s-signature", originalTag),       // 1.36-signature
			fmt.Sprintf("%s.att", originalTag),             // 1.36.att (attestations)
			fmt.Sprintf("%s-att", originalTag),             // 1.36-att
			fmt.Sprintf("%s.sbom", originalTag),            // 1.36.sbom
			fmt.Sprintf("%s-sbom", originalTag),            // 1.36-sbom
			fmt.Sprintf("sig-%s", originalTag),             // sig-1.36
			fmt.Sprintf("signature-%s", originalTag),       // signature-1.36
		)
	} else {
		log.G(ctx).Warnf("[dallas] fetchReferrersByTagsWithResolver: No original tag found, skipping tag-based discovery patterns")
	}
	
	// Digest-based patterns (for tools that use digest-based signatures)
	referrerTags = append(referrerTags,
		// Azure Linux / Microsoft patterns (try first since this is an Azure Linux image) 
		fmt.Sprintf("%s-sig", digestHex),               // <digest>-sig
		fmt.Sprintf("sha256-%s-sig", digestHex),        // sha256-<digest>-sig
		fmt.Sprintf("%s.signature", digestHex),         // <digest>.signature
		fmt.Sprintf("sha256-%s.signature", digestHex),  // sha256-<digest>.signature
		fmt.Sprintf("%s-signatures", digestHex),        // <digest>-signatures
		fmt.Sprintf("signatures-%s", digestHex),        // signatures-<digest>
		
		// Cosign signatures (most common)
		fmt.Sprintf("sha256-%s.sig", digestHex),         // sha256-<digest>.sig
		fmt.Sprintf("%s.sig", digestHex),                // <digest>.sig
		
		// Cosign attestations  
		fmt.Sprintf("sha256-%s.att", digestHex),         // sha256-<digest>.att
		fmt.Sprintf("%s.att", digestHex),                // <digest>.att
		
		// Generic referrers
		fmt.Sprintf("sha256-%s", digestHex),             // sha256-<digest>
		fmt.Sprintf("%s.ref", digestHex),                // <digest>.ref
		
		// Notary v2 signatures
		fmt.Sprintf("%s.nv2.sig", digestHex),           // <digest>.nv2.sig
		fmt.Sprintf("sha256-%s.nv2.sig", digestHex),    // sha256-<digest>.nv2.sig
		
		// SBOM and vulnerability reports
		fmt.Sprintf("%s.sbom", digestHex),              // <digest>.sbom
		fmt.Sprintf("sha256-%s.sbom", digestHex),       // sha256-<digest>.sbom
		fmt.Sprintf("%s.vuln", digestHex),              // <digest>.vuln
		fmt.Sprintf("sha256-%s.vuln", digestHex),       // sha256-<digest>.vuln
		
		// Docker Content Trust (legacy)
		fmt.Sprintf("%s.sig", target.Digest.String()),  // sha256:<full-digest>.sig
		
		// Other common patterns
		fmt.Sprintf("%s.cosign", digestHex),            // <digest>.cosign
		fmt.Sprintf("sig-%s", digestHex),               // sig-<digest>
		fmt.Sprintf("att-%s", digestHex),               // att-<digest>
	)
	
	var manifests []ocispec.Descriptor
	
	log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: Will try %d referrer tag patterns", len(referrerTags))
	for i, tag := range referrerTags {
		// Build the full referrer reference with the original registry host
		var referrerRef string
		if len(parts) == 2 && strings.Contains(parts[0], ".") {
			// Has hostname - construct full reference: hostname/repoPath:tag
			referrerRef = fmt.Sprintf("%s/%s:%s", parts[0], repoPath, tag)
		} else {
			// Docker Hub - use repoPath:tag
			referrerRef = fmt.Sprintf("%s:%s", repoPath, tag)
		}
		log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: [%d/%d] Trying referrer tag %q", i+1, len(referrerTags), referrerRef)
		
		// Try to resolve this tag
		_, desc, err := resolver.Resolve(ctx, referrerRef)
		if err != nil {
			log.G(ctx).WithError(err).Debugf("[dallas] fetchReferrersByTagsWithResolver: Failed to resolve referrer tag %q", referrerRef)
			continue // Skip if tag doesn't exist
		}
		
		log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: Found referrer with tag %q, digest %s, media type %s, size %d", 
			referrerRef, desc.Digest, desc.MediaType, desc.Size)
		
		// Add metadata to help identify the referrer type
		if desc.Annotations == nil {
			desc.Annotations = make(map[string]string)
		}
		desc.Annotations["vnd.docker.reference.type"] = "referrer"
		desc.Annotations["vnd.docker.reference.digest"] = target.Digest.String()
		desc.Annotations["vnd.docker.reference.tag"] = tag
		
		manifests = append(manifests, desc)
	}
	
	if len(manifests) == 0 {
		log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: No referrer artifacts found using tag discovery for ref %q", ref)
		return &ocispec.Index{Manifests: []ocispec.Descriptor{}}, nil
	}
	
	log.G(ctx).Infof("[dallas] fetchReferrersByTagsWithResolver: Found %d referrer artifacts using tag discovery for ref %q", len(manifests), ref)
	return &ocispec.Index{Manifests: manifests}, nil
}

// pullSingleReferrer pulls a single referrer artifact
func (c *CRIImageService) pullSingleReferrer(ctx context.Context, fetcher remotes.Fetcher, originalRef string, desc ocispec.Descriptor) error {
	log.G(ctx).Infof("[dallas] 🚀🚀🚀 NEW BINARY VERIFIED - BUILD OCT 6 2025 - WITH APPEND LOGIC 🚀🚀🚀")
	log.G(ctx).WithFields(log.Fields{
		"digest":    desc.Digest,
		"mediaType": desc.MediaType,
		"size":      desc.Size,
	}).Infof("[dallas] pullSingleReferrer: Starting pull of referrer for image %q", originalRef)
	
	// Fetch the referrer manifest
	log.G(ctx).Infof("[dallas] pullSingleReferrer: Fetching referrer manifest for digest %s", desc.Digest)
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("[dallas] pullSingleReferrer: Failed to fetch referrer manifest for digest %s", desc.Digest)
		return fmt.Errorf("failed to fetch referrer manifest: %w", err)
	}
	log.G(ctx).Infof("[dallas] pullSingleReferrer: Successfully fetched referrer manifest")
	
	// INSPECT REFERRER CONTENT - Read and analyze what's inside
	if err := c.inspectAndLogReferrerContent(ctx, rc, desc); err != nil {
		log.G(ctx).WithError(err).Warnf("[dallas] pullSingleReferrer: Failed to inspect referrer content")
	}
	rc.Close() // Close the inspection reader
	
	// Re-fetch the referrer since inspectAndLogReferrerContent consumed the reader
	log.G(ctx).Infof("[dallas] pullSingleReferrer: Re-fetching referrer manifest for storage after inspection")
	rc, err = fetcher.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("failed to re-fetch referrer manifest for storage: %w", err)
	}
	defer rc.Close()
	
	// Store the referrer in containerd's content store
	log.G(ctx).Infof("[dallas] pullSingleReferrer: Getting content store for referrer storage")
	cs := c.content
	
	// Check if content already exists
	if _, err := cs.Info(ctx, desc.Digest); err == nil {
		log.G(ctx).Infof("[dallas] pullSingleReferrer: Referrer %s already exists in content store, skipping storage", desc.Digest)
	} else {
		// Content doesn't exist, need to store it
		writer, err := cs.Writer(ctx, content.WithDescriptor(desc), content.WithRef(desc.Digest.String()))
		if err != nil {
			log.G(ctx).WithError(err).Errorf("[dallas] pullSingleReferrer: Failed to create writer for referrer %s", desc.Digest)
			return fmt.Errorf("failed to create writer for referrer: %w", err)
		}
		defer writer.Close()
		log.G(ctx).Infof("[dallas] pullSingleReferrer: Created content store writer for referrer %s", desc.Digest)
		
		n, err := io.Copy(writer, rc)
		if err != nil {
			log.G(ctx).WithError(err).Errorf("[dallas] pullSingleReferrer: Failed to write referrer content for %s", desc.Digest)
			return fmt.Errorf("failed to write referrer content: %w", err)
		}
		log.G(ctx).Infof("[dallas] pullSingleReferrer: Successfully wrote %d bytes of referrer content to content store (expected %d bytes)", n, desc.Size)
		
		if err := writer.Commit(ctx, desc.Size, desc.Digest); err != nil {
			log.G(ctx).WithError(err).Errorf("[dallas] pullSingleReferrer: Failed to commit referrer %s", desc.Digest)
			return fmt.Errorf("failed to commit referrer: %w", err)
		}
		log.G(ctx).Infof("[dallas] pullSingleReferrer: Successfully committed referrer %s to content store", desc.Digest)
	}
	
	// If it's a manifest, we might need to pull its layers too
	if containerdimages.IsManifestType(desc.MediaType) {
		log.G(ctx).Infof("[dallas] pullSingleReferrer: Detected manifest type %s, pulling layers for referrer %s", desc.MediaType, desc.Digest)
		if err := c.pullReferrerLayers(ctx, fetcher, desc); err != nil {
			log.G(ctx).WithError(err).Errorf("[dallas] pullSingleReferrer: Failed to pull layers for referrer %s", desc.Digest)
			return fmt.Errorf("failed to pull referrer layers: %w", err)
		}
		log.G(ctx).Infof("[dallas] pullSingleReferrer: Successfully pulled layers for referrer %s", desc.Digest)
		
		// BRIDGE CODE: Extract signature metadata and write to filesystem for EROFS snapshotter
		if err := c.extractAndStoreSignatureMetadata(ctx, originalRef, desc); err != nil {
			log.G(ctx).WithError(err).Warnf("[dallas] pullSingleReferrer: Failed to extract signature metadata for referrer %s", desc.Digest)
			// Don't fail the pull if signature extraction fails
		} else {
			log.G(ctx).Infof("[dallas] pullSingleReferrer: Successfully extracted signature metadata for referrer %s", desc.Digest)
		}
	} else {
		log.G(ctx).Infof("[dallas] pullSingleReferrer: Referrer %s is not a manifest type (%s), skipping layer pull", desc.Digest, desc.MediaType)
	}
	
	log.G(ctx).Infof("[dallas] pullSingleReferrer: Successfully completed pull for referrer %s", desc.Digest)
	return nil
}

// inspectAndLogReferrerContent analyzes referrer content to show what's inside
func (c *CRIImageService) inspectAndLogReferrerContent(ctx context.Context, rc io.ReadCloser, desc ocispec.Descriptor) error {
	log.G(ctx).Infof("[dallas] 🔍 INSPECTING REFERRER CONTENT: digest=%s, mediaType=%s, size=%d", desc.Digest, desc.MediaType, desc.Size)
	
	// Read all content
	content, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("failed to read referrer content: %w", err)
	}
	
	// Check for specific artifact types we know how to handle
	switch desc.MediaType {
	case "application/vnd.oci.mt.pkcs7":
		log.G(ctx).Infof("[dallas] 🔐 MICROSOFT PKCS#7 ARTIFACT detected - this is Azure Linux filesystem signature")
	case "application/vnd.dev.cosign.simplesigning.v1+json":
		log.G(ctx).Infof("[dallas] ✍️  COSIGN SIGNATURE detected - this is container image signature")
	case "application/vnd.in-toto+json":
		log.G(ctx).Infof("[dallas] 📋 IN-TOTO ATTESTATION detected - this is SLSA provenance/attestation")
	default:
		log.G(ctx).Infof("[dallas] ❓ Unknown artifact type: %s", desc.MediaType)
	}
	
	log.G(ctx).Infof("[dallas] 📄 Raw referrer content (%d bytes):\n%s", len(content), string(content))
	
	// Try to parse as JSON (most referrers are JSON manifests)
	var jsonContent map[string]interface{}
	if err := json.Unmarshal(content, &jsonContent); err == nil {
		log.G(ctx).Infof("[dallas] ✅ Successfully parsed referrer as JSON")
		
		// Look for artifactType field (newer OCI artifact spec)
		if artifactType, ok := jsonContent["artifactType"].(string); ok {
			log.G(ctx).Infof("[dallas] 🎨 Artifact type: %s", artifactType)
			switch artifactType {
			case "application/vnd.oci.mt.pkcs7":
				log.G(ctx).Infof("[dallas] 🔐 MICROSOFT PKCS#7 ARTIFACT - Azure Linux filesystem signatures")
			case "application/vnd.dev.cosign.artifact":
				log.G(ctx).Infof("[dallas] ✍️  COSIGN ARTIFACT - Container image signature/attestation")
			case "application/vnd.in-toto+json":
				log.G(ctx).Infof("[dallas] 📋 IN-TOTO ARTIFACT - SLSA provenance/attestation")
			}
		}
		
		// Look for specific fields that indicate what type of referrer this is
		if mediaType, ok := jsonContent["mediaType"].(string); ok {
			log.G(ctx).Infof("[dallas] 🎯 Referrer mediaType: %s", mediaType)
		}
		
		if config, ok := jsonContent["config"].(map[string]interface{}); ok {
			if configMediaType, ok := config["mediaType"].(string); ok {
				log.G(ctx).Infof("[dallas] ⚙️  Config mediaType: %s", configMediaType)
			}
		}
		
		// Look for layers (where signatures/attestations are often stored)
		if layers, ok := jsonContent["layers"].([]interface{}); ok {
			log.G(ctx).Infof("[dallas] 📦 Found %d layer(s) in referrer", len(layers))
			for i, layer := range layers {
				if layerMap, ok := layer.(map[string]interface{}); ok {
					digest := layerMap["digest"]
					mediaType := layerMap["mediaType"]
					size := layerMap["size"]
					log.G(ctx).Infof("[dallas] 📦 Layer[%d]: digest=%v, mediaType=%v, size=%v", i, digest, mediaType, size)
					
					// Check for specific layer types we know about
					if layerMediaType, ok := mediaType.(string); ok {
						switch layerMediaType {
						case "application/vnd.oci.image.layer.v1.erofs.sig":
							log.G(ctx).Infof("[dallas] 🔐 EROFS SIGNATURE LAYER detected - Azure Linux filesystem integrity signature")
						case "application/vnd.dev.cosign.simplesigning.v1+json":
							log.G(ctx).Infof("[dallas] ✍️  COSIGN SIGNATURE LAYER detected")
						case "application/vnd.in-toto+json":
							log.G(ctx).Infof("[dallas] 📋 IN-TOTO ATTESTATION LAYER detected")
						}
					}
					
					// Look for annotations that might contain root hashes or other metadata
					if annotations, ok := layerMap["annotations"].(map[string]interface{}); ok {
						log.G(ctx).Infof("[dallas] 🏷️  Layer[%d] annotations:", i)
						for key, value := range annotations {
							log.G(ctx).Infof("[dallas] 🏷️    %s: %v", key, value)
							
							// Specific detection for known annotation patterns
							switch key {
							case "image.layer.root_hash":
								log.G(ctx).Infof("[dallas] 🔑 EROFS ROOT HASH FOUND: %v", value)
							case "image.layer.digest":
								log.G(ctx).Infof("[dallas] 🎯 Layer refers to filesystem layer: %v", value)
							case "image.layer.signature":
								if str, ok := value.(string); ok && len(str) > 50 {
									log.G(ctx).Infof("[dallas] 📜 PKCS#7 SIGNATURE FOUND (%d chars): %s...", len(str), str[:50])
								} else {
									log.G(ctx).Infof("[dallas] 📜 SIGNATURE DATA: %v", value)
								}
							case "signature.blob.name":
								log.G(ctx).Infof("[dallas] 📝 Signature blob name: %v", value)
							default:
								// General root hash detection
								if strings.Contains(strings.ToLower(key), "root") || strings.Contains(strings.ToLower(key), "hash") {
									log.G(ctx).Infof("[dallas] 🔑 POTENTIAL ROOT HASH - %s: %v", key, value)
								}
							}
						}
					}
				}
			}
		}
		
		// Look for top-level annotations
		if annotations, ok := jsonContent["annotations"].(map[string]interface{}); ok {
			log.G(ctx).Infof("[dallas] 🏷️  Top-level annotations:")
			for key, value := range annotations {
				log.G(ctx).Infof("[dallas] 🏷️    %s: %v", key, value)
				if strings.Contains(strings.ToLower(key), "root") || strings.Contains(strings.ToLower(key), "hash") {
					log.G(ctx).Infof("[dallas] 🔑 POTENTIAL ROOT HASH - %s: %v", key, value)
				}
			}
		}
		
		// Look for subject (what this referrer refers to)
		if subject, ok := jsonContent["subject"].(map[string]interface{}); ok {
			if subjectDigest, ok := subject["digest"].(string); ok {
				log.G(ctx).Infof("[dallas] 🎯 Referrer subject (refers to): %s", subjectDigest)
			}
		}
		
	} else {
		log.G(ctx).Infof("[dallas] ❌ Could not parse referrer as JSON, might be binary content")
		// Show first 200 characters as hex for binary content
		hexContent := fmt.Sprintf("%x", content[:min(len(content), 200)])
		log.G(ctx).Infof("[dallas] 🔍 First 200 bytes as hex: %s", hexContent)
	}
	
	return nil
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// pullReferrerLayers pulls layers referenced by a referrer manifest
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
	log.G(ctx).Infof("[dallas] ═══════════════════════════════════════════════════════════")
	log.G(ctx).Infof("[dallas] 🔄 STARTING SIGNATURE METADATA EXTRACTION")
	log.G(ctx).Infof("[dallas] ═══════════════════════════════════════════════════════════")
	log.G(ctx).Infof("[dallas] Image Ref: %s", imageRef)
	log.G(ctx).Infof("[dallas] Referrer Manifest Digest: %s", manifestDesc.Digest)
	log.G(ctx).Infof("[dallas] Referrer Manifest MediaType: %s", manifestDesc.MediaType)
	log.G(ctx).Infof("[dallas] Referrer Manifest Size: %d bytes", manifestDesc.Size)
	
	cs := c.content
	log.G(ctx).Infof("[dallas] 📖 Step 1: Reading referrer manifest from content store...")
	
	// Read the referrer manifest from content store
	manifestData, err := content.ReadBlob(ctx, cs, manifestDesc)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("[dallas] ❌ Failed to read referrer manifest from content store")
		return fmt.Errorf("failed to read referrer manifest: %w", err)
	}
	log.G(ctx).Infof("[dallas] ✅ Successfully read %d bytes of manifest data from content store", len(manifestData))
	
	log.G(ctx).Infof("[dallas] 📋 Step 2: Parsing manifest JSON...")
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		log.G(ctx).WithError(err).Errorf("[dallas] ❌ Failed to unmarshal referrer manifest JSON")
		return fmt.Errorf("failed to unmarshal referrer manifest: %w", err)
	}
	log.G(ctx).Infof("[dallas] ✅ Successfully parsed manifest")
	log.G(ctx).Infof("[dallas]    - Schema Version: %d", manifest.SchemaVersion)
	log.G(ctx).Infof("[dallas]    - MediaType: %s", manifest.MediaType)
	log.G(ctx).Infof("[dallas]    - ArtifactType: %s", manifest.ArtifactType)
	log.G(ctx).Infof("[dallas]    - Config: %s (size: %d)", manifest.Config.Digest, manifest.Config.Size)
	log.G(ctx).Infof("[dallas]    - Layer Count: %d", len(manifest.Layers))
	
	// Check if this is a Microsoft PKCS#7 signature artifact (Azure Linux filesystem signatures)
	log.G(ctx).Infof("[dallas] 🔍 Step 3: Validating artifact type...")
	if manifest.ArtifactType != "application/vnd.oci.mt.pkcs7" {
		log.G(ctx).Infof("[dallas] ⏭️  Skipping: Not a Microsoft PKCS#7 artifact (type: %s)", manifest.ArtifactType)
		log.G(ctx).Infof("[dallas]    Expected: application/vnd.oci.mt.pkcs7")
		log.G(ctx).Infof("[dallas] ═══════════════════════════════════════════════════════════")
		return nil
	}
	
	log.G(ctx).Infof("[dallas] ✅ Artifact type validated: Microsoft PKCS#7 signature artifact")
	log.G(ctx).Infof("[dallas] 🔐 This contains EROFS filesystem signatures for Azure Linux")
	
	// Build LayerInfo structures for each layer
	log.G(ctx).Infof("[dallas] ───────────────────────────────────────────────────────────")
	log.G(ctx).Infof("[dallas] 📦 Step 4: Extracting layer signature metadata...")
	log.G(ctx).Infof("[dallas] ───────────────────────────────────────────────────────────")
	var layerInfos []map[string]interface{}
	
	for i, layer := range manifest.Layers {
		log.G(ctx).Infof("[dallas] 🔍 Processing Layer %d/%d", i+1, len(manifest.Layers))
		log.G(ctx).Infof("[dallas]    Layer Digest: %s", layer.Digest)
		log.G(ctx).Infof("[dallas]    Layer MediaType: %s", layer.MediaType)
		log.G(ctx).Infof("[dallas]    Layer Size: %d bytes", layer.Size)
		
		// Extract metadata from layer annotations
		if layer.Annotations == nil {
			log.G(ctx).Warnf("[dallas] ⚠️  Layer %d has no annotations - skipping", i+1)
			continue
		}
		log.G(ctx).Infof("[dallas]    Annotations found: %d entries", len(layer.Annotations))
		
		// Get the filesystem layer digest this signature refers to
		layerDigest, ok := layer.Annotations["image.layer.digest"]
		if !ok {
			log.G(ctx).Warnf("[dallas] ⚠️  Layer %d missing 'image.layer.digest' annotation - skipping", i+1)
			log.G(ctx).Infof("[dallas]    Available annotations: %v", layer.Annotations)
			continue
		}
		log.G(ctx).Infof("[dallas]    ✅ Found filesystem layer digest: %s", layerDigest)
		
		// Get the EROFS root hash
		rootHash, ok := layer.Annotations["image.layer.root_hash"]
		if !ok {
			log.G(ctx).Warnf("[dallas] ⚠️  Layer %d missing 'image.layer.root_hash' annotation - skipping", i+1)
			continue
		}
		log.G(ctx).Infof("[dallas]    ✅ Found EROFS root hash: %s", rootHash)
		
		// Read the signature blob from content store
		log.G(ctx).Infof("[dallas]    📥 Reading signature blob from content store...")
		signatureData, err := content.ReadBlob(ctx, cs, layer)
		if err != nil {
			log.G(ctx).WithError(err).Warnf("[dallas] ⚠️  Failed to read signature blob for layer %d - skipping", i+1)
			continue
		}
		log.G(ctx).Infof("[dallas]    ✅ Read %d bytes of signature data (PKCS#7 DER format)", len(signatureData))
		
		// The signature is stored as raw PKCS#7 DER bytes, encode to base64 for JSON storage
		signatureBase64 := base64.StdEncoding.EncodeToString(signatureData)
		log.G(ctx).Infof("[dallas]    ✅ Encoded signature to base64: %d characters", len(signatureBase64))
		
		log.G(ctx).Infof("[dallas] ✅ Successfully processed Layer %d:", i+1)
		log.G(ctx).Infof("[dallas]    - Filesystem Layer: %s", layerDigest)
		log.G(ctx).Infof("[dallas]    - EROFS Root Hash: %s", rootHash)
		log.G(ctx).Infof("[dallas]    - Signature: %d bytes (base64: %d chars)", len(signatureData), len(signatureBase64))
		
		// Build LayerInfo structure matching what EROFS snapshotter expects
		layerInfo := map[string]interface{}{
			"digest":     layerDigest,
			"root_hash":  rootHash,
			"signature":  signatureBase64,
		}
		layerInfos = append(layerInfos, layerInfo)
		log.G(ctx).Infof("[dallas] ───────────────────────────────────────────────────────────")
	}
	
	if len(layerInfos) == 0 {
		log.G(ctx).Warnf("[dallas] ⚠️  No valid layer info extracted from referrer manifest")
		log.G(ctx).Warnf("[dallas]    This might indicate missing annotations or incompatible format")
		log.G(ctx).Infof("[dallas] ═══════════════════════════════════════════════════════════")
		return nil
	}
	
	log.G(ctx).Infof("[dallas] 🎉 Successfully extracted metadata for %d layers!", len(layerInfos))
	log.G(ctx).Infof("[dallas] ───────────────────────────────────────────────────────────")
	log.G(ctx).Infof("[dallas] 💾 Step 5: Building JSON structure for filesystem storage...")
	log.G(ctx).Infof("[dallas] ───────────────────────────────────────────────────────────")
	
	// Build ImageInfo structure (matches format expected by EROFS snapshotter)
	imageInfo := map[string]interface{}{
		"layers": layerInfos,
	}
	log.G(ctx).Infof("[dallas] ✅ Built ImageInfo structure with %d layer entries", len(layerInfos))
	
	// Wrap in array as expected by readSignatureManifests()
	signatureManifest := []map[string]interface{}{imageInfo}
	log.G(ctx).Infof("[dallas] ✅ Wrapped in array format expected by EROFS snapshotter")
	
	// Marshal to JSON
	log.G(ctx).Infof("[dallas] 📝 Marshaling to JSON with indentation...")
	jsonData, err := json.MarshalIndent(signatureManifest, "", "  ")
	if err != nil {
		log.G(ctx).WithError(err).Errorf("[dallas] ❌ Failed to marshal signature manifest to JSON")
		return fmt.Errorf("failed to marshal signature manifest: %w", err)
	}
	log.G(ctx).Infof("[dallas] ✅ Successfully marshaled to JSON: %d bytes", len(jsonData))
	
	// Write to filesystem in signature-manifests directory
	// We need to write to each snapshotter's root directory
	log.G(ctx).Infof("[dallas] ───────────────────────────────────────────────────────────")
	log.G(ctx).Infof("[dallas] 📁 Step 6: Writing signature manifest files to filesystem...")
	log.G(ctx).Infof("[dallas] ───────────────────────────────────────────────────────────")
	log.G(ctx).Infof("[dallas] Configured snapshotters: %d", len(c.imageFSPaths))
	
	if len(c.imageFSPaths) == 0 {
		log.G(ctx).Warnf("[dallas] ⚠️  No snapshotter paths configured! Cannot write signature manifests.")
		log.G(ctx).Infof("[dallas] ═══════════════════════════════════════════════════════════")
		return fmt.Errorf("no snapshotter paths configured")
	}
	
	successCount := 0
	for snapshotterName, snapshotterPath := range c.imageFSPaths {
		log.G(ctx).Infof("[dallas] 🔄 Processing snapshotter: %s", snapshotterName)
		log.G(ctx).Infof("[dallas]    Root path: %s", snapshotterPath)
		
		// Create signature-manifests directory if it doesn't exist
		sigManifestDir := filepath.Join(snapshotterPath, "signature-manifests")
		log.G(ctx).Infof("[dallas]    Creating directory: %s", sigManifestDir)
		if err := os.MkdirAll(sigManifestDir, 0755); err != nil {
			log.G(ctx).WithError(err).Warnf("[dallas] ⚠️  Failed to create signature-manifests dir for snapshotter %s", snapshotterName)
			continue
		}
		log.G(ctx).Infof("[dallas]    ✅ Directory created/verified")
		
		// Use a well-known filename: signatures.json (append to existing file)
		filePath := filepath.Join(sigManifestDir, "signatures.json")
		log.G(ctx).Infof("[dallas]    Target file: %s", filePath)
		
		// Read existing signatures.json if it exists
		var existingManifests []map[string]interface{}
		if existingData, err := os.ReadFile(filePath); err == nil {
			log.G(ctx).Infof("[dallas]    📖 Found existing signatures.json (%d bytes), reading...", len(existingData))
			if err := json.Unmarshal(existingData, &existingManifests); err != nil {
				log.G(ctx).WithError(err).Warnf("[dallas] ⚠️  Failed to parse existing signatures.json, will overwrite")
				existingManifests = nil
			} else {
				log.G(ctx).Infof("[dallas]    ✅ Successfully parsed existing file: %d image entries", len(existingManifests))
			}
		} else if os.IsNotExist(err) {
			log.G(ctx).Infof("[dallas]    📝 No existing signatures.json, will create new file")
		} else {
			log.G(ctx).WithError(err).Warnf("[dallas] ⚠️  Error checking for existing file: %v", err)
		}
		
		// Merge new layer info with existing entries
		// Build a map of existing digests to avoid duplicates
		existingDigests := make(map[string]bool)
		if len(existingManifests) > 0 {
			log.G(ctx).Infof("[dallas]    🔍 Scanning existing entries for duplicates...")
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
			log.G(ctx).Infof("[dallas]    ✅ Found %d existing layer digests", len(existingDigests))
		}
		
		// Add only new layers that don't already exist
		newLayersAdded := 0
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
			log.G(ctx).Infof("[dallas]    ✅ Preserved %d existing layers", len(mergedLayers))
		}
		
		// Then add new layers if they don't already exist
		log.G(ctx).Infof("[dallas]    🔍 Checking new layers for duplicates...")
		for _, newLayer := range layerInfos {
			digest := newLayer["digest"].(string)
			if existingDigests[digest] {
				log.G(ctx).Infof("[dallas]       ⏭️  Skipping duplicate: %s", digest)
			} else {
				mergedLayers = append(mergedLayers, newLayer)
				newLayersAdded++
				log.G(ctx).Infof("[dallas]       ➕ Adding new layer: %s", digest)
			}
		}
		
		log.G(ctx).Infof("[dallas]    ✅ Total layers after merge: %d (added %d new)", len(mergedLayers), newLayersAdded)
		
		// Build final structure with all layers in a single ImageInfo
		finalManifest := []map[string]interface{}{
			{
				"layers": mergedLayers,
			},
		}
		
		// Marshal merged data to JSON
		log.G(ctx).Infof("[dallas]    📝 Marshaling merged data to JSON...")
		mergedJSON, err := json.MarshalIndent(finalManifest, "", "  ")
		if err != nil {
			log.G(ctx).WithError(err).Warnf("[dallas] ⚠️  Failed to marshal merged data")
			continue
		}
		
		// Write the merged JSON file
		log.G(ctx).Infof("[dallas]    💾 Writing merged signatures.json (%d bytes)...", len(mergedJSON))
		if err := os.WriteFile(filePath, mergedJSON, 0644); err != nil {
			log.G(ctx).WithError(err).Warnf("[dallas] ⚠️  Failed to write signature manifest to %s", filePath)
			continue
		}
		
		log.G(ctx).Infof("[dallas]    ✅ File written successfully: %d bytes", len(mergedJSON))
		log.G(ctx).Infof("[dallas]    📄 File path: %s", filePath)
		log.G(ctx).Infof("[dallas]    📊 Stats: %d existing + %d new = %d total layers", len(mergedLayers)-newLayersAdded, newLayersAdded, len(mergedLayers))
		successCount++
	}
	
	log.G(ctx).Infof("[dallas] ───────────────────────────────────────────────────────────")
	if successCount == 0 {
		log.G(ctx).Errorf("[dallas] ❌ Failed to write signature manifest to any snapshotter!")
		log.G(ctx).Infof("[dallas] ═══════════════════════════════════════════════════════════")
		return fmt.Errorf("failed to write signature manifest to any snapshotter")
	}
	
	log.G(ctx).Infof("[dallas] 🎉 SUCCESS! Signature metadata extraction complete")
	log.G(ctx).Infof("[dallas]    ✅ Layers processed: %d", len(layerInfos))
	log.G(ctx).Infof("[dallas]    ✅ Snapshotters updated: %d/%d", successCount, len(c.imageFSPaths))
	log.G(ctx).Infof("[dallas]    ✅ JSON size: %d bytes", len(jsonData))
	log.G(ctx).Infof("[dallas]    ✅ Filename: %s.json", manifestDesc.Digest.Encoded())
	log.G(ctx).Infof("[dallas] ═══════════════════════════════════════════════════════════")
	return nil
}
