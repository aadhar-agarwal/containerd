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

package docker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func (r dockerFetcher) FetchReferrers(ctx context.Context, dgst digest.Digest, artifactTypes ...string) (io.ReadCloser, ocispec.Descriptor, error) {
	var desc ocispec.Descriptor
	// The referrers endpoint returns an image index
	// The image index contains a list of referrer references.
	desc.MediaType = ocispec.MediaTypeImageIndex
	ctx = log.WithLogger(ctx, log.G(ctx).WithField("digest", dgst))

	// Filter for hosts that have referrers capability OR resolve capability (for fallback)
	hosts := r.filterHosts(HostCapabilityResolve | HostCapabilityReferrers)
	if len(hosts) == 0 {
		return nil, desc, fmt.Errorf("no pull hosts: %w", errdefs.ErrNotFound)
	}

	ctx, err := ContextWithRepositoryScope(ctx, r.refspec, false)
	if err != nil {
		return nil, desc, err
	}

	for _, host := range hosts {
		var req *request
		if host.Capabilities.Has(HostCapabilityReferrers) {
			// Try the OCI Distribution Spec referrers API
			// Build the path with query parameters if artifact types are specified
			pathWithQuery := "referrers/" + dgst.String()
			if len(artifactTypes) > 0 {
				// Add artifactType query parameters
				// Note: Multiple artifactType parameters are allowed by the spec
				queryParams := make([]string, len(artifactTypes))
				for i, at := range artifactTypes {
					queryParams[i] = "artifactType=" + at
				}
				pathWithQuery += "?" + strings.Join(queryParams, "&")
			}
			req = r.request(host, http.MethodGet, pathWithQuery)

			rc, err := r.open(ctx, req, desc.MediaType, 0)
			if err != nil {
				if !errdefs.IsNotFound(err) {
					log.G(ctx).WithError(err).Warn("referrers API request failed")
					return nil, desc, err
				}
				// Not found, try fallback
				log.G(ctx).Debug("referrers API returned not found, trying fallback")
			} else {
				// Success - return the referrers index
				// Size is unknown without reading the content
				log.G(ctx).Info("successfully fetched referrers via OCI API")
				return rc, desc, nil
			}
		}
		// This is a fallback for registries that do not support the referrers API.
		// For example, a Cosign signature is a manifest with a new tag living in the same repo,
		// rather than living in the referrers list
		if host.Capabilities.Has(HostCapabilityResolve) {
			tagSuffix := strings.Replace(dgst.String(), ":", "-", 1) + ".sig"
			req = r.request(host, http.MethodGet, "manifests", tagSuffix)
			
			rc, err := r.open(ctx, req, desc.MediaType, 0)
			if err != nil {
				if !errdefs.IsNotFound(err) {
					log.G(ctx).WithError(err).Warn("fallback referrers request failed")
					return nil, desc, err
				}
				// Not found with this host, try next host
				log.G(ctx).Debug("fallback referrers not found")
			} else {
				// Success with fallback
				log.G(ctx).Info("successfully fetched referrers via fallback method")
				return rc, desc, nil
			}
		}
	}

	return nil, ocispec.Descriptor{}, fmt.Errorf("could not be found at any host: %w", errdefs.ErrNotFound)
}
