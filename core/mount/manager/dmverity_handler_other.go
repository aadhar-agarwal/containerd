//go:build !linux

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

package manager

import (
	"context"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/errdefs"
)

type dmverityHandler struct{}

func (h dmverityHandler) Mount(ctx context.Context, m mount.Mount, target string, active []mount.ActiveMount) (mount.ActiveMount, error) {
	return mount.ActiveMount{}, errdefs.ErrNotImplemented
}

func (h dmverityHandler) Unmount(ctx context.Context, target string) error {
	return errdefs.ErrNotImplemented
}

func unmountDmverity(ctx context.Context, active mount.ActiveMount) error {
	return errdefs.ErrNotImplemented
}
