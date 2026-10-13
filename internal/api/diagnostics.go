package api

import (
	"context"
	"errors"
	"fmt"
	"github.com/awarelyeu/awarely-sbom-scanner/internal/diagnostics"
)

// RemoteError retains only a locally allowed code, never arbitrary server text.
type RemoteError struct {
	Status int
	Code   string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("API returned HTTP %d (%s)", e.Status, e.Code)
}

var ErrPartialSync = errors.New("sync requires complete coverage; review the local SBOM warnings")
var ErrEmptySync = errors.New("empty sync requires --allow-empty")
var ErrTransport = errors.New("API transport failed; credentials and response details were not logged")

func Diagnose(ctx context.Context, err error) {
	code := "REMOTE_FAILED"
	var remote *RemoteError
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		code = "INTERRUPTED"
	case errors.As(err, &remote):
		code = remote.Code
	case errors.Is(err, ErrPartialSync):
		code = "PARTIAL_SYNC"
	case errors.Is(err, ErrEmptySync):
		code = "EMPTY_SYNC"
	case errors.Is(err, ErrTransport):
		code = "API_TRANSPORT_FAILED"
	}
	diagnostics.Failure(ctx, code)
}
