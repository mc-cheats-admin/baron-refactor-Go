package middleware

import (
	"bytes"
	"io"
)

// newReadCloser wraps a []byte into an io.ReadCloser so the request body
// can be re-injected after being read for HMAC verification.
func newReadCloser(data []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(data))
}
