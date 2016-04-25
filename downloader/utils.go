// Copyright 2016 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package downloader

import (
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/juju/errors"
	"github.com/juju/utils"
)

// NewHTTPBlobOpener returns a blob opener func suitable for use with
// Download. The opener func uses an HTTP client that enforces the
// provided SSL hostname verification policy.
func NewHTTPBlobOpener(hostnameVerification utils.SSLHostnameVerification) func(*url.URL) (io.ReadCloser, error) {
	return func(url *url.URL) (io.ReadCloser, error) {
		// TODO(rog) make the download operation interruptible.
		client := utils.GetHTTPClient(hostnameVerification)
		resp, err := client.Get(url.String())
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			// resp.Body is always non-nil. (see https://golang.org/pkg/net/http/#Response)
			resp.Body.Close()
			return nil, errors.Errorf("bad http response: %v", resp.Status)
		}
		return resp.Body, nil
	}
}

// NewSha256Verifier returns a verifier suitable for Request. The
// verifier checks the SHA-256 checksum of the file to ensure that it
// matches the one returned by the provided func.
func NewSha256Verifier(getExpected func() (string, error)) func(*os.File) error {
	return func(file *os.File) error {
		expected, err := getExpected()
		if err != nil {
			return errors.Trace(err)
		}

		actual, _, err := utils.ReadSHA256(file)
		if err != nil {
			return errors.Trace(err)
		}
		if actual != expected {
			err := errors.Errorf("expected sha256 %q, got %q", expected, actual)
			return errors.NewNotValid(err, "")
		}
		return nil
	}
}
