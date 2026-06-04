// Copyright © 2026 Attestant Limited.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/attestantio/dirk/testing/resources"
	standardservercert "github.com/attestantio/go-certmanager/server/standard"
	mockcertfetcher "github.com/attestantio/go-certmanager/testing/mock"
	"github.com/stretchr/testify/require"
)

// newTestCertManager builds an in-memory server certificate manager backed by
// the bundled test signer certificate and key.
func newTestCertManager(t *testing.T) *standardservercert.Service {
	t.Helper()
	fetcher := mockcertfetcher.NewMajordomo(map[string][]byte{
		"cert.pem": resources.SignerTest01Crt,
		"cert.key": resources.SignerTest01Key,
	})
	mgr, err := standardservercert.New(t.Context(),
		standardservercert.WithMajordomo(fetcher),
		standardservercert.WithCertPEMURI("cert.pem"),
		standardservercert.WithCertKeyURI("cert.key"),
	)
	require.NoError(t, err)
	return mgr
}

func TestBuildServerTLSConfig_WithCAPEM(t *testing.T) {
	mgr := newTestCertManager(t)

	cfg, err := buildServerTLSConfig(context.Background(), mgr, resources.CACrt)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	require.NotNil(t, cfg.ClientCAs)
}

func TestBuildServerTLSConfig_EmptyCAFallsBackToSystemRoots(t *testing.T) {
	mgr := newTestCertManager(t)

	cfg, err := buildServerTLSConfig(context.Background(), mgr, nil)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
	require.NotNil(t, cfg.ClientCAs, "expected ClientCAs to be populated from the system pool")
}
