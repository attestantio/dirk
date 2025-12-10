// Copyright © 2020, 2021 Attestant Limited.
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

package daemon_test

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/attestantio/dirk/services/certmanager"
	"github.com/attestantio/dirk/testing/daemon"
	"github.com/attestantio/dirk/testing/resources"
	"github.com/stretchr/testify/require"
)

func TestDaemon(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	// Set up certificates
	certPath := t.TempDir()
	err = resources.SetupCerts(certPath)
	require.NoError(t, err)

	ctx := context.Background()
	// #nosec G404
	port := uint32(12000 + rand.Intn(4000))
	_, path, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("signer-test01:%d", port)})
	require.NoError(t, err)
	os.RemoveAll(path)
}

func TestCancelDaemon(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	// Set up certificates
	certPath := t.TempDir()
	err = resources.SetupCerts(certPath)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	// #nosec G404
	port := uint32(12000 + rand.Intn(4000))
	_, path, _, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("signer-test01:%d", port)})
	require.NoError(t, err)
	defer os.RemoveAll(path)
	require.True(t, endpointAlive(fmt.Sprintf("signer-test01:%d", port)))
	cancel()
	// Sleep for a second to allow graceful stop of the daemon.
	time.Sleep(time.Second)
	require.False(t, endpointAlive(fmt.Sprintf("signer-test01:%d", port)))
}

func TestCertReload(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx := context.Background()

	// Set up certificates
	certPath := t.TempDir()
	err = resources.SetupCerts(certPath)
	require.NoError(t, err)

	port := uint32(12000 + rand.Intn(4000))
	logCapture, path, services, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("signer-test01:%d", port)})
	require.NoError(t, err)
	defer os.RemoveAll(path)

	for _, svc := range services {
		if certManager, ok := svc.(certmanager.Service); ok {
			require.NotNil(t, certManager)

			// Get initial certificate via GetCertificate
			cert1, err := certManager.GetCertificate(nil)
			require.NoError(t, err)
			require.NotNil(t, cert1)
			require.NotEmpty(t, cert1.Certificate)

			// Replace the certificate file on disk with a different one (use signer-test02's cert)
			originalCertPath := resources.CertPaths[1]
			originalKeyPath := resources.KeyPaths[1]

			// Back up original cert data
			originalCertData, err := os.ReadFile(originalCertPath)
			require.NoError(t, err)
			originalKeyData, err := os.ReadFile(originalKeyPath)
			require.NoError(t, err)
			defer func() {
				// Restore original certificates
				os.WriteFile(originalCertPath, originalCertData, 0600)
				os.WriteFile(originalKeyPath, originalKeyData, 0600)
			}()

			// Write new certificate (from signer-test02)
			err = os.WriteFile(originalCertPath, resources.SignerCerts[2], 0600)
			require.NoError(t, err)
			err = os.WriteFile(originalKeyPath, resources.SignerKeys[2], 0600)
			require.NoError(t, err)

			// Trigger reload
			certManager.TryReloadCertificate()
			logCapture.AssertHasEntry(t, "Server certificate reloaded successfully")
			require.True(t, endpointAlive(fmt.Sprintf("signer-test01:%d", port)))

			// Get new certificate and verify it changed
			cert2, err := certManager.GetCertificate(nil)
			require.NoError(t, err)
			require.NotNil(t, cert2)
			require.NotEmpty(t, cert2.Certificate)

			// Verify the certificates are different by comparing raw bytes
			require.NotEqual(t, cert1.Certificate[0], cert2.Certificate[0], "Certificate should have changed after reload")

			return
		}
	}
	require.Fail(t, "cert manager not found")
}
func endpointAlive(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}
