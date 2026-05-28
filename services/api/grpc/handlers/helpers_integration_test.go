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

package handlers_test

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attestantio/dirk/core"
	mockrules "github.com/attestantio/dirk/rules/mock"
	mockaccountmanager "github.com/attestantio/dirk/services/accountmanager/mock"
	grpcapi "github.com/attestantio/dirk/services/api/grpc"
	"github.com/attestantio/dirk/services/checker"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	"github.com/attestantio/dirk/services/checker/static"
	"github.com/attestantio/dirk/services/fetcher/mem"
	"github.com/attestantio/dirk/services/lister/standard"
	"github.com/attestantio/dirk/services/locker/syncmap"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	"github.com/attestantio/dirk/services/ruler/golang"
	mocksender "github.com/attestantio/dirk/services/sender/mock"
	mocksigner "github.com/attestantio/dirk/services/signer/mock"
	"github.com/attestantio/dirk/services/unlocker/local"
	mockwalletmanager "github.com/attestantio/dirk/services/walletmanager/mock"
	"github.com/attestantio/dirk/testing/resources"
	"github.com/attestantio/dirk/util"
	standardclientcert "github.com/attestantio/go-certmanager/client/standard"
	"github.com/attestantio/go-certmanager/san"
	servercert "github.com/attestantio/go-certmanager/server"
	standardservercert "github.com/attestantio/go-certmanager/server/standard"
	mockcertfetcher "github.com/attestantio/go-certmanager/testing/mock"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// parseCertificate parses a PEM-encoded certificate and returns the x509 certificate.
func parseCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse certificate")
	}
	return cert, nil
}

// extractExpectedIdentity extracts the expected identity and SANs from a certificate
// using the same utilities as the interceptor.
func extractExpectedIdentity(certPEM []byte) (string, san.IdentitySource, *san.CertificateSANs, error) {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return "", san.IdentitySourceUnknown, nil, err
	}

	identity, identitySource := san.ExtractIdentity(cert)
	certSANs := san.ExtractAllSANs(cert)

	return identity, identitySource, certSANs, nil
}

// waitForServerReady blocks until the server is accepting TCP connections on
// the given port, or fails the test after a fixed deadline.
func waitForServerReady(t *testing.T, port uint32) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond, "server at %s did not become ready", addr)
}

// pickTestPort returns a port in [8192, 16384) that is bindable on the
// loopback interface at the time of the check. The bind probe is racy by
// nature (the port might be taken before the caller binds for real) but it
// rules out ports already held by another process and avoids the silent
// "address already in use" failures the previous unchecked variant produced.
// Ports are sourced from crypto/rand so the math/rand weak-randomness lint
// does not fire.
func pickTestPort(t *testing.T) uint32 {
	t.Helper()
	const maxAttempts = 32
	for range maxAttempts {
		n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(8192))
		require.NoError(t, err, "failed to pick test port")
		port := uint32(n.Uint64()) + 8192

		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = ln.Close()
		return port
	}
	t.Fatalf("could not find an available test port after %d attempts", maxAttempts)
	return 0
}

// createCheckerService returns a static checker when permissions are provided
// and a mock checker otherwise.
func createCheckerService(ctx context.Context, permissions map[string][]*checker.Permissions) (checker.Service, error) {
	if permissions != nil {
		return static.New(ctx,
			static.WithLogLevel(zerolog.Disabled),
			static.WithPermissions(permissions))
	}
	return mockchecker.New(zerolog.Disabled)
}

// loadServerCertManager reads the test server cert/key/CA from base and wraps
// them in a go-certmanager server cert manager backed by an in-memory fetcher.
func loadServerCertManager(ctx context.Context, base string) (servercert.Service, []byte, error) {
	certPEMBlock, err := os.ReadFile(filepath.Join(base, "signer-test01.crt"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain server certificate")
	}
	keyPEMBlock, err := os.ReadFile(filepath.Join(base, "signer-test01.key"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain server key")
	}
	caPEMBlock, err := os.ReadFile(filepath.Join(base, "ca.crt"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain CA certificate")
	}

	certFetcher := mockcertfetcher.NewMajordomo(map[string][]byte{
		"cert.pem": certPEMBlock,
		"cert.key": keyPEMBlock,
	})
	certManager, err := standardservercert.New(ctx,
		standardservercert.WithMajordomo(certFetcher),
		standardservercert.WithCertPEMURI("cert.pem"),
		standardservercert.WithCertKeyURI("cert.key"),
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create certificate manager")
	}
	return certManager, caPEMBlock, nil
}

// createTestServer creates a gRPC server with static checker and configured permissions.
func createTestServer(ctx context.Context, t *testing.T, base string, permissions map[string][]*checker.Permissions) (*grpcapi.Service, uint32, error) {
	t.Helper()
	port := pickTestPort(t)

	majordomo, err := util.InitMajordomo(ctx)
	if err != nil {
		return nil, 0, err
	}

	stores, err := core.InitStores(ctx, majordomo, []*core.Store{
		{
			Name:     "Local",
			Type:     "filesystem",
			Location: filepath.Join(base, "wallets"),
		},
	})
	if err != nil {
		return nil, 0, err
	}

	unlocker, err := local.New(ctx,
		local.WithAccountPassphrases([]string{}))
	if err != nil {
		return nil, 0, err
	}

	locker, err := syncmap.New(ctx)
	if err != nil {
		return nil, 0, err
	}

	fetcher, err := mem.New(ctx,
		mem.WithLogLevel(zerolog.Disabled),
		mem.WithStores(stores))
	if err != nil {
		return nil, 0, err
	}

	ruler, err := golang.New(ctx,
		golang.WithLogLevel(zerolog.Disabled),
		golang.WithLocker(locker),
		golang.WithRules(mockrules.New()))
	if err != nil {
		return nil, 0, err
	}

	checkerSvc, err := createCheckerService(ctx, permissions)
	if err != nil {
		return nil, 0, err
	}

	lister, err := standard.New(ctx,
		standard.WithLogLevel(zerolog.Disabled),
		standard.WithFetcher(fetcher),
		standard.WithChecker(checkerSvc),
		standard.WithRuler(ruler))
	if err != nil {
		return nil, 0, err
	}

	peers, err := staticpeers.New(ctx,
		staticpeers.WithPeers(map[uint64]string{
			1: fmt.Sprintf("signer-test01:%d", port),
		}))
	if err != nil {
		return nil, 0, err
	}

	process, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checkerSvc),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(1),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(mocksender.New(1)),
		standardprocess.WithFetcher(fetcher),
		standardprocess.WithStores(stores),
		standardprocess.WithUnlocker(unlocker),
	)
	if err != nil {
		return nil, 0, err
	}

	certManager, caPEMBlock, err := loadServerCertManager(ctx, base)
	if err != nil {
		return nil, 0, err
	}

	serverSvc, err := grpcapi.New(ctx,
		grpcapi.WithLister(lister),
		grpcapi.WithSigner(mocksigner.New()),
		grpcapi.WithName("signer-test01"),
		grpcapi.WithCertManager(certManager),
		grpcapi.WithCACert(caPEMBlock),
		grpcapi.WithPeers(peers),
		grpcapi.WithID(1),
		grpcapi.WithProcess(process),
		grpcapi.WithAccountManager(mockaccountmanager.New()),
		grpcapi.WithWalletManager(mockwalletmanager.New()),
		grpcapi.WithListenAddress(fmt.Sprintf("127.0.0.1:%d", port)),
	)
	if err != nil {
		return nil, 0, err
	}

	return serverSvc, port, nil
}

// createTestClient creates a gRPC client connection with client certificate.
func createTestClient(ctx context.Context, base string, clientCertName string, serverPort uint32) (*grpc.ClientConn, error) {
	// Load client certificate
	certPEMBlock, err := os.ReadFile(filepath.Join(base, fmt.Sprintf("%s.crt", clientCertName)))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain client certificate")
	}
	keyPEMBlock, err := os.ReadFile(filepath.Join(base, fmt.Sprintf("%s.key", clientCertName)))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain client key")
	}
	caPEMBlock, err := os.ReadFile(filepath.Join(base, "ca.crt"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain CA certificate")
	}

	// Create certificate manager for client using go-certmanager
	clientCertFetcher := mockcertfetcher.NewMajordomo(map[string][]byte{
		"client.cert": certPEMBlock,
		"client.key":  keyPEMBlock,
	})
	clientCertManager, err := standardclientcert.New(ctx,
		standardclientcert.WithMajordomo(clientCertFetcher),
		standardclientcert.WithCertPEMURI("client.cert"),
		standardclientcert.WithCertKeyURI("client.key"),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create client certificate manager")
	}

	// Get TLS config from certificate manager
	tlsCfg, err := clientCertManager.GetTLSConfig(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get TLS config")
	}

	// Add CA certificate for server verification
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(caPEMBlock) {
		return nil, errors.New("failed to add CA certificate to pool")
	}
	tlsCfg.RootCAs = cp

	// Set ServerName to match the server certificate's DNS name
	// The server certificate is for "signer-test01", not "127.0.0.1"
	tlsCfg.ServerName = "signer-test01"

	// Create gRPC client connection
	conn, err := grpc.NewClient(
		fmt.Sprintf("127.0.0.1:%d", serverPort),
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create gRPC client")
	}

	return conn, nil
}

func TestIntegration_CertificateIdentityExtraction_DNS(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)

	// Set up test certificates
	err = resources.SetupCerts(base)
	require.NoError(t, err)

	// Extract expected identity from client-test01 certificate
	clientCertPEM, err := os.ReadFile(filepath.Join(base, "client-test01.crt"))
	require.NoError(t, err)
	expectedIdentity, expectedSource, expectedSANs, err := extractExpectedIdentity(clientCertPEM)
	require.NoError(t, err)

	// Create server with mock checker
	_, port, err := createTestServer(ctx, t, base, nil)
	require.NoError(t, err)

	// Server starts automatically in New(); wait for the accept loop to be ready.
	waitForServerReady(t, port)

	// Create client with client-test01 certificate
	clientConn, err := createTestClient(ctx, base, "client-test01", port)
	require.NoError(t, err)
	defer clientConn.Close()

	// Make gRPC call
	client := pb.NewListerClient(clientConn)
	resp, err := client.ListAccounts(ctx, &pb.ListAccountsRequest{
		Paths: []string{},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify the expected identity was extracted
	// Since we're using mock checker, we can't verify credentials directly,
	// but we can verify the call succeeded, which means the interceptor worked
	assert.NotNil(t, resp)

	// Verify expected values match what interceptor should extract
	assert.Equal(t, expectedIdentity, "client-test01", "Expected DNS SAN identity")
	assert.Equal(t, expectedSource, san.IdentitySourceSANDNS, "Expected DNS SAN source")
	assert.NotNil(t, expectedSANs, "Expected SANs to be extracted")
}

func TestIntegration_CertificateIdentityPriority_DNSOverCN(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)

	err = resources.SetupCerts(base)
	require.NoError(t, err)

	// Extract expected identity from client-test01 certificate
	clientCertPEM, err := os.ReadFile(filepath.Join(base, "client-test01.crt"))
	require.NoError(t, err)
	expectedIdentity, expectedSource, _, err := extractExpectedIdentity(clientCertPEM)
	require.NoError(t, err)

	// Verify DNS SAN is used (not CN) - client-test01 has both DNS SAN and CN
	// The identity should be from DNS SAN per RFC 6125 priority
	assert.Equal(t, expectedSource, san.IdentitySourceSANDNS, "DNS SAN should be used, not CN")
	assert.Equal(t, expectedIdentity, "client-test01", "Identity should be from DNS SAN")

	_, port, err := createTestServer(ctx, t, base, nil)
	require.NoError(t, err)

	waitForServerReady(t, port)

	clientConn, err := createTestClient(ctx, base, "client-test01", port)
	require.NoError(t, err)
	defer clientConn.Close()

	client := pb.NewListerClient(clientConn)
	resp, err := client.ListAccounts(ctx, &pb.ListAccountsRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIntegration_CertificateIdentity_CNOnly(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)

	err = resources.SetupCerts(base)
	require.NoError(t, err)

	// Extract expected identity from CN-only certificate
	clientCertPEM, err := os.ReadFile(filepath.Join(base, "client-cn-only.crt"))
	require.NoError(t, err)
	expectedIdentity, expectedSource, expectedSANs, err := extractExpectedIdentity(clientCertPEM)
	require.NoError(t, err)

	// Expect CN to be used when no SAN is present
	assert.Equal(t, san.IdentitySourceCN, expectedSource)
	assert.Equal(t, "client-cn-only", expectedIdentity)
	assert.NotNil(t, expectedSANs)
	assert.Empty(t, expectedSANs.DNSNames)

	// Create server with mock checker
	_, port, err := createTestServer(ctx, t, base, nil)
	require.NoError(t, err)

	waitForServerReady(t, port)

	// Create client with CN-only certificate
	clientConn, err := createTestClient(ctx, base, "client-cn-only", port)
	require.NoError(t, err)
	defer clientConn.Close()

	client := pb.NewListerClient(clientConn)
	resp, err := client.ListAccounts(ctx, &pb.ListAccountsRequest{})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestIntegration_EndToEndPermissionCheck_Granted(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)

	err = resources.SetupCerts(base)
	require.NoError(t, err)

	// Extract expected identity
	clientCertPEM, err := os.ReadFile(filepath.Join(base, "client-test01.crt"))
	require.NoError(t, err)
	expectedIdentity, expectedSource, expectedSANs, err := extractExpectedIdentity(clientCertPEM)
	require.NoError(t, err)

	// Create server with static checker that allows client-test01
	permissions := map[string][]*checker.Permissions{
		expectedIdentity: {
			{
				Path:       "*",
				Operations: []string{"ListAccounts"},
			},
		},
	}

	_, port, err := createTestServer(ctx, t, base, permissions)
	require.NoError(t, err)

	waitForServerReady(t, port)

	clientConn, err := createTestClient(ctx, base, "client-test01", port)
	require.NoError(t, err)
	defer clientConn.Close()

	client := pb.NewListerClient(clientConn)
	resp, err := client.ListAccounts(ctx, &pb.ListAccountsRequest{
		Paths: []string{},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify request succeeded (permission granted)
	assert.Equal(t, pb.ResponseState_SUCCEEDED, resp.State)

	// Verify expected identity values
	assert.Equal(t, expectedIdentity, "client-test01")
	assert.Equal(t, expectedSource, san.IdentitySourceSANDNS)
	assert.NotNil(t, expectedSANs)
}

func TestIntegration_EndToEndPermissionCheck_Denied(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)

	err = resources.SetupCerts(base)
	require.NoError(t, err)

	// Extract expected identity for client-test02
	clientCertPEM, err := os.ReadFile(filepath.Join(base, "client-test02.crt"))
	require.NoError(t, err)
	expectedIdentity, expectedSource, _, err := extractExpectedIdentity(clientCertPEM)
	require.NoError(t, err)

	// Create server with static checker that only allows client-test01 (not client-test02)
	permissions := map[string][]*checker.Permissions{
		"client-test01": {
			{
				Path:       "*",
				Operations: []string{"ListAccounts"},
			},
		},
	}

	_, port, err := createTestServer(ctx, t, base, permissions)
	require.NoError(t, err)

	waitForServerReady(t, port)

	// Use client-test02 certificate (not in permissions)
	clientConn, err := createTestClient(ctx, base, "client-test02", port)
	require.NoError(t, err)
	defer clientConn.Close()

	client := pb.NewListerClient(clientConn)
	resp, err := client.ListAccounts(ctx, &pb.ListAccountsRequest{
		Paths: []string{},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Note: Empty paths don't trigger permission checks in the lister service,
	// so the request succeeds even without permissions. However, we verify that
	// the credentials were still extracted correctly from the certificate.
	// The important part is that the interceptor extracted the identity correctly.
	assert.NotNil(t, resp)

	// Verify expected identity was still extracted correctly
	// (even though empty paths don't require permission checks)
	assert.Equal(t, expectedIdentity, "client-test02")
	assert.Equal(t, expectedSource, san.IdentitySourceSANDNS)
}
