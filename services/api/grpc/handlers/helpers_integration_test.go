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
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	nd "github.com/wealdtech/go-eth2-wallet-nd/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	testWalletName  = "TestWallet"
	testAccountName = "account1"
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

// createCheckerService returns a static checker initialised with the provided
// permission map. Integration tests always use the static checker so the
// observable response of each test reflects what the server-side interceptor
// extracted (the identity drives whether the configured permissions match).
func createCheckerService(ctx context.Context, permissions map[string][]*checker.Permissions) (checker.Service, error) {
	return static.New(ctx,
		static.WithLogLevel(zerolog.Disabled),
		static.WithPermissions(permissions))
}

// seedTestWallet creates a wallet named testWalletName with one account
// testAccountName in the provided store. The lister returns this account when
// the request's path includes testWalletName and the server-extracted identity
// is authorised for that path, giving each integration test a deterministic
// allow/deny signal driven by the interceptor's output.
func seedTestWallet(ctx context.Context, store e2wtypes.Store) error {
	if err := e2types.InitBLS(); err != nil {
		return errors.Wrap(err, "failed to initialise BLS")
	}
	wallet, err := nd.CreateWallet(ctx, testWalletName, store, keystorev4.New())
	if err != nil {
		return errors.Wrap(err, "failed to create test wallet")
	}
	if err := wallet.(e2wtypes.WalletLocker).Unlock(ctx, nil); err != nil {
		return errors.Wrap(err, "failed to unlock test wallet")
	}
	if _, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(ctx, testAccountName, []byte("pass")); err != nil {
		return errors.Wrap(err, "failed to create test account")
	}
	return wallet.(e2wtypes.WalletLocker).Lock(ctx)
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

	// Seed a wallet with one account so the lister has something concrete to
	// return when permissions match; the test asserts on the listed accounts
	// to confirm the server-side interceptor populated the credentials with
	// the expected identity.
	if err := seedTestWallet(ctx, stores[0]); err != nil {
		return nil, 0, err
	}

	unlocker, err := local.New(ctx,
		local.WithAccountPassphrases([]string{"pass"}))
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

// integrationEnv is the per-test environment for an interceptor integration
// test: a temp base directory with certificates set up and a context that
// cancels at the end of the test.
type integrationEnv struct {
	ctx  context.Context
	base string
}

func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	require.NoError(t, resources.SetupCerts(base))

	return &integrationEnv{ctx: t.Context(), base: base}
}

// runListerCall starts a server with the provided permissions, connects with
// the given client certificate name, and issues a ListAccounts call for the
// seeded test wallet. The returned response reflects what the server-side
// interceptor extracted: if its identity matches a permission entry, the
// seeded account is listed; otherwise the response carries zero accounts.
func runListerCall(t *testing.T, env *integrationEnv, permissions map[string][]*checker.Permissions, clientCertName string) *pb.ListAccountsResponse {
	t.Helper()
	_, port, err := createTestServer(env.ctx, t, env.base, permissions)
	require.NoError(t, err)
	waitForServerReady(t, port)

	clientConn, err := createTestClient(env.ctx, env.base, clientCertName, port)
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientConn.Close() })

	client := pb.NewListerClient(clientConn)
	resp, err := client.ListAccounts(env.ctx, &pb.ListAccountsRequest{
		Paths: []string{testWalletName},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	return resp
}

// permissionsFor returns a static permission map that grants the given
// identity full access to the seeded test wallet.
func permissionsFor(identity string) map[string][]*checker.Permissions {
	return map[string][]*checker.Permissions{
		identity: {
			{
				Path:       testWalletName,
				Operations: []string{"All"},
			},
		},
	}
}

func TestIntegration_CertificateIdentityExtraction_DNS(t *testing.T) {
	env := newIntegrationEnv(t)

	clientCertPEM, err := os.ReadFile(filepath.Join(env.base, "client-test01.crt"))
	require.NoError(t, err)
	expectedIdentity, expectedSource, expectedSANs, err := extractExpectedIdentity(clientCertPEM)
	require.NoError(t, err)
	require.Equal(t, "client-test01", expectedIdentity, "Expected DNS SAN identity")
	require.Equal(t, san.IdentitySourceSANDNS, expectedSource, "Expected DNS SAN source")
	require.NotNil(t, expectedSANs)

	// Grant the DNS-SAN identity full access. If the server interceptor
	// populated credentials.Client with anything other than the DNS SAN, no
	// permission would match and the listing would come back empty.
	resp := runListerCall(t, env, permissionsFor(expectedIdentity), "client-test01")
	assert.Equal(t, pb.ResponseState_SUCCEEDED, resp.GetState())
	assert.Len(t, resp.GetAccounts(), 1, "server interceptor should have extracted the DNS-SAN identity, allowing the lister to return the seeded account")
}

func TestIntegration_CertificateIdentityPriority_DNSOverCN(t *testing.T) {
	env := newIntegrationEnv(t)

	clientCertPEM, err := os.ReadFile(filepath.Join(env.base, "client-test01.crt"))
	require.NoError(t, err)
	expectedIdentity, expectedSource, _, err := extractExpectedIdentity(clientCertPEM)
	require.NoError(t, err)
	require.Equal(t, san.IdentitySourceSANDNS, expectedSource, "DNS SAN should be used, not CN")
	require.Equal(t, "client-test01", expectedIdentity, "Identity should be from DNS SAN")

	// The bundled client-test01 fixture has the same string for both CN and
	// DNS SAN, so the only black-box check available here is that permissions
	// keyed on a value that exists in *neither* CN nor SAN are not honoured.
	// A future fixture with distinct CN/SAN values would let this assert the
	// DNS-over-CN priority more strongly.
	resp := runListerCall(t, env, permissionsFor("definitely-not-this-client"), "client-test01")
	assert.Equal(t, pb.ResponseState_SUCCEEDED, resp.GetState())
	assert.Empty(t, resp.GetAccounts(), "interceptor must not invent an identity that isn't in the cert")
}

func TestIntegration_CertificateIdentity_CNOnly(t *testing.T) {
	env := newIntegrationEnv(t)

	clientCertPEM, err := os.ReadFile(filepath.Join(env.base, "client-cn-only.crt"))
	require.NoError(t, err)
	expectedIdentity, expectedSource, expectedSANs, err := extractExpectedIdentity(clientCertPEM)
	require.NoError(t, err)
	require.Equal(t, san.IdentitySourceCN, expectedSource)
	require.Equal(t, "client-cn-only", expectedIdentity)
	require.NotNil(t, expectedSANs)
	require.Empty(t, expectedSANs.DNSNames)

	// Grant the CN-only identity. The interceptor's CN fallback must apply
	// for this listing to return the seeded account.
	resp := runListerCall(t, env, permissionsFor(expectedIdentity), "client-cn-only")
	assert.Equal(t, pb.ResponseState_SUCCEEDED, resp.GetState())
	assert.Len(t, resp.GetAccounts(), 1, "interceptor should fall back to CN when the certificate has no DNS SANs")
}

func TestIntegration_EndToEndPermissionCheck_Granted(t *testing.T) {
	env := newIntegrationEnv(t)

	resp := runListerCall(t, env, permissionsFor("client-test01"), "client-test01")
	assert.Equal(t, pb.ResponseState_SUCCEEDED, resp.GetState())
	assert.Len(t, resp.GetAccounts(), 1, "client-test01 has a matching permission entry; seeded account should be listed")
}

func TestIntegration_EndToEndPermissionCheck_Denied(t *testing.T) {
	env := newIntegrationEnv(t)

	// Permissions grant client-test01, but the client connects as
	// client-test02. The interceptor must extract client-test02, the static
	// checker must find no matching rules, and the lister must filter the
	// seeded account out of the response.
	resp := runListerCall(t, env, permissionsFor("client-test01"), "client-test02")
	assert.Equal(t, pb.ResponseState_SUCCEEDED, resp.GetState())
	assert.Empty(t, resp.GetAccounts(), "client-test02 has no permission entry; seeded account must not be listed")
}
