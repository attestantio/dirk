// Copyright © 2020 - 2026 Attestant Limited.
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

package receiver_test

import (
	context "context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/dirk/core"
	mockrules "github.com/attestantio/dirk/rules/mock"
	mockaccountmanager "github.com/attestantio/dirk/services/accountmanager/mock"
	grpcapi "github.com/attestantio/dirk/services/api/grpc"
	"github.com/attestantio/dirk/services/checker"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	"github.com/attestantio/dirk/services/fetcher"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	standardlister "github.com/attestantio/dirk/services/lister/standard"
	"github.com/attestantio/dirk/services/locker"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/peers"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	"github.com/attestantio/dirk/services/process"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	"github.com/attestantio/dirk/services/ruler"
	goruler "github.com/attestantio/dirk/services/ruler/golang"
	"github.com/attestantio/dirk/services/sender"
	grpcsender "github.com/attestantio/dirk/services/sender/grpc"
	mocksender "github.com/attestantio/dirk/services/sender/mock"
	standardsigner "github.com/attestantio/dirk/services/signer/standard"
	"github.com/attestantio/dirk/services/unlocker"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	mockwalletmanager "github.com/attestantio/dirk/services/walletmanager/mock"
	"github.com/attestantio/dirk/testing/mock"
	"github.com/attestantio/dirk/testing/resources"
	"github.com/attestantio/dirk/util"
	standardclientcert "github.com/attestantio/go-certmanager/client/standard"
	standardservercert "github.com/attestantio/go-certmanager/server/standard"
	mockcertfetcher "github.com/attestantio/go-certmanager/testing/mock"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"github.com/wealdtech/go-majordomo"
)

func TestAbort(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx := context.Background()
	servers, err := createServers(t, ctx)
	require.NoError(t, err)
	// #nosec G404
	accountName := fmt.Sprintf("Test/%d", rand.Int())
	participants := servers.endpoints[0:3]

	senderSvc, err := createSender(ctx, servers.endpoints[0].Name, servers.base)
	require.NoError(t, err)

	require.Error(t, senderSvc.Abort(ctx, participants[0], accountName))
	require.NoError(t, senderSvc.Prepare(ctx, participants[0], accountName, []byte("test"), 2, participants))
	require.NoError(t, senderSvc.Abort(ctx, participants[0], accountName))
}

func TestAbortUnknownEndpoint(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx := context.Background()
	servers, err := createServers(t, ctx)
	require.NoError(t, err)
	// #nosec G404
	accountName := fmt.Sprintf("Test/%d", rand.Int())
	participants := servers.endpoints[0:3]

	senderSvc, err := createSender(ctx, servers.endpoints[0].Name, servers.base)
	require.NoError(t, err)

	require.NoError(t, senderSvc.Prepare(ctx, participants[0], accountName, []byte("test"), 2, participants))
	err = senderSvc.Abort(ctx, &core.Endpoint{ID: 11111, Name: "unknown", Port: 1111}, accountName)
	require.Error(t, err)
	require.True(t, strings.HasPrefix(err.Error(), "failed to call Abort(): rpc error: code = Unavailable"))
}

func TestEndToEnd(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx := context.Background()
	servers, err := createServers(t, ctx)
	require.NoError(t, err)
	// #nosec G404
	accountName := fmt.Sprintf("Test/%d", rand.Int())
	participants := servers.endpoints[0:3]

	senderSvc, err := createSender(ctx, servers.endpoints[0].Name, servers.base)
	require.NoError(t, err)

	for _, participant := range participants {
		require.NoError(t, senderSvc.Prepare(ctx, participant, accountName, []byte("test"), 2, participants))
	}

	for _, participant := range participants {
		require.NoError(t, senderSvc.Execute(ctx, participant, accountName))
	}

	pubKeys := make([][]byte, len(participants))
	confirmationSigs := make([][]byte, len(participants))
	confirmationData := make([]byte, 32)
	// #nosec G404
	n, err := rand.Read(confirmationData)
	require.NoError(t, err)
	require.Equal(t, 32, n)
	for i, participant := range participants {
		pubKeys[i], confirmationSigs[i], err = senderSvc.Commit(ctx, participant, accountName, confirmationData)
		require.NoError(t, err)
	}

	for i := range pubKeys {
		require.Equal(t, pubKeys[i], pubKeys[(i+1)%len(pubKeys)])
	}
}

// testServers bundles the per-test resources produced by createServers so
// individual tests do not have to thread unrelated values, and so the
// lifecycle of the package-global mock.Processes map can be tied to t.Cleanup
// rather than leaking between tests.
type testServers struct {
	base      string
	endpoints []*core.Endpoint
	services  []*grpcapi.Service
	processes map[uint64]process.Service
}

func createServers(t *testing.T, ctx context.Context) (*testServers, error) {
	t.Helper()

	base, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	if err := resources.SetupCerts(base); err != nil {
		return nil, err
	}

	rand.Seed(time.Now().UnixNano())
	endpoints := []*core.Endpoint{
		{
			ID:   1,
			Name: "signer-test01",
			// #nosec G404
			Port: uint32((rand.Int() % 8192) + 8192),
		},
		{
			ID:   2,
			Name: "signer-test02",
			// #nosec G404
			Port: uint32((rand.Int() % 8192) + 8192),
		},
		{
			ID:   3,
			Name: "signer-test03",
			// #nosec G404
			Port: uint32((rand.Int() % 8192) + 8192),
		},
		{
			ID:   4,
			Name: "signer-test04",
			// #nosec G404
			Port: uint32((rand.Int() % 8192) + 8192),
		},
		{
			ID:   5,
			Name: "signer-test05",
			// #nosec G404
			Port: uint32((rand.Int() % 8192) + 8192),
		},
	}

	peerAddresses := make(map[uint64]string, len(endpoints))
	for _, endpoint := range endpoints {
		peerAddresses[endpoint.ID] = net.JoinHostPort(endpoint.Name, fmt.Sprintf("%d", endpoint.Port))
	}

	servers := &testServers{
		base:      base,
		endpoints: endpoints,
		processes: make(map[uint64]process.Service),
	}

	// The mock sender resolves process services through this package-global.
	// Adopt the fixture's map so tests share a clean view, and tear it down
	// on test end so order-dependent state cannot leak into later tests.
	mock.Processes = servers.processes
	t.Cleanup(func() { mock.Processes = nil })

	for _, endpoint := range endpoints {
		grpcdService, processSvc, err := createServer(ctx, endpoint.Name, endpoint.ID, endpoint.Port, base, peerAddresses)
		if err != nil {
			return nil, err
		}
		servers.services = append(servers.services, grpcdService)
		servers.processes[endpoint.ID] = processSvc
	}

	return servers, nil
}

// createTestStoresAndWallet creates filesystem stores and a test wallet for the test server.
func createTestStoresAndWallet(ctx context.Context, majordomo majordomo.Service, base, name string) ([]e2wtypes.Store, error) {
	stores, err := core.InitStores(ctx, majordomo, []*core.Store{
		{
			Name:     "Local",
			Type:     "filesystem",
			Location: filepath.Join(base, fmt.Sprintf("%s-wallets", name)),
		},
	})
	if err != nil {
		return nil, err
	}
	testWallet, err := distributed.CreateWallet(ctx, "Test", stores[0], keystorev4.New())
	if err != nil {
		return nil, err
	}
	if err := testWallet.(e2wtypes.WalletLocker).Unlock(ctx, nil); err != nil {
		return nil, err
	}

	return stores, nil
}

// basicTestServices bundles the core test services to reduce argument lists.
type basicTestServices struct {
	unlocker unlocker.Service
	checker  checker.Service
	fetcher  fetcher.Service
	locker   locker.Service
	ruler    ruler.Service
}

// createBasicTestServices creates the basic services needed for testing.
func createBasicTestServices(ctx context.Context, stores []e2wtypes.Store) (*basicTestServices, error) {
	unlocker, err := localunlocker.New(ctx,
		localunlocker.WithAccountPassphrases([]string{}))
	if err != nil {
		return nil, err
	}

	checker, err := mockchecker.New(zerolog.Disabled)
	if err != nil {
		return nil, err
	}

	locker, err := syncmaplocker.New(ctx)
	if err != nil {
		return nil, err
	}

	fetcher, err := memfetcher.New(ctx,
		memfetcher.WithLogLevel(zerolog.Disabled),
		memfetcher.WithStores(stores))
	if err != nil {
		return nil, err
	}

	ruler, err := goruler.New(ctx,
		goruler.WithLogLevel(zerolog.Disabled),
		goruler.WithLocker(locker),
		goruler.WithRules(mockrules.New()))
	if err != nil {
		return nil, err
	}

	return &basicTestServices{
		unlocker: unlocker,
		checker:  checker,
		fetcher:  fetcher,
		locker:   locker,
		ruler:    ruler,
	}, nil
}

// createTestPeers creates static peers for testing.
func createTestPeers(ctx context.Context, peerAddresses map[uint64]string) (peers.Service, error) {
	return staticpeers.New(ctx,
		staticpeers.WithPeers(peerAddresses))
}

func createServer(ctx context.Context, name string, id uint64, port uint32, base string, peerAddresses map[uint64]string) (*grpcapi.Service, process.Service, error) {
	majordomo, err := util.InitMajordomo(ctx)
	if err != nil {
		return nil, nil, err
	}

	stores, err := createTestStoresAndWallet(ctx, majordomo, base, name)
	if err != nil {
		return nil, nil, err
	}

	basicSvcs, err := createBasicTestServices(ctx, stores)
	if err != nil {
		return nil, nil, err
	}

	lister, err := standardlister.New(ctx,
		standardlister.WithLogLevel(zerolog.Disabled),
		standardlister.WithFetcher(basicSvcs.fetcher),
		standardlister.WithChecker(basicSvcs.checker),
		standardlister.WithRuler(basicSvcs.ruler))
	if err != nil {
		return nil, nil, err
	}

	peers, err := createTestPeers(ctx, peerAddresses)
	if err != nil {
		return nil, nil, err
	}

	// Set up the signer.
	signer, err := standardsigner.New(ctx,
		standardsigner.WithLogLevel(zerolog.Disabled),
		standardsigner.WithUnlocker(basicSvcs.unlocker),
		standardsigner.WithChecker(basicSvcs.checker),
		standardsigner.WithFetcher(basicSvcs.fetcher),
		standardsigner.WithRuler(basicSvcs.ruler))
	if err != nil {
		return nil, nil, err
	}

	processSvc, err := standardprocess.New(ctx,
		standardprocess.WithChecker(basicSvcs.checker),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(id),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(mocksender.New(id)),
		standardprocess.WithFetcher(basicSvcs.fetcher),
		standardprocess.WithStores(stores),
		standardprocess.WithUnlocker(basicSvcs.unlocker),
	)
	if err != nil {
		return nil, nil, err
	}

	certPEMBlock, err := os.ReadFile(filepath.Join(base, fmt.Sprintf("%s.crt", name)))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain server certificate")
	}
	keyPEMBlock, err := os.ReadFile(filepath.Join(base, fmt.Sprintf("%s.key", name)))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain server key")
	}
	caPEMBlock, err := os.ReadFile(filepath.Join(base, "ca.crt"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain CA certificate")
	}

	// Create certificate manager for test.
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

	serverSvc, err := grpcapi.New(ctx,
		grpcapi.WithLister(lister),
		grpcapi.WithSigner(signer),
		grpcapi.WithName(name),
		grpcapi.WithCertManager(certManager),
		grpcapi.WithCACert(caPEMBlock),
		grpcapi.WithPeers(peers),
		grpcapi.WithID(id),
		grpcapi.WithProcess(processSvc),
		grpcapi.WithWalletManager(mockwalletmanager.New()),
		grpcapi.WithAccountManager(mockaccountmanager.New()),
		grpcapi.WithListenAddress(fmt.Sprintf("127.0.0.1:%d", port)),
	)
	if err != nil {
		return nil, nil, err
	}
	return serverSvc, processSvc, nil
}

func createSender(ctx context.Context, name string, base string) (sender.Service, error) {
	certPEMBlock, err := os.ReadFile(filepath.Join(base, fmt.Sprintf("%s.crt", name)))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server certificate")
	}
	keyPEMBlock, err := os.ReadFile(filepath.Join(base, fmt.Sprintf("%s.key", name)))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server key")
	}
	caPEMBlock, err := os.ReadFile(filepath.Join(base, "ca.crt"))
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain CA certificate")
	}

	senderCertFetcher := mockcertfetcher.NewMajordomo(map[string][]byte{
		"sender.cert": certPEMBlock,
		"sender.key":  keyPEMBlock,
		"ca.cert":     caPEMBlock,
	})
	senderCertManager, err := standardclientcert.New(ctx,
		standardclientcert.WithMajordomo(senderCertFetcher),
		standardclientcert.WithCertPEMURI("sender.cert"),
		standardclientcert.WithCertKeyURI("sender.key"),
		standardclientcert.WithCACertURI("ca.cert"),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create sender certificate manager")
	}

	return grpcsender.New(ctx,
		grpcsender.WithName(name),
		grpcsender.WithCertManager(senderCertManager),
	)
}
