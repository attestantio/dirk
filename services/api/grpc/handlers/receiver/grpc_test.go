// Copyright © 2020, 2022 Attestant Limited.
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
	mocklister "github.com/attestantio/dirk/services/lister/mock"
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
	mocksigner "github.com/attestantio/dirk/services/signer/mock"
	standardsigner "github.com/attestantio/dirk/services/signer/standard"
	"github.com/attestantio/dirk/services/unlocker"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	mockwalletmanager "github.com/attestantio/dirk/services/walletmanager/mock"
	"github.com/attestantio/dirk/testing/mock"
	"github.com/attestantio/dirk/testing/resources"
	"github.com/attestantio/dirk/util"
	majordomofetcher "github.com/attestantio/go-certmanager/fetcher/majordomo"
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
	base, endpoints, _, err := createServers(ctx)
	require.NoError(t, err)
	defer os.RemoveAll(base)
	// #nosec G404
	accountName := fmt.Sprintf("Test/%d", rand.Int())
	participants := endpoints[0:3]

	senderSvc, err := createSender(ctx, endpoints[0].Name, base)
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
	base, endpoints, _, err := createServers(ctx)
	require.NoError(t, err)
	defer os.RemoveAll(base)
	// #nosec G404
	accountName := fmt.Sprintf("Test/%d", rand.Int())
	participants := endpoints[0:3]

	senderSvc, err := createSender(ctx, endpoints[0].Name, base)
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
	base, endpoints, _, err := createServers(ctx)
	require.NoError(t, err)
	defer os.RemoveAll(base)
	// #nosec G404
	accountName := fmt.Sprintf("Test/%d", rand.Int())
	participants := endpoints[0:3]

	senderSvc, err := createSender(ctx, endpoints[0].Name, base)
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

func createServers(ctx context.Context) (string, []*core.Endpoint, []*grpcapi.Service, error) {
	// initialise mock.Processes map
	mock.Processes = make(map[uint64]process.Service)

	base, err := os.MkdirTemp("", "")
	if err != nil {
		return "", nil, nil, err
	}

	if err := resources.SetupCerts(base); err != nil {
		return "", nil, nil, err
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

	grpcdServices := make([]*grpcapi.Service, 0)
	for _, endpoint := range endpoints {
		grpcdService, err := createServer(ctx, endpoint.Name, endpoint.ID, endpoint.Port, base, peerAddresses)
		if err != nil {
			return "", nil, nil, err
		}
		grpcdServices = append(grpcdServices, grpcdService)
	}

	return base, endpoints, grpcdServices, nil
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

// createTestCertManager creates a certificate manager for testing.
func createTestCertManager(ctx context.Context, majordomo majordomo.Service, base, name string) (*standardservercert.Service, []byte, error) {
	certPEMURI := "file://" + filepath.Join(base, fmt.Sprintf("%s.crt", name))
	certKeyURI := "file://" + filepath.Join(base, fmt.Sprintf("%s.key", name))

	fetcher, err := majordomofetcher.New(ctx,
		majordomofetcher.WithMajordomo(majordomo),
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create majordomo fetcher")
	}

	certManager, err := standardservercert.New(ctx,
		standardservercert.WithLogLevel(zerolog.Disabled),
		standardservercert.WithFetcher(fetcher),
		standardservercert.WithCertPEMURI(certPEMURI),
		standardservercert.WithCertKeyURI(certKeyURI),
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to create cert manager")
	}

	caPEMBlock, err := os.ReadFile(filepath.Join(base, "ca.crt"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to obtain CA certificate")
	}

	return certManager, caPEMBlock, nil
}

func createServer(ctx context.Context, name string, id uint64, port uint32, base string, peerAddresses map[uint64]string) (*grpcapi.Service, error) {
	majordomo, err := util.InitMajordomo(ctx)
	if err != nil {
		return nil, err
	}

	stores, err := createTestStoresAndWallet(ctx, majordomo, base, name)
	if err != nil {
		return nil, err
	}

	basicSvcs, err := createBasicTestServices(ctx, stores)
	if err != nil {
		return nil, err
	}

	lister, err := standardlister.New(ctx,
		standardlister.WithLogLevel(zerolog.Disabled),
		standardlister.WithFetcher(basicSvcs.fetcher),
		standardlister.WithChecker(basicSvcs.checker),
		standardlister.WithRuler(basicSvcs.ruler))
	if err != nil {
		return nil, err
	}

	peers, err := createTestPeers(ctx, peerAddresses)
	if err != nil {
		return nil, err
	}

	// Set up the signer.
	signer, err := standardsigner.New(ctx,
		standardsigner.WithLogLevel(zerolog.Disabled),
		standardsigner.WithUnlocker(basicSvcs.unlocker),
		standardsigner.WithChecker(basicSvcs.checker),
		standardsigner.WithFetcher(basicSvcs.fetcher),
		standardsigner.WithRuler(basicSvcs.ruler))
	if err != nil {
		return nil, err
	}

	process, err := standardprocess.New(ctx,
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
		return nil, err
	}
	mock.Processes[id] = process

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

	// Create certificate manager for test.
	certFetcher := mockcertfetcher.NewFetcher(map[string][]byte{
		"cert.pem": certPEMBlock,
		"cert.key": keyPEMBlock,
	})
	certManager, err := standardservercert.New(ctx,
		standardservercert.WithFetcher(certFetcher),
		standardservercert.WithCertPEMURI("cert.pem"),
		standardservercert.WithCertKeyURI("cert.key"),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create certificate manager")
	}

	serverSvc, err := grpcapi.New(ctx,
		grpcapi.WithLister(lister),
		grpcapi.WithSigner(signer),
		grpcapi.WithName(name),
		grpcapi.WithCertManager(certManager),
		grpcapi.WithCACert(caPEMBlock),
		grpcapi.WithPeers(peers),
		grpcapi.WithID(id),
		grpcapi.WithProcess(process),
		grpcapi.WithWalletManager(mockwalletmanager.New()),
		grpcapi.WithAccountManager(mockaccountmanager.New()),
		grpcapi.WithSigner(mocksigner.New()),
		grpcapi.WithLister(mocklister.New()),
		grpcapi.WithListenAddress(fmt.Sprintf("127.0.0.1:%d", port)),
	)
	if err != nil {
		return nil, err
	}
	return serverSvc, nil
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

	senderCertFetcher := mockcertfetcher.NewFetcher(map[string][]byte{
		"sender.cert": certPEMBlock,
		"sender.key":  keyPEMBlock,
	})
	senderCertManager, err := standardservercert.New(ctx,
		standardservercert.WithFetcher(senderCertFetcher),
		standardservercert.WithCertPEMURI("sender.cert"),
		standardservercert.WithCertKeyURI("sender.key"),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create sender certificate manager")
	}

	return grpcsender.New(ctx,
		grpcsender.WithName(name),
		grpcsender.WithCertManager(senderCertManager),
		grpcsender.WithCACert(caPEMBlock),
	)
}
