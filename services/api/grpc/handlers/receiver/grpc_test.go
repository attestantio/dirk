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
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	mocklister "github.com/attestantio/dirk/services/lister/mock"
	standardlister "github.com/attestantio/dirk/services/lister/standard"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	goruler "github.com/attestantio/dirk/services/ruler/golang"
	"github.com/attestantio/dirk/services/sender"
	grpcsender "github.com/attestantio/dirk/services/sender/grpc"
	mocksender "github.com/attestantio/dirk/services/sender/mock"
	mocksigner "github.com/attestantio/dirk/services/signer/mock"
	standardsigner "github.com/attestantio/dirk/services/signer/standard"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	mockwalletmanager "github.com/attestantio/dirk/services/walletmanager/mock"
	"github.com/attestantio/dirk/testing/mock"
	"github.com/attestantio/dirk/testing/resources"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
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
	require.True(t, strings.HasPrefix(err.Error(), "Failed to call Abort(): rpc error: code = Unavailable"))
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

	servers := make(map[uint64]string)
	for _, endpoint := range endpoints {
		servers[endpoint.ID] = fmt.Sprintf("%s:%d", endpoint.Name, endpoint.Port)
	}

	grpcdServices := make([]*grpcapi.Service, 0)
	for _, endpoint := range endpoints {
		grpcdService, err := createServer(ctx, endpoint.Name, endpoint.ID, endpoint.Port, base)
		if err != nil {
			return "", nil, nil, err
		}
		grpcdServices = append(grpcdServices, grpcdService)
	}

	return base, endpoints, grpcdServices, nil
}

func createServer(ctx context.Context, name string, id uint64, port uint32, base string) (*grpcapi.Service, error) {
	unlocker, err := localunlocker.New(ctx,
		localunlocker.WithAccountPassphrases([]string{}))
	if err != nil {
		return nil, err
	}
	checker, err := mockchecker.New(zerolog.Disabled)
	if err != nil {
		return nil, err
	}
	stores, err := core.InitStores(ctx, []*core.Store{
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

	lister, err := standardlister.New(ctx,
		standardlister.WithLogLevel(zerolog.Disabled),
		standardlister.WithFetcher(fetcher),
		standardlister.WithChecker(checker),
		standardlister.WithRuler(ruler))
	if err != nil {
		return nil, err
	}

	peers, err := staticpeers.New(ctx,
		staticpeers.WithPeers(map[uint64]string{
			1: "signer-test01:8881",
			2: "signer-test02:8882",
			3: "signer-test03:8883",
		}))
	if err != nil {
		return nil, err
	}

	// Set up the signer.
	signer, err := standardsigner.New(ctx,
		standardsigner.WithLogLevel(zerolog.Disabled),
		standardsigner.WithUnlocker(unlocker),
		standardsigner.WithChecker(checker),
		standardsigner.WithFetcher(fetcher),
		standardsigner.WithRuler(ruler))
	if err != nil {
		return nil, err
	}

	process, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checker),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(id),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(mocksender.New(id)),
		standardprocess.WithFetcher(fetcher),
		standardprocess.WithStores(stores),
		standardprocess.WithUnlocker(unlocker),
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

	serverSvc, err := grpcapi.New(ctx,
		grpcapi.WithLister(lister),
		grpcapi.WithSigner(signer),
		grpcapi.WithName(name),
		grpcapi.WithServerCert(certPEMBlock),
		grpcapi.WithServerKey(keyPEMBlock),
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

	return grpcsender.New(ctx,
		grpcsender.WithName(name),
		grpcsender.WithServerCert(certPEMBlock),
		grpcsender.WithServerKey(keyPEMBlock),
		grpcsender.WithCACert(caPEMBlock),
	)
}
