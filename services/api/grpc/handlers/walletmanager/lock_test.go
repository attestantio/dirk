// Copyright © 2020 Attestant Limited.
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

package walletmanager_test

import (
	context "context"
	"os"
	"testing"

	mockrules "github.com/attestantio/dirk/rules/mock"
	"github.com/attestantio/dirk/services/api/grpc/handlers/walletmanager"
	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	"github.com/attestantio/dirk/services/ruler/golang"
	mocksender "github.com/attestantio/dirk/services/sender/mock"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	standardwalletmanager "github.com/attestantio/dirk/services/walletmanager/standard"
	"github.com/attestantio/dirk/testing/accounts"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestMain(m *testing.M) {
	if err := e2types.InitBLS(); err != nil {
		os.Exit(1)
	}
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func TestLock(t *testing.T) {
	tests := []struct {
		name   string
		client string
		req    *pb.LockWalletRequest
		err    string
		state  pb.ResponseState
	}{
		{
			name:   "Missing",
			client: "client1",
			state:  pb.ResponseState_DENIED,
			err:    "no request specified",
		},
		{
			name:   "Empty",
			client: "client1",
			req:    &pb.LockWalletRequest{},
			state:  pb.ResponseState_DENIED,
		},
		{
			name:   "WalletUnknown",
			client: "client1",
			req: &pb.LockWalletRequest{
				Wallet: "Unknown",
			},
			state: pb.ResponseState_DENIED,
		},
		{
			name:   "DeniedClient",
			client: "Deny this client",
			req: &pb.LockWalletRequest{
				Wallet: "Wallet 1",
			},
			state: pb.ResponseState_DENIED,
		},
		{
			name:   "Good",
			client: "client1",
			req: &pb.LockWalletRequest{
				Wallet: "Wallet 1",
			},
			state: pb.ResponseState_SUCCEEDED,
		},
	}

	handler, err := Setup()
	require.Nil(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), &interceptors.ClientName{}, test.client)
			resp, err := handler.Lock(ctx, test.req)
			if test.err == "" {
				// Result expected.
				require.NoError(t, err)
				assert.Equal(t, test.state, resp.State)
			} else {
				// Error expected.
				assert.EqualError(t, err, test.err)
			}
		})
	}
}

func Setup() (*walletmanager.Handler, error) {
	ctx := context.Background()
	store, err := accounts.Setup(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create accounts")
	}

	locker, err := syncmaplocker.New(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create locker")
	}

	stores := []e2wtypes.Store{store}
	fetcher, err := memfetcher.New(ctx,
		memfetcher.WithStores(stores),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create fetcher")
	}

	ruler, err := golang.New(ctx,
		golang.WithLocker(locker),
		golang.WithRules(mockrules.New()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ruler")
	}

	checker, err := mockchecker.New(zerolog.Disabled)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create checker")
	}

	unlocker, err := localunlocker.New(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create unlocker")
	}

	walletManager, err := standardwalletmanager.New(ctx,
		standardwalletmanager.WithLogLevel(zerolog.Disabled),
		standardwalletmanager.WithUnlocker(unlocker),
		standardwalletmanager.WithChecker(checker),
		standardwalletmanager.WithFetcher(fetcher),
		standardwalletmanager.WithRuler(ruler),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create wallet manager")
	}

	endpoints := map[uint64]string{
		1: "signer-test01:8881",
		2: "signer-test02:8882",
		3: "signer-test03:8883",
	}

	peers, err := staticpeers.New(ctx,
		staticpeers.WithPeers(endpoints),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create peers")
	}

	process, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checker),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(1),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(mocksender.New(1)),
		standardprocess.WithFetcher(fetcher),
		standardprocess.WithStores(stores),
		standardprocess.WithUnlocker(unlocker),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create process")
	}

	return walletmanager.New(ctx,
		walletmanager.WithWalletManager(walletManager),
		walletmanager.WithProcess(process),
	)
}
