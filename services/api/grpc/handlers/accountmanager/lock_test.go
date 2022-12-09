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

package accountmanager_test

import (
	context "context"
	"os"
	"testing"

	mockrules "github.com/attestantio/dirk/rules/mock"
	standardaccountmanager "github.com/attestantio/dirk/services/accountmanager/standard"
	"github.com/attestantio/dirk/services/api/grpc/handlers/accountmanager"
	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	mockprocess "github.com/attestantio/dirk/services/process/mock"
	"github.com/attestantio/dirk/services/ruler/golang"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	accounts "github.com/attestantio/dirk/testing/accounts"
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
	os.Exit(m.Run())
}

func TestLock(t *testing.T) {
	tests := []struct {
		name   string
		client string
		req    *pb.LockAccountRequest
		err    string
		state  pb.ResponseState
	}{
		{
			name:   "Missing",
			client: "client1",
			err:    "no request specified",
		},
		{
			name:   "Empty",
			client: "client1",
			req:    &pb.LockAccountRequest{},
			state:  pb.ResponseState_DENIED,
		},
		{
			name:   "WalletUnknown",
			client: "client1",
			req:    &pb.LockAccountRequest{Account: "Unknown"},
			state:  pb.ResponseState_DENIED,
		},
		{
			name:   "AccountNil",
			client: "client1",
			req:    &pb.LockAccountRequest{Account: "Wallet 1"},
			state:  pb.ResponseState_DENIED,
		},
		{
			name:   "AccountEmpty",
			client: "client1",
			req:    &pb.LockAccountRequest{Account: "Wallet 1/"},
			state:  pb.ResponseState_DENIED,
		},
		{
			name:   "AccountUnknown",
			client: "client1",
			req:    &pb.LockAccountRequest{Account: "Wallet 1/Unknown"},
			state:  pb.ResponseState_DENIED,
		},
		{
			name:   "DeniedClient",
			client: "Deny this client",
			req:    &pb.LockAccountRequest{Account: "Wallet 1/Account 1"},
			state:  pb.ResponseState_DENIED,
		},
		{
			name:   "Good",
			client: "client1",
			req:    &pb.LockAccountRequest{Account: "Wallet 1/Account 1"},
			state:  pb.ResponseState_SUCCEEDED,
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

func Setup() (*accountmanager.Handler, error) {
	ctx := context.Background()
	store, err := accounts.Setup(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create accounts")
	}

	locker, err := syncmaplocker.New(ctx)
	if err != nil {
		return nil, err
	}

	fetcher, err := memfetcher.New(ctx,
		memfetcher.WithStores([]e2wtypes.Store{store}))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create account fetcher service")
	}

	ruler, err := golang.New(ctx,
		golang.WithLocker(locker),
		golang.WithRules(mockrules.New()))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create account rules service")
	}

	checker, err := mockchecker.New(zerolog.Disabled)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create account checker service")
	}
	process, err := mockprocess.New()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create process service")
	}
	unlocker, err := localunlocker.New(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create unlocker service")
	}

	accountManager, err := standardaccountmanager.New(ctx,
		standardaccountmanager.WithLogLevel(zerolog.Disabled),
		standardaccountmanager.WithUnlocker(unlocker),
		standardaccountmanager.WithChecker(checker),
		standardaccountmanager.WithFetcher(fetcher),
		standardaccountmanager.WithRuler(ruler),
		standardaccountmanager.WithProcess(process),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create account manager service")
	}
	return accountmanager.New(ctx,
		accountmanager.WithAccountManager(accountManager),
		accountmanager.WithProcess(process))
}
