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

package lister_test

import (
	context "context"
	"os"
	"testing"

	mockrules "github.com/attestantio/dirk/rules/mock"
	"github.com/attestantio/dirk/services/api/grpc/handlers/lister"
	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	standardlister "github.com/attestantio/dirk/services/lister/standard"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/ruler/golang"
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

func TestListAccounts(t *testing.T) {
	tests := []struct {
		name   string
		client string
		req    *pb.ListAccountsRequest
		// paths               []string
		err                 string
		accounts            []string
		distributedAccounts []string
	}{
		{
			name:   "Empty",
			client: "client1",
			err:    "no request specified",
		},
		{
			name:   "MissingPaths",
			client: "client1",
			req:    &pb.ListAccountsRequest{},
		},
		{
			name:   "EmptyPaths",
			client: "client1",
			req: &pb.ListAccountsRequest{
				Paths: []string{},
			},
		},
		{
			name:   "EmptyPath",
			client: "client1",
			req: &pb.ListAccountsRequest{
				Paths: []string{""},
			},
		},
		{
			name:   "NoWallet",
			client: "client1",
			req: &pb.ListAccountsRequest{
				Paths: []string{"/Account"},
			},
		},
		{
			name:   "UnknownWallet",
			client: "client1",
			req: &pb.ListAccountsRequest{
				Paths: []string{"Unknown/.*"},
			},
			accounts: []string{},
		},
		{
			name:   "UnknownPath",
			client: "client1",
			req: &pb.ListAccountsRequest{
				Paths: []string{"Wallet 1/nothinghere"},
			},
			accounts: []string{},
		},
		{
			name:   "BadPath",
			client: "client1",
			req: &pb.ListAccountsRequest{
				Paths: []string{"Wallet 1/.***"},
			},
			accounts: []string{},
		},
		{
			name:   "All",
			client: "client1",
			req: &pb.ListAccountsRequest{
				Paths: []string{"Wallet 1"},
			},
			accounts: []string{"Account 1", "Account 2", "Account 3", "Account 4", "A different account"},
		},
		{
			name:   "DeniedClient",
			client: "Deny this client",
			req: &pb.ListAccountsRequest{
				Paths: []string{"Wallet 1"},
			},
			accounts: []string{},
		},
		{
			name:   "Subset",
			client: "client1",
			req: &pb.ListAccountsRequest{
				Paths: []string{"Wallet 1/Account [0-9]+"},
			},
			accounts: []string{"Account 1", "Account 2", "Account 3", "Account 4"},
		},
		{
			name:   "Distributed",
			client: "client1",
			req: &pb.ListAccountsRequest{
				Paths: []string{"Wallet 2"},
			},
			distributedAccounts: []string{"Account 1"},
		},
	}

	handler, err := Setup()
	require.Nil(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), &interceptors.ClientName{}, test.client)
			resp, err := handler.ListAccounts(ctx, test.req)
			if test.err == "" {
				// Result expected.
				require.NoError(t, err)
				assert.Equal(t, len(test.accounts), len(resp.Accounts))
				assert.Equal(t, len(test.distributedAccounts), len(resp.DistributedAccounts))
			} else {
				// Error expected.
				require.NotNil(t, err)
				assert.Equal(t, test.err, err.Error())
			}
		})
	}
}

func Setup() (*lister.Handler, error) {
	ctx := context.Background()
	store, err := accounts.Setup(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create accounts")
	}

	locker, err := syncmaplocker.New(ctx,
		syncmaplocker.WithLogLevel(zerolog.Disabled),
	)
	if err != nil {
		return nil, err
	}

	fetcher, err := memfetcher.New(ctx,
		memfetcher.WithLogLevel(zerolog.Disabled),
		memfetcher.WithStores([]e2wtypes.Store{store}))
	if err != nil {
		return nil, err
	}

	ruler, err := golang.New(ctx,
		golang.WithLogLevel(zerolog.Disabled),
		golang.WithLocker(locker),
		golang.WithRules(mockrules.New()))
	if err != nil {
		return nil, err
	}

	checker, err := mockchecker.New(zerolog.Disabled)
	if err != nil {
		return nil, err
	}

	service, err := standardlister.New(ctx,
		standardlister.WithLogLevel(zerolog.Disabled),
		standardlister.WithChecker(checker),
		standardlister.WithFetcher(fetcher),
		standardlister.WithRuler(ruler))
	if err != nil {
		return nil, err
	}

	return lister.New(ctx,
		lister.WithLogLevel(zerolog.Disabled),
		lister.WithLister(service),
	)
}
