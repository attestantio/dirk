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

package signer_test

import (
	context "context"
	"os"
	"testing"

	mockrules "github.com/attestantio/dirk/rules/mock"
	"github.com/attestantio/dirk/services/api/grpc/handlers/signer"
	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/ruler/golang"
	standardsigner "github.com/attestantio/dirk/services/signer/standard"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	"github.com/attestantio/dirk/testing/accounts"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
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

func TestSign(t *testing.T) {
	tests := []struct {
		name   string
		client string
		req    *pb.SignRequest
		state  pb.ResponseState
		err    string
	}{
		{
			name:   "Empty",
			client: "client1",
			state:  pb.ResponseState_DENIED,
		},
		{
			name:   "IdEmpty",
			client: "client1",
			state:  pb.ResponseState_DENIED,
			req: &pb.SignRequest{
				Data: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				Domain: []byte{
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
					0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x1e, 0x3f,
				},
			},
		},
		{
			name:   "IdInvalid",
			client: "client1",
			state:  pb.ResponseState_DENIED,
			req: &pb.SignRequest{
				Id: &pb.SignRequest_Account{
					Account: "Bad",
				},
				Data: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				Domain: []byte{
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
					0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x1e, 0x3f,
				},
			},
		},
		{
			name:   "Good",
			client: "client1",
			req: &pb.SignRequest{
				Id: &pb.SignRequest_Account{
					Account: "Wallet 1/Account 1",
				},
				Data: []byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				Domain: []byte{
					0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
					0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x1e, 0x3f,
				},
			},
			state: pb.ResponseState_SUCCEEDED,
		},
	}

	handler, err := Setup()
	require.Nil(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), &interceptors.ClientName{}, test.client)
			resp, err := handler.Sign(ctx, test.req)
			if test.err == "" {
				require.NoError(t, err)
				require.Equal(t, test.state, resp.State)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}

// Setup sets up a test signer handler.
func Setup() (*signer.Handler, error) {
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
		return nil, err
	}

	unlocker, err := localunlocker.New(context.Background(),
		localunlocker.WithAccountPassphrases([]string{"Account 1 passphrase", "Account 2 passphrase"}))
	if err != nil {
		return nil, err
	}

	ruler, err := golang.New(ctx,
		golang.WithLocker(locker),
		golang.WithRules(mockrules.New()))
	if err != nil {
		return nil, err
	}

	checker, err := mockchecker.New(zerolog.Disabled)
	if err != nil {
		return nil, err
	}

	service, err := standardsigner.New(ctx,
		standardsigner.WithUnlocker(unlocker),
		standardsigner.WithChecker(checker),
		standardsigner.WithFetcher(fetcher),
		standardsigner.WithRuler(ruler))
	if err != nil {
		return nil, err
	}

	return signer.New(ctx, signer.WithSigner(service))
}
