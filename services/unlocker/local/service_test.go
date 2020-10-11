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

package local_test

import (
	"context"
	"testing"

	"github.com/attestantio/dirk/services/unlocker/local"
	"github.com/attestantio/dirk/testing/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	nd "github.com/wealdtech/go-eth2-wallet-nd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestUnlockWallet(t *testing.T) {
	ctx := context.Background()
	service, err := local.New(context.Background(),
		local.WithWalletPassphrases([]string{"guess", "secret"}),
	)
	require.NoError(t, err)

	err = e2types.InitBLS()
	require.NoError(t, err)

	// Create wallets of varying types.
	store := scratch.New()
	encryptor := keystorev4.New()
	seed := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}

	hdWallet1, err := hd.CreateWallet(ctx, "HD wallet 1", []byte("not known"), store, encryptor, seed)
	require.NoError(t, err)
	hdWallet2, err := hd.CreateWallet(ctx, "HD wallet 2", []byte("secret"), store, encryptor, seed)
	require.NoError(t, err)
	ndWallet, err := nd.CreateWallet(ctx, "ND wallet", store, encryptor)
	require.NoError(t, err)
	mockWallet := mock.NewWallet("Test wallet")

	tests := []struct {
		name   string
		wallet e2wtypes.Wallet
		err    string
		result bool
	}{
		{
			name: "NoWallet",
			err:  "no wallet supplied",
		},
		{
			name:   "UnknownPassword",
			wallet: hdWallet1,
			result: false,
		},
		{
			name:   "Good",
			wallet: hdWallet2,
			result: true,
		},
		{
			name:   "GoodND",
			wallet: ndWallet,
			result: true,
		},
		{
			name:   "UnsuitableWalletType",
			wallet: mockWallet,
			result: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := service.UnlockWallet(ctx, test.wallet)
			if test.err != "" {
				assert.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.result, result)
			}
		})
	}
}

func TestUnlockAccount(t *testing.T) {
	ctx := context.Background()
	service, err := local.New(context.Background(),
		local.WithAccountPassphrases([]string{"secret", "secret2"}))
	require.NoError(t, err)

	err = e2types.InitBLS()
	require.NoError(t, err)

	wallet := mock.NewWallet("Test wallet")

	tests := []struct {
		name    string
		wallet  e2wtypes.Wallet
		account e2wtypes.Account
		err     string
		result  bool
	}{
		{
			name:    "NoWallet",
			account: mock.NewAccount("Account 1", []byte("secret")),
			err:     "no wallet supplied",
		},
		{
			name:   "NoAccount",
			wallet: wallet,
			err:    "no account supplied",
		},
		{
			name:    "UnknownPassword",
			wallet:  wallet,
			account: mock.NewAccount("Account 1", []byte("unknown secret")),
			result:  false,
		},
		{
			name:    "Good",
			wallet:  wallet,
			account: mock.NewAccount("Account 1", []byte("secret")),
			result:  true,
		},
		{
			name:    "GoodSecondTry",
			wallet:  wallet,
			account: mock.NewAccount("Account 1", []byte("secret2")),
			result:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := service.UnlockAccount(ctx, test.wallet, test.account)
			if test.err != "" {
				assert.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.result, result)
			}
		})
	}
}
