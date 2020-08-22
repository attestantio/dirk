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
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

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
