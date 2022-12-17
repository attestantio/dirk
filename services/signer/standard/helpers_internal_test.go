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

package standard

import (
	context "context"
	"fmt"
	"testing"

	"github.com/attestantio/dirk/core"
	mockrules "github.com/attestantio/dirk/rules/mock"
	"github.com/attestantio/dirk/services/checker"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/attestantio/dirk/services/ruler/golang"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestUnlockAccount(t *testing.T) {
	ctx := context.Background()
	signerSvc, wallet, accounts, err := setupSignerService(ctx)
	require.NoError(t, err)

	tests := []struct {
		name    string
		wallet  e2wtypes.Wallet
		account e2wtypes.Account
		res     core.Result
	}{
		{
			name: "Empty",
			res:  core.ResultDenied,
		},
		{
			name:   "NoAccount",
			wallet: wallet,
			res:    core.ResultDenied,
		},
		{
			name:    "UnknownPassword",
			wallet:  wallet,
			account: accounts[1],
			res:     core.ResultDenied,
		},
		{
			name:    "KnownPassword",
			wallet:  wallet,
			account: accounts[0],
			res:     core.ResultSucceeded,
		},
		{
			name:    "ReUnlock",
			wallet:  wallet,
			account: accounts[0],
			res:     core.ResultSucceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := signerSvc.unlockAccount(context.Background(), test.wallet, test.account)
			assert.Equal(t, test.res, res)
		})
	}
}

func TestCheckAccess(t *testing.T) {
	ctx := context.Background()
	signerSvc, _, _, err := setupSignerService(ctx)
	require.NoError(t, err)

	tests := []struct {
		name        string
		credentials *checker.Credentials
		accountName string
		action      string
		res         core.Result
	}{
		{
			name: "Empty",
			res:  core.ResultDenied,
		},
		{
			name:        "DeniedClient",
			credentials: &checker.Credentials{Client: "Deny this client"},
			accountName: "Test wallet/Test account 2",
			action:      ruler.ActionSign,
			res:         core.ResultDenied,
		},
		{
			name:        "Good",
			credentials: &checker.Credentials{Client: "client1"},
			accountName: "Test wallet/Test account 1",
			action:      ruler.ActionSign,
			res:         core.ResultSucceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := signerSvc.checkAccess(context.Background(), test.credentials, test.accountName, test.action)
			assert.Equal(t, test.res, res)
		})
	}
}

func TestFetchAccount(t *testing.T) {
	ctx := context.Background()
	signerSvc, _, accounts, err := setupSignerService(ctx)
	require.NoError(t, err)

	tests := []struct {
		name        string
		accountName string
		pubKey      []byte
		res         core.Result
	}{
		{
			name: "Empty",
			res:  core.ResultDenied,
		},
		{
			name:        "UnknownAccount",
			accountName: "Unknown",
			res:         core.ResultDenied,
		},
		{
			name:        "KnownAccount",
			accountName: "Test wallet/Test account 1",
			res:         core.ResultSucceeded,
		},
		{
			name:   "UnknownPubKey",
			pubKey: []byte{},
			res:    core.ResultDenied,
		},
		{
			name:   "KnownPubKey",
			pubKey: accounts[0].PublicKey().Marshal(),
			res:    core.ResultSucceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, res := signerSvc.fetchAccount(context.Background(), test.accountName, test.pubKey)
			assert.Equal(t, test.res, res)
		})
	}
}

func TestPreCheck(t *testing.T) {
	ctx := context.Background()
	signerSvc, wallet, accounts, err := setupSignerService(ctx)
	require.NoError(t, err)

	tests := []struct {
		name        string
		credentials *checker.Credentials
		accountName string
		pubKey      []byte
		action      string
		res         core.Result
	}{
		{
			name: "Empty",
			res:  core.ResultDenied,
		},
		{
			name:        "Locked",
			accountName: fmt.Sprintf("%s/%s", wallet.Name(), accounts[0].Name()),
			res:         core.ResultDenied,
		},
		{
			name:        "UnknownWallet",
			accountName: "Unknown/Unknown",
			res:         core.ResultDenied,
		},
		{
			name:        "UnknownAccount",
			accountName: fmt.Sprintf("%s/Unknown", wallet.Name()),
			res:         core.ResultDenied,
		},
		{
			name:        "Unlockable",
			credentials: &checker.Credentials{Client: "client1"},
			accountName: fmt.Sprintf("%s/%s", wallet.Name(), accounts[1].Name()),
			res:         core.ResultDenied,
		},
		{
			name:        "Good",
			credentials: &checker.Credentials{Client: "client1"},
			accountName: fmt.Sprintf("%s/%s", wallet.Name(), accounts[0].Name()),
			res:         core.ResultSucceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, res := signerSvc.preCheck(context.Background(), test.credentials, test.accountName, test.pubKey, test.action)
			assert.Equal(t, test.res, res)
		})
	}
}

// setupSignerService is a helper that creates a signer service for testing.
func setupSignerService(ctx context.Context) (*Service, e2wtypes.Wallet, []e2wtypes.Account, error) {
	store := scratch.New()
	encryptor := keystorev4.New()
	seed := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}

	wallet, err := hd.CreateWallet(ctx, "Test wallet", []byte("secret"), store, encryptor, seed)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := wallet.(e2wtypes.WalletLocker).Unlock(ctx, []byte("secret")); err != nil {
		return nil, nil, nil, err
	}

	accountNames := []string{
		"Test account 1",
		"Test account 2",
	}
	accounts := make([]e2wtypes.Account, 0)
	for _, accountName := range accountNames {
		account, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(ctx, accountName, []byte(accountName+" passphrase"))
		if err != nil {
			return nil, nil, nil, err
		}
		accounts = append(accounts, account)
	}
	if err := wallet.(e2wtypes.WalletLocker).Lock(ctx); err != nil {
		return nil, nil, nil, err
	}

	lockerSvc, err := syncmaplocker.New(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	fetcherSvc, err := memfetcher.New(ctx,
		memfetcher.WithStores([]e2wtypes.Store{store}))
	if err != nil {
		return nil, nil, nil, err
	}

	rulerSvc, err := golang.New(ctx,
		golang.WithLocker(lockerSvc),
		golang.WithRules(mockrules.New()))
	if err != nil {
		return nil, nil, nil, err
	}

	unlockerSvc, err := localunlocker.New(context.Background(),
		localunlocker.WithAccountPassphrases([]string{"Test account 1 passphrase"}))
	if err != nil {
		return nil, nil, nil, err
	}

	checkerSvc, err := mockchecker.New(zerolog.Disabled)
	if err != nil {
		return nil, nil, nil, err
	}

	s, err := New(ctx,
		WithChecker(checkerSvc),
		WithFetcher(fetcherSvc),
		WithRuler(rulerSvc),
		WithUnlocker(unlockerSvc))
	if err != nil {
		return nil, nil, nil, err
	}
	return s, wallet, accounts, nil
}
