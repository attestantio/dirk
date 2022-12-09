// Copyright © 2020, 2021 Attestant Limited.
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

package standard_test

import (
	context "context"
	"os"
	"testing"

	mockrules "github.com/attestantio/dirk/rules/mock"
	"github.com/attestantio/dirk/services/checker"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	"github.com/attestantio/dirk/services/fetcher"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/attestantio/dirk/services/metrics/prometheus"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/attestantio/dirk/services/ruler/golang"
	standardsigner "github.com/attestantio/dirk/services/signer/standard"
	"github.com/attestantio/dirk/services/unlocker"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestMain(m *testing.M) {
	if err := e2types.InitBLS(); err != nil {
		os.Exit(1)
	}
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func TestService(t *testing.T) {
	ctx := context.Background()

	store := scratch.New()
	encryptor := keystorev4.New()
	seed := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}

	wallet, err := hd.CreateWallet(ctx, "Test wallet", []byte("secret"), store, encryptor, seed)
	require.NoError(t, err)
	require.NoError(t, wallet.(e2wtypes.WalletLocker).Unlock(ctx, []byte("secret")))

	accounts := []string{
		"Test account 1",
		"Test account 2",
	}
	for _, account := range accounts {
		_, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(ctx, account, []byte(account+" passphrase"))
		require.NoError(t, err)
	}
	require.NoError(t, wallet.(e2wtypes.WalletLocker).Lock(ctx))

	monitorSvc, err := prometheus.New(ctx, prometheus.WithAddress("localhost:11111"))
	require.NoError(t, err)

	lockerSvc, err := syncmaplocker.New(ctx)
	require.NoError(t, err)

	fetcherSvc, err := memfetcher.New(ctx,
		memfetcher.WithStores([]e2wtypes.Store{store}))
	require.NoError(t, err)

	rulerSvc, err := golang.New(ctx,
		golang.WithLocker(lockerSvc),
		golang.WithRules(mockrules.New()))
	require.NoError(t, err)

	unlockerSvc, err := localunlocker.New(context.Background(),
		localunlocker.WithAccountPassphrases([]string{"Test account 1 passphrase"}))
	require.NoError(t, err)

	checkerSvc, err := mockchecker.New(zerolog.Disabled)
	require.NoError(t, err)

	tests := []struct {
		name     string
		monitor  metrics.SignerMonitor
		unlocker unlocker.Service
		checker  checker.Service
		fetcher  fetcher.Service
		ruler    ruler.Service
		err      string
	}{
		{
			name: "Empty",
			err:  "problem with parameters: no checker specified",
		},
		{
			name:     "NoChecker",
			monitor:  monitorSvc,
			unlocker: unlockerSvc,
			fetcher:  fetcherSvc,
			ruler:    rulerSvc,
			err:      "problem with parameters: no checker specified",
		},
		{
			name:     "NoFetcher",
			monitor:  monitorSvc,
			unlocker: unlockerSvc,
			checker:  checkerSvc,
			ruler:    rulerSvc,
			err:      "problem with parameters: no fetcher specified",
		},
		{
			name:     "NoRuler",
			monitor:  monitorSvc,
			unlocker: unlockerSvc,
			checker:  checkerSvc,
			fetcher:  fetcherSvc,
			err:      "problem with parameters: no ruler specified",
		},
		{
			name:    "NoUnlocker",
			monitor: monitorSvc,
			checker: checkerSvc,
			fetcher: fetcherSvc,
			ruler:   rulerSvc,
			err:     "problem with parameters: no unlocker specified",
		},
		{
			name:     "Good",
			monitor:  monitorSvc,
			unlocker: unlockerSvc,
			checker:  checkerSvc,
			fetcher:  fetcherSvc,
			ruler:    rulerSvc,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := standardsigner.New(ctx,
				standardsigner.WithLogLevel(zerolog.Disabled),
				standardsigner.WithMonitor(test.monitor),
				standardsigner.WithUnlocker(test.unlocker),
				standardsigner.WithChecker(test.checker),
				standardsigner.WithFetcher(test.fetcher),
				standardsigner.WithRuler(test.ruler))
			if test.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.err)
			}
		})
	}
}
