// Copyright © 2026 Attestant Limited.
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
	"fmt"
	"os"
	"testing"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	standardrules "github.com/attestantio/dirk/rules/standard"
	"github.com/attestantio/dirk/services/checker"
	staticchecker "github.com/attestantio/dirk/services/checker/static"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	syncmaplocker "github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/ruler/golang"
	"github.com/attestantio/dirk/services/signer"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// _voluntaryExitSignerSvc creates a signer service with a static checker and the standard
// rules, allowing the voluntary exit permission flow to be exercised end-to-end.
func _voluntaryExitSignerSvc(ctx context.Context, t *testing.T, adminIPs []string) signer.Service {
	t.Helper()

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

	for _, accountName := range []string{"Test account 1", "Test account 2"} {
		passphrase := []byte(fmt.Sprintf("%s passphrase", accountName))
		account, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(ctx, accountName, passphrase)
		require.NoError(t, err)
		require.NoError(t, account.(e2wtypes.AccountLocker).Unlock(ctx, passphrase))
	}
	require.NoError(t, wallet.(e2wtypes.WalletLocker).Lock(ctx))

	lockerSvc, err := syncmaplocker.New(ctx)
	require.NoError(t, err)

	fetcherSvc, err := memfetcher.New(ctx,
		memfetcher.WithStores([]e2wtypes.Store{store}))
	require.NoError(t, err)

	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(base) })
	rulesSvc, err := standardrules.New(ctx,
		standardrules.WithStoragePath(base),
		standardrules.WithAdminIPs(adminIPs),
	)
	require.NoError(t, err)

	rulerSvc, err := golang.New(ctx,
		golang.WithLocker(lockerSvc),
		golang.WithRules(rulesSvc))
	require.NoError(t, err)

	unlockerSvc, err := localunlocker.New(ctx,
		localunlocker.WithAccountPassphrases([]string{"Test account 1 passphrase", "Test account 2 passphrase"}))
	require.NoError(t, err)

	permissions := map[string][]*checker.Permissions{
		"exiter": {
			{
				Path:       ".*",
				Operations: []string{"Sign voluntary exit"},
			},
		},
		"legacy": {
			{
				Path:       ".*",
				Operations: []string{"Sign"},
			},
		},
		"all": {
			{
				Path:       ".*",
				Operations: []string{"All"},
			},
		},
		"denyve": {
			{
				Path:       ".*",
				Operations: []string{"~Sign voluntary exit", "All"},
			},
		},
	}
	checkerSvc, err := staticchecker.New(ctx,
		staticchecker.WithPermissions(permissions))
	require.NoError(t, err)

	return _signerSvc(ctx, checkerSvc, fetcherSvc, rulerSvc, unlockerSvc)
}

func TestSignVoluntaryExit(t *testing.T) {
	ctx := context.Background()
	signerSvc := _voluntaryExitSignerSvc(ctx, t, []string{"1.2.3.4"})

	voluntaryExitDomain := []byte{
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	genericDomain := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	root := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	tests := []struct {
		name        string
		credentials *checker.Credentials
		domain      []byte
		res         core.Result
	}{
		{
			// A client with the voluntary exit permission does not require an approved IP address.
			name:        "ExiterNoIP",
			credentials: &checker.Credentials{Client: "exiter"},
			domain:      voluntaryExitDomain,
			res:         core.ResultSucceeded,
		},
		{
			name:        "ExiterUnapprovedIP",
			credentials: &checker.Credentials{Client: "exiter", IP: "5.6.7.8"},
			domain:      voluntaryExitDomain,
			res:         core.ResultSucceeded,
		},
		{
			// The voluntary exit permission does not grant generic signing.
			name:        "ExiterGenericDomain",
			credentials: &checker.Credentials{Client: "exiter"},
			domain:      genericDomain,
			res:         core.ResultDenied,
		},
		{
			// A client without the voluntary exit permission falls back to the generic sign
			// permission, which requires an approved IP address for voluntary exits.
			name:        "LegacyApprovedIP",
			credentials: &checker.Credentials{Client: "legacy", IP: "1.2.3.4"},
			domain:      voluntaryExitDomain,
			res:         core.ResultSucceeded,
		},
		{
			name:        "LegacyUnapprovedIP",
			credentials: &checker.Credentials{Client: "legacy", IP: "5.6.7.8"},
			domain:      voluntaryExitDomain,
			res:         core.ResultDenied,
		},
		{
			name:        "LegacyNoIP",
			credentials: &checker.Credentials{Client: "legacy"},
			domain:      voluntaryExitDomain,
			res:         core.ResultDenied,
		},
		{
			name:        "LegacyGenericDomain",
			credentials: &checker.Credentials{Client: "legacy"},
			domain:      genericDomain,
			res:         core.ResultSucceeded,
		},
		{
			// "All" includes the voluntary exit permission.
			name:        "AllNoIP",
			credentials: &checker.Credentials{Client: "all"},
			domain:      voluntaryExitDomain,
			res:         core.ResultSucceeded,
		},
		{
			// An explicit denial of the voluntary exit permission removes the IP-free path...
			name:        "ExplicitDenialNoIP",
			credentials: &checker.Credentials{Client: "denyve"},
			domain:      voluntaryExitDomain,
			res:         core.ResultDenied,
		},
		{
			// ...but the fallback still allows voluntary exits from an approved IP address.
			name:        "ExplicitDenialApprovedIP",
			credentials: &checker.Credentials{Client: "denyve", IP: "1.2.3.4"},
			domain:      voluntaryExitDomain,
			res:         core.ResultSucceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, signature := signerSvc.SignGeneric(ctx, test.credentials, "Test wallet/Test account 1", nil, &rules.SignData{
				Data:   root,
				Domain: test.domain,
			})
			assert.Equal(t, test.res, res)
			if test.res == core.ResultSucceeded {
				assert.NotNil(t, signature)
			}
		})
	}
}

func TestMultisignVoluntaryExit(t *testing.T) {
	ctx := context.Background()
	signerSvc := _voluntaryExitSignerSvc(ctx, t, []string{"1.2.3.4"})

	voluntaryExitDomain := []byte{
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	genericDomain := []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	root := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	accountNames := []string{
		"Test wallet/Test account 1",
		"Test wallet/Test account 2",
	}
	data := []*rules.SignData{
		{
			Data:   root,
			Domain: genericDomain,
		},
		{
			Data:   root,
			Domain: voluntaryExitDomain,
		},
	}

	tests := []struct {
		name        string
		credentials *checker.Credentials
		res         []core.Result
	}{
		{
			// "All" covers both the generic sign and voluntary exit permissions.
			name:        "AllNoIP",
			credentials: &checker.Credentials{Client: "all"},
			res:         []core.Result{core.ResultSucceeded, core.ResultSucceeded},
		},
		{
			// A legacy client is subject to the IP address check for the voluntary exit only.
			name:        "LegacyUnapprovedIP",
			credentials: &checker.Credentials{Client: "legacy", IP: "5.6.7.8"},
			res:         []core.Result{core.ResultSucceeded, core.ResultDenied},
		},
		{
			name:        "LegacyApprovedIP",
			credentials: &checker.Credentials{Client: "legacy", IP: "1.2.3.4"},
			res:         []core.Result{core.ResultSucceeded, core.ResultSucceeded},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, _ := signerSvc.Multisign(ctx, test.credentials, accountNames, nil, data)
			assert.Equal(t, test.res, res)
		})
	}
}
