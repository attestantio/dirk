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

package local

import (
	"context"

	"github.com/attestantio/dirk/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is an unlocker service that holds unlock passphrases for wallets and accounts.
type Service struct {
	monitor            metrics.UnlockerMonitor
	walletPassphrases  []string
	accountPassphrases []string
}

// module-wide log.
var log zerolog.Logger

// New creates a new unlocker service that holds unlock passphrases for wallets and accounts.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "unlocker").Str("impl", "local").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		monitor:            parameters.monitor,
		walletPassphrases:  parameters.walletPassphrases,
		accountPassphrases: parameters.accountPassphrases,
	}

	return s, nil
}

// UnlockWallet attempts to unlock a wallet.
func (s *Service) UnlockWallet(ctx context.Context, wallet e2wtypes.Wallet) (bool, error) {
	if wallet == nil {
		return false, errors.New("no wallet supplied")
	}

	locker, isUnlocker := wallet.(e2wtypes.WalletLocker)
	if !isUnlocker {
		// Wallet does not support unlocking.
		return true, nil
	}

	if wallet.Type() == "non-deterministic" {
		// Non-deterministic wallets don't have passphrases.
		err := locker.Unlock(ctx, nil)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	for _, passphrase := range s.walletPassphrases {
		if err := locker.Unlock(ctx, []byte(passphrase)); err == nil {
			return true, nil
		}
	}
	return false, nil
}

// UnlockAccount attempts to unlock an account.
func (s *Service) UnlockAccount(ctx context.Context, wallet e2wtypes.Wallet, account e2wtypes.Account) (bool, error) {
	if wallet == nil {
		return false, errors.New("no wallet supplied")
	}
	if account == nil {
		return false, errors.New("no account supplied")
	}

	locker, isUnlocker := account.(e2wtypes.AccountLocker)
	if !isUnlocker {
		// Account does not support unlocking.
		return true, nil
	}

	for _, passphrase := range s.accountPassphrases {
		if err := locker.Unlock(ctx, []byte(passphrase)); err == nil {
			return true, nil
		}
	}

	return false, nil
}
