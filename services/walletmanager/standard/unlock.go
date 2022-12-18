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
	"context"
	"time"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/pkg/errors"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Unlock unlocks a wallet.
func (s *Service) Unlock(ctx context.Context,
	credentials *checker.Credentials,
	accountName string,
	passphrase []byte,
) (
	core.Result,
	error,
) {
	started := time.Now()

	if credentials == nil {
		log.Error().Msg("No credentials supplied")
		return core.ResultFailed, nil
	}

	log := log.With().
		Str("request_id", credentials.RequestID).
		Str("client", credentials.Client).
		Str("wallet", accountName).
		Str("action", "Unlock").
		Logger()
	log.Trace().Msg("Request received")

	wallet, checkRes := s.preCheck(ctx, credentials, accountName, ruler.ActionUnlockWallet)
	if checkRes != core.ResultSucceeded {
		s.monitor.WalletManagerCompleted(started, "unlock", checkRes)
		return checkRes, nil
	}

	// Confirm approval via rules.
	rulesData := []*ruler.RulesData{
		{
			WalletName: wallet.Name(),
			Data:       &rules.UnlockWalletData{},
		},
	}
	results := s.ruler.RunRules(ctx, credentials, ruler.ActionUnlockWallet, rulesData)
	switch results[0] {
	case rules.DENIED:
		log.Debug().Str("result", "denied").Msg("Denied by rules")
		s.monitor.WalletManagerCompleted(started, "unlock", core.ResultDenied)
		return core.ResultDenied, nil
	case rules.FAILED:
		log.Error().Str("result", "failed").Msg("Rules check failed")
		s.monitor.WalletManagerCompleted(started, "unlock", core.ResultFailed)
		return core.ResultFailed, errors.New("rules check failed")
	case rules.UNKNOWN:
		log.Error().Str("result", "failed").Msg("Rules check indeterminate result")
		s.monitor.WalletManagerCompleted(started, "unlock", core.ResultFailed)
		return core.ResultFailed, errors.New("rules check indeterminate result")
	case rules.APPROVED:
		// Nothing to do.
	}

	// Unlock it.
	locker, isLocker := wallet.(e2wtypes.WalletLocker)
	if !isLocker {
		// We cannot unlock this wallet, it may be through external means
		// (for example, a hardware key).  We return success to allow the
		// control flow to proceed.
		log.Debug().Str("result", "succeeded").Msg("Not an unlockable wallet")
		s.monitor.WalletManagerCompleted(started, "unlock", core.ResultSucceeded)
		return core.ResultSucceeded, nil
	}

	if err := locker.Unlock(ctx, passphrase); err != nil {
		log.Error().Err(err).Str("result", "denied").Msg("Failed to unlock")
		s.monitor.WalletManagerCompleted(started, "unlock", core.ResultDenied)
		return core.ResultDenied, nil
	}

	log.Trace().Str("result", "succeeded").Msg("Success")
	s.monitor.WalletManagerCompleted(started, "unlock", core.ResultSucceeded)
	return core.ResultSucceeded, nil
}
