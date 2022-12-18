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
	"time"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/ruler"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Lock locks an account.
func (s *Service) Lock(ctx context.Context,
	credentials *checker.Credentials,
	accountName string,
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
		Str("account", accountName).
		Str("action", "Lock").
		Logger()
	log.Trace().Msg("Request received")

	wallet, account, checkRes := s.preCheck(ctx, credentials, accountName, nil, ruler.ActionLockAccount)
	if checkRes != core.ResultSucceeded {
		s.monitor.AccountManagerCompleted(started, "lock", checkRes)
		return checkRes, nil
	}

	// Confirm approval via rules.
	rulesData := []*ruler.RulesData{
		{
			WalletName:  wallet.Name(),
			AccountName: account.Name(),
			PubKey:      account.PublicKey().Marshal(),
			Data:        &rules.LockAccountData{},
		},
	}
	results := s.ruler.RunRules(ctx, credentials, ruler.ActionLockAccount, rulesData)
	switch results[0] {
	case rules.DENIED:
		log.Debug().Str("result", "denied").Msg("Denied by rules")
		s.monitor.AccountManagerCompleted(started, "lock", core.ResultDenied)
		return core.ResultDenied, nil
	case rules.FAILED:
		log.Error().Str("result", "failed").Msg("Rules check failed")
		s.monitor.AccountManagerCompleted(started, "lock", core.ResultFailed)
		return core.ResultFailed, nil
	case rules.UNKNOWN:
		log.Error().Str("result", "failed").Msg("Rules check indeterminate result")
		s.monitor.AccountManagerCompleted(started, "lock", core.ResultFailed)
		return core.ResultFailed, nil
	case rules.APPROVED:
		// Nothing to do.
	}

	// Lock it.
	locker, isLocker := account.(e2wtypes.AccountLocker)
	if !isLocker {
		// We cannot lock this account, it may be through external means
		// (for example, a hardware key).  We return success to allow the
		// control flow to proceed.
		log.Debug().Str("result", "succeeded").Msg("Not a lockable account")
		s.monitor.AccountManagerCompleted(started, "lock", core.ResultSucceeded)
		return core.ResultSucceeded, nil
	}

	if err := locker.Lock(ctx); err != nil {
		log.Warn().Err(err).Str("result", "denied").Msg("Failed to lock")
		s.monitor.AccountManagerCompleted(started, "lock", core.ResultDenied)
		return core.ResultDenied, nil
	}

	log.Trace().Str("result", "succeeded").Msg("Success")
	s.monitor.AccountManagerCompleted(started, "lock", core.ResultSucceeded)
	return core.ResultSucceeded, nil
}
