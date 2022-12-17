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

// Unlock unlocks an account.
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
		Str("account", accountName).
		Str("action", "Unlock").
		Logger()
	log.Trace().Msg("Request received")

	wallet, account, checkRes := s.preCheck(ctx, credentials, accountName, nil, ruler.ActionUnlockAccount)
	if checkRes != core.ResultSucceeded {
		s.monitor.AccountManagerCompleted(started, "unlock", checkRes)
		return checkRes, nil
	}

	// Confirm approval via rules.
	rulesData := []*ruler.RulesData{
		{
			WalletName:  wallet.Name(),
			AccountName: account.Name(),
			PubKey:      account.PublicKey().Marshal(),
			Data:        &rules.UnlockAccountData{},
		},
	}
	results := s.ruler.RunRules(ctx, credentials, ruler.ActionUnlockAccount, rulesData)
	switch results[0] {
	case rules.DENIED:
		s.monitor.AccountManagerCompleted(started, "unlock", core.ResultDenied)
		return core.ResultDenied, nil
	case rules.FAILED:
		s.monitor.AccountManagerCompleted(started, "unlock", core.ResultFailed)
		return core.ResultFailed, errors.New("rules check failed")
	case rules.UNKNOWN:
		s.monitor.AccountManagerCompleted(started, "unlock", core.ResultFailed)
		return core.ResultFailed, errors.New("rules check indeterminate result")
	case rules.APPROVED:
		// Nothing to do.
	}

	// Unlock it.
	locker, isLocker := account.(e2wtypes.AccountLocker)
	if !isLocker {
		// We cannot unlock this account, it may be through external means
		// (for example, a hardware key).  We return success to allow the
		// control flow to proceed.
		s.monitor.AccountManagerCompleted(started, "unlock", core.ResultSucceeded)
		return core.ResultSucceeded, nil
	}

	if err := locker.Unlock(ctx, passphrase); err != nil {
		s.monitor.AccountManagerCompleted(started, "unlock", core.ResultDenied)
		//nolint:nilerr
		return core.ResultDenied, nil
	}

	log.Trace().Str("result", "succeeded").Msg("Success")
	s.monitor.AccountManagerCompleted(started, "unlock", core.ResultSucceeded)
	return core.ResultSucceeded, nil
}
