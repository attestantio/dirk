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
	e2wallet "github.com/wealdtech/go-eth2-wallet"
)

// Generate generates an account.
func (s *Service) Generate(ctx context.Context,
	credentials *checker.Credentials,
	account string,
	passphrase []byte,
	signingThreshold uint32,
	participants uint32,
) (
	core.Result,
	[]byte,
	[]*core.Endpoint,
	error,
) {
	started := time.Now()

	if credentials == nil {
		log.Error().Msg("No credentials supplied")
		return core.ResultFailed, nil, nil, nil
	}

	log := log.With().
		Str("request_id", credentials.RequestID).
		Str("client", credentials.Client).
		Str("account", account).
		Str("action", "Generate").
		Logger()
	log.Trace().Msg("Request received")

	checkRes := s.checkAccess(ctx, credentials, account, ruler.ActionCreateAccount)
	if checkRes != core.ResultSucceeded {
		s.monitor.AccountManagerCompleted(started, "generate", checkRes)
		return checkRes, nil, nil, nil
	}

	// Check parameters.
	if participants == 0 {
		s.monitor.AccountManagerCompleted(started, "generate", core.ResultDenied)
		return core.ResultDenied, nil, nil, errors.New("invalid number of participants")
	}
	if participants < signingThreshold {
		s.monitor.AccountManagerCompleted(started, "generate", core.ResultDenied)
		return core.ResultDenied, nil, nil, errors.New("invalid signing threshold")
	}

	walletName, accountName, err := e2wallet.WalletAndAccountNames(account)
	if err != nil {
		s.monitor.AccountManagerCompleted(started, "generate", core.ResultDenied)
		return core.ResultDenied, nil, nil, errors.Wrap(err, "invalid account name")
	}
	// Confirm approval via rules.
	rulesData := []*ruler.RulesData{
		{
			WalletName:  walletName,
			AccountName: accountName,
			Data:        &rules.CreateAccountData{},
		},
	}
	results := s.ruler.RunRules(ctx, credentials, ruler.ActionCreateAccount, rulesData)
	switch results[0] {
	case rules.DENIED:
		s.monitor.AccountManagerCompleted(started, "generate", core.ResultDenied)
		return core.ResultDenied, nil, nil, nil
	case rules.FAILED:
		s.monitor.AccountManagerCompleted(started, "generate", core.ResultFailed)
		return core.ResultFailed, nil, nil, errors.New("rules check failed")
	case rules.UNKNOWN:
		s.monitor.AccountManagerCompleted(started, "generate", core.ResultFailed)
		return core.ResultFailed, nil, nil, errors.New("rules check indeterminate result")
	case rules.APPROVED:
		// Nothing to do.
	}

	// Generate it.
	pubKey, endpoints, err := s.process.OnGenerate(ctx, credentials, account, passphrase, signingThreshold, participants)
	if err != nil {
		s.monitor.AccountManagerCompleted(started, "generate", core.ResultSucceeded)
		return core.ResultFailed, nil, nil, errors.Wrap(err, "failed to generate account")
	}

	s.monitor.AccountManagerCompleted(started, "generate", core.ResultSucceeded)
	return core.ResultSucceeded, pubKey, endpoints, nil
}
