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
	"time"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/ruler"
)

// SignGeneric signs generic data.
func (s *Service) SignGeneric(
	ctx context.Context,
	credentials *checker.Credentials,
	accountName string,
	pubKey []byte,
	data *rules.SignData,
) (
	core.Result,
	[]byte,
) {
	started := time.Now()

	if credentials == nil {
		log.Error().Msg("No credentials supplied")
		return core.ResultFailed, nil
	}

	log := log.With().
		Str("request_id", credentials.RequestID).
		Str("action", "SignGeneric").
		Str("client", credentials.Client).
		Logger()
	log.Trace().Msg("Request received")

	// Check input.
	if data == nil {
		log.Warn().Str("result", "denied").Msg("Request empty")
		s.monitor.SignCompleted(started, "generic", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Data == nil {
		log.Warn().Str("result", "denied").Msg("Request missing data")
		s.monitor.SignCompleted(started, "generic", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Domain == nil {
		log.Warn().Str("result", "denied").Msg("Request missing domain")
		s.monitor.SignCompleted(started, "generic", core.ResultDenied)
		return core.ResultDenied, nil
	}

	wallet, account, checkRes := s.preCheck(ctx, credentials, accountName, pubKey, ruler.ActionSign)
	if checkRes != core.ResultSucceeded {
		s.monitor.SignCompleted(started, "generic", checkRes)
		return checkRes, nil
	}
	accountName = fmt.Sprintf("%s/%s", wallet.Name(), account.Name())
	log = log.With().Str("account", accountName).Logger()

	// Confirm approval via rules.
	rulesData := []*ruler.RulesData{
		{
			WalletName:  wallet.Name(),
			AccountName: account.Name(),
			PubKey:      account.PublicKey().Marshal(),
			Data:        data,
		},
	}
	results := s.ruler.RunRules(ctx, credentials, ruler.ActionSign, rulesData)
	switch results[0] {
	case rules.DENIED:
		s.monitor.SignCompleted(started, "generic", core.ResultDenied)
		log.Debug().Str("result", "denied").Msg("Denied by rules")
		return core.ResultDenied, nil
	case rules.FAILED:
		s.monitor.SignCompleted(started, "generic", core.ResultFailed)
		log.Error().Str("result", "failed").Msg("Rules check failed")
		return core.ResultFailed, nil
	}

	// Sign it.
	signingRoot, err := generateSigningRootFromRoot(ctx, data.Data, data.Domain)
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to generate signing root")
		s.monitor.SignCompleted(started, "generic", core.ResultFailed)
		return core.ResultFailed, nil
	}
	signature, err := signRoot(ctx, account, signingRoot[:])
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to sign")
		s.monitor.SignCompleted(started, "generic", core.ResultFailed)
		return core.ResultFailed, nil
	}

	log.Trace().Str("result", "succeeded").Msg("Success")
	s.monitor.SignCompleted(started, "generic", core.ResultSucceeded)
	return core.ResultSucceeded, signature
}
