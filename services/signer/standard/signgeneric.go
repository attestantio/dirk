// Copyright © 2020, 2022 Attestant Limited.
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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
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
	ctx, span := otel.Tracer("attestantio.dirk.services.signer.standard").Start(ctx, "SignGeneric")
	defer span.End()
	started := time.Now()

	if credentials == nil {
		log.Error().Msg("No credentials supplied")
		return core.ResultFailed, nil
	}
	span.SetAttributes(attribute.String("client", credentials.Client))

	log := log.With().
		Str("request_id", credentials.RequestID).
		Str("action", "SignGeneric").
		Str("client", credentials.Client).
		Logger()
	log.Trace().Msg("Request received")

	// Check input.
	if data == nil {
		log.Warn().Str("result", "denied").Msg("Request empty")
		span.SetStatus(codes.Error, "Request empty")
		s.monitor.SignCompleted(started, "generic", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Data == nil {
		log.Warn().Str("result", "denied").Msg("Request missing data")
		span.SetStatus(codes.Error, "Request missing data")
		s.monitor.SignCompleted(started, "generic", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Domain == nil {
		log.Warn().Str("result", "denied").Msg("Request missing domain")
		span.SetStatus(codes.Error, "Request missing domain")
		s.monitor.SignCompleted(started, "generic", core.ResultDenied)
		return core.ResultDenied, nil
	}

	if e := log.Trace(); e.Enabled() {
		e.Str("domain", fmt.Sprintf("%#x", data.Domain)).
			Str("data", fmt.Sprintf("%#x", data.Data))
		if len(accountName) > 0 {
			e.Str("account", accountName)
		}
		if len(pubKey) > 0 {
			e.Str("pubkey", fmt.Sprintf("%#x", pubKey))
		}
		e.Msg("Data to sign")
	}

	wallet, account, checkRes := s.preCheck(ctx, credentials, accountName, pubKey, ruler.ActionSign)
	if checkRes != core.ResultSucceeded {
		s.monitor.SignCompleted(started, "generic", checkRes)
		span.SetStatus(codes.Ok, "")
		return checkRes, nil
	}
	accountName = fmt.Sprintf("%s/%s", wallet.Name(), account.Name())
	span.SetAttributes(attribute.String("account", accountName))
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
		span.SetStatus(codes.Ok, "")
		log.Debug().Str("result", "denied").Msg("Denied by rules")
		return core.ResultDenied, nil
	case rules.FAILED:
		s.monitor.SignCompleted(started, "generic", core.ResultFailed)
		span.SetStatus(codes.Ok, "")
		log.Error().Str("result", "failed").Msg("Rules check failed")
		return core.ResultFailed, nil
	case rules.UNKNOWN:
		s.monitor.SignCompleted(started, "generic", core.ResultFailed)
		span.SetStatus(codes.Ok, "")
		log.Error().Str("result", "failed").Msg("Rules check indeterminate result")
		return core.ResultFailed, nil
	case rules.APPROVED:
		// Nothing to do.
	}

	signingRoot, err := generateSigningRoot(ctx, data.Data, data.Domain)
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to generate signing root")
		span.SetStatus(codes.Error, "Failed to generate signing root")
		s.monitor.SignCompleted(started, "generic", core.ResultFailed)
		return core.ResultFailed, nil
	}

	// Sign it.
	signature, err := signRoot(ctx, account, signingRoot[:])
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to sign")
		span.SetStatus(codes.Error, "Failed to sign")
		s.monitor.SignCompleted(started, "generic", core.ResultFailed)
		return core.ResultFailed, nil
	}

	log.Trace().Str("result", "succeeded").Msg("Success")
	span.SetStatus(codes.Ok, "")
	s.monitor.SignCompleted(started, "generic", core.ResultSucceeded)
	return core.ResultSucceeded, signature
}
