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
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// SignBeaconProposal signs a proposal for a beacon block.
func (s *Service) SignBeaconProposal(
	ctx context.Context,
	credentials *checker.Credentials,
	accountName string,
	pubKey []byte,
	data *rules.SignBeaconProposalData,
) (
	core.Result,
	[]byte,
) {
	ctx, span := otel.Tracer("attestantio.dirk.services.signer.standard").Start(ctx, "SignBeaconProposal")
	defer span.End()
	started := time.Now()

	if credentials == nil {
		log.Warn().Msg("No credentials supplied")
		return core.ResultFailed, nil
	}
	span.SetAttributes(attribute.String("client", credentials.Client))

	log := log.With().
		Str("request_id", credentials.RequestID).
		Str("action", "SignBeaconProposal").
		Str("client", credentials.Client).
		Logger()
	log.Trace().Msg("Signing")

	// Check input.
	if data == nil {
		log.Warn().Str("result", "denied").Msg("Request missing data")
		s.monitor.SignCompleted(started, "proposal", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Domain == nil {
		log.Warn().Str("result", "denied").Msg("Request missing domain")
		s.monitor.SignCompleted(started, "proposal", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.ParentRoot == nil {
		log.Warn().Str("result", "denied").Msg("Request missing parent root")
		s.monitor.SignCompleted(started, "proposal", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.BodyRoot == nil {
		s.monitor.SignCompleted(started, "proposal", core.ResultDenied)
		log.Warn().Str("result", "denied").Msg("Request missing body root")
		return core.ResultDenied, nil
	}
	if data.StateRoot == nil {
		s.monitor.SignCompleted(started, "proposal", core.ResultDenied)
		log.Warn().Str("result", "denied").Msg("Request missing state root")
		return core.ResultDenied, nil
	}

	if e := log.Trace(); e.Enabled() {
		e.Str("domain", fmt.Sprintf("%#x", data.Domain)).
			Uint64("slot", data.Slot).
			Uint64("proposer_index", data.ProposerIndex).
			Str("parent_root", fmt.Sprintf("%#x", data.ParentRoot)).
			Str("state_root", fmt.Sprintf("%#x", data.StateRoot)).
			Str("body_root", fmt.Sprintf("%#x", data.BodyRoot))
		if len(accountName) > 0 {
			e.Str("account", accountName)
		}
		if len(pubKey) > 0 {
			e.Str("pubkey", fmt.Sprintf("%#x", pubKey))
		}
		e.Msg("Data to sign")
	}

	wallet, account, checkRes := s.preCheck(ctx, credentials, accountName, pubKey, ruler.ActionSignBeaconProposal)
	if checkRes != core.ResultSucceeded {
		s.monitor.SignCompleted(started, "proposal", checkRes)
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
	results := s.ruler.RunRules(ctx, credentials, ruler.ActionSignBeaconProposal, rulesData)
	switch results[0] {
	case rules.DENIED:
		log.Debug().Str("result", "denied").Msg("Denied by rules")
		s.monitor.SignCompleted(started, "proposal", core.ResultDenied)
		return core.ResultDenied, nil
	case rules.FAILED:
		log.Error().Str("result", "failed").Msg("Rules check failed")
		s.monitor.SignCompleted(started, "proposal", core.ResultFailed)
		return core.ResultFailed, nil
	case rules.UNKNOWN:
		log.Error().Str("result", "failed").Msg("Rules check indeterminate result")
		s.monitor.SignCompleted(started, "proposal", core.ResultFailed)
		return core.ResultFailed, nil
	case rules.APPROVED:
		//  Nothing to do.
	}

	// Create a spec version of the beacon block header to obtain its hash tree root.
	blockHeader := &spec.BeaconBlockHeader{
		Slot:          spec.Slot(data.Slot),
		ProposerIndex: spec.ValidatorIndex(data.ProposerIndex),
	}
	copy(blockHeader.ParentRoot[:], data.ParentRoot)
	copy(blockHeader.StateRoot[:], data.StateRoot)
	copy(blockHeader.BodyRoot[:], data.BodyRoot)
	dataRoot, err := blockHeader.HashTreeRoot()
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to generate data root")
		s.monitor.SignCompleted(started, "proposal", core.ResultFailed)
		return core.ResultFailed, nil
	}
	signingRoot, err := generateSigningRoot(ctx, dataRoot[:], data.Domain)
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to generate signing root")
		s.monitor.SignCompleted(started, "proposal", core.ResultFailed)
		return core.ResultFailed, nil
	}

	// Sign it.
	signature, err := signRoot(ctx, account, signingRoot[:])
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to sign")
		s.monitor.SignCompleted(started, "proposal", core.ResultFailed)
		return core.ResultFailed, nil
	}

	log.Trace().Str("result", "succeeded").Msg("Success")
	s.monitor.SignCompleted(started, "proposal", core.ResultSucceeded)
	return core.ResultSucceeded, signature
}
