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
)

// SignBeaconAttestation signs a attestation for a beacon block.
func (s *Service) SignBeaconAttestation(
	ctx context.Context,
	credentials *checker.Credentials,
	accountName string,
	pubKey []byte,
	data *rules.SignBeaconAttestationData,
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
		Str("client", credentials.Client).
		Str("action", "SignBeaconAttestation").
		Logger()
	log.Trace().Msg("Signing")

	// Check input.
	if data == nil {
		log.Warn().Str("result", "denied").Msg("Request missing data")
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.BeaconBlockRoot == nil {
		log.Warn().Str("result", "denied").Msg("Request missing beacon block root")
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Domain == nil {
		log.Warn().Str("result", "denied").Msg("Request missing domain")
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Source == nil {
		log.Warn().Str("result", "denied").Msg("Request missing source")
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Source.Root == nil {
		log.Warn().Str("result", "denied").Msg("Request missing source root")
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Target == nil {
		log.Warn().Str("result", "denied").Msg("Request missing target")
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		return core.ResultDenied, nil
	}
	if data.Target.Root == nil {
		log.Warn().Str("result", "denied").Msg("Request missing target root")
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		return core.ResultDenied, nil
	}

	if e := log.Trace(); e.Enabled() {
		e.Str("domain", fmt.Sprintf("%#x", data.Domain)).
			Str("block_root", fmt.Sprintf("%#x", data.BeaconBlockRoot)).
			Uint64("slot", data.Slot).
			Uint64("committee_index", data.CommitteeIndex).
			Str("source_root", fmt.Sprintf("%#x", data.Source.Root)).
			Str("source_root", fmt.Sprintf("%#x", data.Source.Root)).
			Uint64("source_epoch", data.Source.Epoch).
			Str("target_root", fmt.Sprintf("%#x", data.Target.Root)).
			Uint64("target_epoch", data.Target.Epoch)
		if len(accountName) > 0 {
			e.Str("account", accountName)
		}
		if len(pubKey) > 0 {
			e.Str("pubkey", fmt.Sprintf("%#x", pubKey))
		}
		e.Msg("Data to sign")
	}

	wallet, account, checkRes := s.preCheck(ctx, credentials, accountName, pubKey, ruler.ActionSignBeaconAttestation)
	if checkRes != core.ResultSucceeded {
		s.monitor.SignCompleted(started, "attestation", checkRes)
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
	results := s.ruler.RunRules(ctx, credentials, ruler.ActionSignBeaconAttestation, rulesData)
	switch results[0] {
	case rules.DENIED:
		log.Debug().Str("result", "denied").Msg("Denied by rules")
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		return core.ResultDenied, nil
	case rules.FAILED:
		log.Error().Str("result", "failed").Msg("Rules check failed")
		s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
		return core.ResultFailed, nil
	case rules.UNKNOWN:
		log.Error().Str("result", "failed").Msg("Rules check indeterminate result")
		s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
		return core.ResultFailed, nil
	case rules.APPROVED:
		// Nothing to do.
	}

	// Create a spec version of the attestation to obtain its hash tree root.
	attestation := &spec.AttestationData{
		Slot:  spec.Slot(data.Slot),
		Index: spec.CommitteeIndex(data.CommitteeIndex),
		Source: &spec.Checkpoint{
			Epoch: spec.Epoch(data.Source.Epoch),
		},
		Target: &spec.Checkpoint{
			Epoch: spec.Epoch(data.Target.Epoch),
		},
	}
	copy(attestation.BeaconBlockRoot[:], data.BeaconBlockRoot)
	copy(attestation.Source.Root[:], data.Source.Root)
	copy(attestation.Target.Root[:], data.Target.Root)
	dataRoot, err := attestation.HashTreeRoot()
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to generate signing root")
		s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
		return core.ResultFailed, nil
	}
	signingRoot, err := generateSigningRoot(ctx, dataRoot[:], data.Domain)
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to generate signing root")
		s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
		return core.ResultFailed, nil
	}

	// Sign it.
	signature, err := signRoot(ctx, account, signingRoot[:])
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to sign")
		s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
		return core.ResultFailed, nil
	}

	log.Trace().Str("result", "succeeded").Msg("Success")
	s.monitor.SignCompleted(started, "attestation", core.ResultSucceeded)
	return core.ResultSucceeded, signature
}
