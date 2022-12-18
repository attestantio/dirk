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
	"sync"
	"time"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/attestantio/dirk/util"
	spec "github.com/attestantio/go-eth2-client/spec/phase0"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// SignBeaconAttestations signs multiple attestations for a beacon block.
func (s *Service) SignBeaconAttestations(
	ctx context.Context,
	credentials *checker.Credentials,
	accountNames []string,
	pubKeys [][]byte,
	data []*rules.SignBeaconAttestationData,
) (
	[]core.Result,
	[][]byte,
) {
	ctx, span := otel.Tracer("attestantio.dirk.services.signer.standard").Start(ctx, "SignBeaconAttestations")
	defer span.End()
	started := time.Now()

	if len(data) == 0 {
		log.Warn().Str("result", "denied").Msg("Request empty")
		span.SetStatus(codes.Error, "Request empty")
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		results := make([]core.Result, 1)
		results[0] = core.ResultDenied
		return results, nil
	}

	results := make([]core.Result, len(data))
	for i := range results {
		results[i] = core.ResultUnknown
	}

	if credentials == nil {
		log.Error().Msg("No credentials supplied")
		for i := range results {
			results[i] = core.ResultDenied
		}
		return results, nil
	}
	span.SetAttributes(attribute.String("client", credentials.Client))

	log := log.With().
		Str("request_id", credentials.RequestID).
		Str("client", credentials.Client).
		Str("action", "SignBeaconAttestations").
		Logger()
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Starting signing process")
	signatures := make([][]byte, len(data))

	if err := s.checkAttestationsData(data, accountNames, pubKeys, results); err != nil {
		log.Warn().Str("result", "denied").Msgf("Attestations data check failed: %s", err.Error())
		s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
		return results, nil
	}

	log.Trace().Dur("elapsed", time.Since(started)).Msg("Data checked")

	// We could have either or both of account names and/or entries, so take the longer
	entries := len(pubKeys)
	if len(accountNames) > entries {
		entries = len(accountNames)
	}
	span.SetAttributes(attribute.Int("requests", entries))
	rulesData := make([]*ruler.RulesData, entries)
	accounts := make([]e2wtypes.Account, entries)
	_, err := util.Scatter(entries, func(offset int, entries int, _ *sync.RWMutex) (interface{}, error) {
		for i := offset; i < offset+entries; i++ {
			var pubKey []byte
			if len(pubKeys) > i {
				pubKey = pubKeys[i]
			}

			var accountName string
			if len(accountNames) > i {
				accountName = accountNames[i]
			}

			wallet, account, checkRes := s.preCheck(ctx, credentials, accountName, pubKey, ruler.ActionSignBeaconAttestation)
			if checkRes != core.ResultSucceeded {
				s.monitor.SignCompleted(started, "attestation", checkRes)
				results[i] = checkRes
				continue
			}
			rulesData[i] = &ruler.RulesData{
				WalletName:  wallet.Name(),
				AccountName: account.Name(),
				PubKey:      account.PublicKey().Marshal(),
				Data:        data[i],
			}
			accounts[i] = account
		}
		return nil, nil
	})
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to scatter check")
	}
	for i := range results {
		if results[i] != core.ResultUnknown && results[i] != core.ResultSucceeded {
			s.monitor.SignCompleted(started, "generic", results[i])
			return results, nil
		}
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Completed precheck")

	// Confirm approval via rules.
	rulesResults := s.ruler.RunRules(ctx, credentials, ruler.ActionSignBeaconAttestation, rulesData)
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Completed rules")

	// Carry out the signing.
	_, err = util.Scatter(len(rulesResults), func(offset int, entries int, _ *sync.RWMutex) (interface{}, error) {
		for i := offset; i < offset+entries; i++ {
			switch rulesResults[i] {
			case rules.UNKNOWN:
				log.Debug().Str("result", "failed").Msg("Unknown result from rules")
				s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
				results[i] = core.ResultFailed
				continue
			case rules.DENIED:
				log.Debug().Str("result", "denied").Msg("Denied by rules")
				s.monitor.SignCompleted(started, "attestation", core.ResultDenied)
				results[i] = core.ResultDenied
				continue
			case rules.FAILED:
				log.Error().Str("result", "failed").Msg("Rules check failed")
				s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
				results[i] = core.ResultFailed
				continue
			case rules.APPROVED:
				// Nothing to do.
			}

			// Create a spec version of the attestation to obtain its hash tree root.
			attestation := &spec.AttestationData{
				Slot:  spec.Slot(data[i].Slot),
				Index: spec.CommitteeIndex(data[i].CommitteeIndex),
				Source: &spec.Checkpoint{
					Epoch: spec.Epoch(data[i].Source.Epoch),
				},
				Target: &spec.Checkpoint{
					Epoch: spec.Epoch(data[i].Target.Epoch),
				},
			}
			copy(attestation.BeaconBlockRoot[:], data[i].BeaconBlockRoot)
			copy(attestation.Source.Root[:], data[i].Source.Root)
			copy(attestation.Target.Root[:], data[i].Target.Root)
			dataRoot, err := attestation.HashTreeRoot()
			if err != nil {
				log.Error().Err(err).Str("result", "failed").Msg("Failed to generate data root")
				s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
				results[i] = core.ResultFailed
				continue
			}
			signingRoot, err := generateSigningRoot(ctx, dataRoot[:], data[i].Domain)
			if err != nil {
				log.Error().Err(err).Str("result", "failed").Msg("Failed to generate signing root")
				s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
				results[i] = core.ResultFailed
				continue
			}

			// Sign it.
			signature, err := signRoot(ctx, accounts[i], signingRoot[:])
			if err != nil {
				log.Error().Err(err).Str("result", "failed").Msg("Failed to sign")
				s.monitor.SignCompleted(started, "attestation", core.ResultFailed)
				results[i] = core.ResultFailed
				continue
			}

			log.Trace().Str("result", "succeeded").Msg("Success")
			s.monitor.SignCompleted(started, "attestation", core.ResultSucceeded)
			results[i] = core.ResultSucceeded
			signatures[i] = signature
		}
		return nil, nil
	})
	if err != nil {
		log.Error().Err(err).Str("result", "failed").Msg("Failed to scatter sign")
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Completed signing")

	return results, signatures
}

func (s *Service) checkAttestationsData(data []*rules.SignBeaconAttestationData,
	accountNames []string,
	pubKeys [][]byte,
	results []core.Result,
) error {
	// Check input.
	for i := range data {
		if data[i] == nil {
			results[i] = core.ResultDenied
			return fmt.Errorf("request %d missing data", i)
		}
		if data[i].BeaconBlockRoot == nil {
			results[i] = core.ResultDenied
			return fmt.Errorf("request %d missing beacon block root", i)
		}
		if data[i].Domain == nil {
			results[i] = core.ResultDenied
			return fmt.Errorf("request %d missing domain", i)
		}
		if data[i].Source == nil {
			results[i] = core.ResultDenied
			return fmt.Errorf("request %d missing source", i)
		}
		if data[i].Source.Root == nil {
			results[i] = core.ResultDenied
			return fmt.Errorf("request %d missing source root", i)
		}
		if data[i].Target == nil {
			results[i] = core.ResultDenied
			return fmt.Errorf("request %d missing target", i)
		}
		if data[i].Target.Root == nil {
			results[i] = core.ResultDenied
			return fmt.Errorf("request %d missing target root", i)
		}

		if e := log.Trace(); e.Enabled() {
			e.Int("position", i).
				Str("domain", fmt.Sprintf("%#x", data[i].Domain)).
				Str("block_root", fmt.Sprintf("%#x", data[i].BeaconBlockRoot)).
				Uint64("slot", data[i].Slot).
				Uint64("committee_index", data[i].CommitteeIndex).
				Str("source_root", fmt.Sprintf("%#x", data[i].Source.Root)).
				Str("source_root", fmt.Sprintf("%#x", data[i].Source.Root)).
				Uint64("source_epoch", data[i].Source.Epoch).
				Str("target_root", fmt.Sprintf("%#x", data[i].Target.Root)).
				Uint64("target_epoch", data[i].Target.Epoch)
			if len(accountNames) > i && len(accountNames[i]) > 0 {
				e.Str("account", accountNames[i])
			}
			if len(pubKeys) > i && len(pubKeys[i]) > 0 {
				e.Str("pubkey", fmt.Sprintf("%#x", pubKeys[i]))
			}
			e.Msg("Data to sign")
		}
	}
	return nil
}
