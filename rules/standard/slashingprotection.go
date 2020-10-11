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
	"fmt"

	"github.com/attestantio/dirk/rules"
	"github.com/pkg/errors"
)

// ExportSlashingProtection exports the slashing protection data.
func (s *Service) ExportSlashingProtection(ctx context.Context) (map[[48]byte]*rules.SlashingProtection, error) {
	entries, err := s.store.FetchAll(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain data from store")
	}

	results := make(map[[48]byte]*rules.SlashingProtection)
	for key, value := range entries {
		var pubKey [48]byte
		copy(pubKey[:], key[:])
		if _, exists := results[pubKey]; !exists {
			results[pubKey] = &rules.SlashingProtection{
				PubKey:                     pubKey[:],
				HighestProposedSlot:        -1,
				HighestAttestedSourceEpoch: -1,
				HighestAttestedTargetEpoch: -1,
			}
		}
		switch key[48] {
		case actionSignBeaconAttestation[0]:
			state := &signBeaconAttestationState{
				SourceEpoch: 0,
				TargetEpoch: 0,
			}
			if err := state.Decode(value); err != nil {
				return nil, errors.Wrap(err, fmt.Sprintf("failed to decode attestation state for %#x (%x)", key, value))
			}
			results[pubKey].HighestAttestedSourceEpoch = state.SourceEpoch
			results[pubKey].HighestAttestedTargetEpoch = state.TargetEpoch
		case actionSignBeaconProposal[0]:
			state := &signBeaconProposalState{
				Slot: 0,
			}
			if err := state.Decode(value); err != nil {
				return nil, errors.Wrap(err, "failed to decode proposal state")
			}
			results[pubKey].HighestProposedSlot = state.Slot
		default:
			return nil, fmt.Errorf("unknown byte %x", key[48])
		}
	}

	return results, nil
}

// ImportSlashingProtection imports the slashing protection data.
func (s *Service) ImportSlashingProtection(ctx context.Context, protection map[[48]byte]*rules.SlashingProtection) error {
	for k, v := range protection {
		var key [49]byte
		copy(key[:], k[:])
		if v.HighestProposedSlot != -1 {
			state := &signBeaconProposalState{
				Slot: v.HighestProposedSlot,
			}
			key[48] = actionSignBeaconProposal[0]
			if err := s.store.Store(ctx, key[:], state.Encode()); err != nil {
				return errors.Wrap(err, "failed to store attestation state")
			}
		}
		if v.HighestAttestedSourceEpoch != -1 {
			state := &signBeaconAttestationState{
				SourceEpoch: v.HighestAttestedSourceEpoch,
				TargetEpoch: v.HighestAttestedTargetEpoch,
			}
			key[48] = actionSignBeaconAttestation[0]
			if err := s.store.Store(ctx, key[:], state.Encode()); err != nil {
				return errors.Wrap(err, "failed to store attestation state")
			}
		}
	}
	return nil
}
