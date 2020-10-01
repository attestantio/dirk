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
	"bytes"
	"context"
	"encoding/gob"

	"github.com/attestantio/dirk/rules"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

type signBeaconProposalState struct {
	Slot int64
}

// OnSignBeaconProposal is called when a request to sign a beacon block proposal needs to be approved.
func (s *Service) OnSignBeaconProposal(ctx context.Context, metadata *rules.ReqMetadata, req *rules.SignBeaconProposalData) rules.Result {
	span, _ := opentracing.StartSpanFromContext(ctx, "rules.OnSignBeaconProposal")
	defer span.Finish()
	log := log.With().Str("client", metadata.Client).Str("account", metadata.Account).Str("rule", "sign beacon proposal").Logger()

	// The request must have the appropriate domain.
	if !bytes.Equal(req.Domain[0:4], e2types.DomainBeaconProposer[:]) {
		log.Warn().Msg("Not approving non-beacon proposal due to incorrect domain")
		return rules.DENIED
	}

	// Fetch state from previous signings.
	state, err := s.fetchSignBeaconProposalState(ctx, metadata.PubKey)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch state for beacon proposal")
		return rules.FAILED
	}
	slot := req.Slot

	if state.Slot != -1 {
		// The request slot must be greater than the previous request slot.
		if int64(slot) <= state.Slot {
			log.Warn().
				Int64("previousSlot", state.Slot).
				Uint64("slot", slot).
				Msg("Request slot equal to or lower than previous signed slot")
			return rules.DENIED
		}
	}

	state.Slot = int64(slot)
	if err = s.storeSignBeaconProposalState(ctx, metadata.PubKey, state); err != nil {
		log.Error().Err(err).Msg("Failed to store state for beacon proposal")
		return rules.FAILED
	}

	return rules.APPROVED
}

func (s *Service) fetchSignBeaconProposalState(ctx context.Context, pubKey []byte) (*signBeaconProposalState, error) {
	state := &signBeaconProposalState{
		Slot: -1,
	}
	key := make([]byte, len(pubKey)+len(actionSignBeaconProposal))
	copy(key, pubKey)
	copy(key[len(pubKey):], actionSignBeaconProposal)
	data, err := s.store.Fetch(ctx, key)
	if err == nil {
		buf := bytes.NewBuffer(data)
		dec := gob.NewDecoder(buf)
		err = dec.Decode(&state)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode state")
		}
	} else if err.Error() != "not found" {
		return nil, err
	}
	return state, nil
}

func (s *Service) storeSignBeaconProposalState(ctx context.Context, pubKey []byte, state *signBeaconProposalState) error {
	key := make([]byte, len(pubKey)+len(actionSignBeaconProposal))
	copy(key, pubKey)
	copy(key[len(pubKey):], actionSignBeaconProposal)
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(state); err != nil {
		return err
	}
	value := buf.Bytes()
	return s.store.Store(ctx, key, value)
}
