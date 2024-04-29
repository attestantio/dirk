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
	"encoding/binary"
	"encoding/gob"
	"fmt"

	"github.com/attestantio/dirk/rules"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

type signBeaconProposalState struct {
	Slot int64
}

// Encode encodes the proposal state.
func (s *signBeaconProposalState) Encode() []byte {
	data := make([]byte, 1+8)
	// Version.
	data[0] = 0x01

	if s != nil {
		// Slot.
		binary.LittleEndian.PutUint64(data[1:9], uint64(s.Slot))
	}

	return data
}

// Decode decodes the proposal state.
func (s *signBeaconProposalState) Decode(data []byte) error {
	var err error
	if len(data) == 0 {
		return errors.New("no data supplied")
	}
	switch data[0] {
	case 0x01:
		if len(data) != 9 {
			return fmt.Errorf("invalid version 1 data size %d", len(data))
		}
		s.Slot = int64(binary.LittleEndian.Uint64(data[1:9]))
	default:
		err = gob.NewDecoder(bytes.NewBuffer(data)).Decode(s)
	}

	return err
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
	state := &signBeaconProposalState{}
	key := make([]byte, len(pubKey)+len(actionSignBeaconProposal))
	copy(key, pubKey)
	copy(key[len(pubKey):], actionSignBeaconProposal)
	data, err := s.store.Fetch(ctx, key)
	if err != nil {
		if err.Error() != "not found" {
			return nil, err
		}
		// No value; set it to -1.
		state.Slot = -1
	} else {
		err = state.Decode(data)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode state")
		}
	}

	log.Trace().Int64("slot", state.Slot).Msg("Returning proposal state from store")

	return state, nil
}

func (s *Service) storeSignBeaconProposalState(ctx context.Context, pubKey []byte, state *signBeaconProposalState) error {
	key := make([]byte, len(pubKey)+len(actionSignBeaconProposal))
	copy(key, pubKey)
	copy(key[len(pubKey):], actionSignBeaconProposal)

	err := s.store.Store(ctx, key, state.Encode())
	if err != nil {
		return err
	}

	log.Trace().Int64("slot", state.Slot).Msg("Stored proposal state to store")

	return nil
}
