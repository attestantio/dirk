// Copyright © 2020, 2021 Attestant Limited.
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
	"errors"
	"fmt"
	"time"

	"github.com/attestantio/dirk/rules"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

// OnSignBeaconAttestations is called when a request to sign multiple beacon block attestations needs to be approved.
func (s *Service) OnSignBeaconAttestations(ctx context.Context,
	metadata []*rules.ReqMetadata,
	req []*rules.SignBeaconAttestationData,
) []rules.Result {
	started := time.Now()

	res := make([]rules.Result, len(req))
	for i := range res {
		res[i] = rules.UNKNOWN
	}

	if len(req) != len(metadata) {
		log.Error().Int("reqs", len(req)).Int("metadatas", len(metadata)).Msg("Mismatch between number of requests and number of metadata entries")
		for i := range res {
			res[i] = rules.FAILED
		}
		return res
	}

	for i := range metadata {
		if metadata[i] == nil {
			log.Error().Int("index", i).Msg("Nil metadata entry")
			res[i] = rules.FAILED
			return res
		}
	}

	for i := range req {
		if req[i] == nil {
			log.Error().Int("index", i).Msg("Nil req entry")
			res[i] = rules.FAILED
			return res
		}
		if req[i].Source == nil {
			log.Error().Int("index", i).Msg("Nil req source")
			res[i] = rules.FAILED
			return res
		}
		if req[i].Target == nil {
			log.Error().Int("index", i).Msg("Nil req target")
			res[i] = rules.FAILED
			return res
		}
	}

	pubKeys := make([][]byte, len(metadata))
	for i := range metadata {
		pubKeys[i] = metadata[i].PubKey
	}

	// Fetch state from previous signings.
	states, err := s.fetchSignBeaconAttestationStates(ctx, pubKeys)
	if err != nil {
		log.Error().Err(err).Msg("Failed to fetch state for beacon attestations")
		for i := range res {
			res[i] = rules.FAILED
		}
		return res
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Fetched states")

	// Run the rules.
	for i := range req {
		res[i] = s.runSignBeaconAttestationChecks(ctx, metadata[i], req[i], states[i])
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Checked rules")

	// Update the state
	if err = s.storeSignBeaconAttestationStates(ctx, pubKeys, states); err != nil {
		log.Error().Err(err).Msg("Failed to store state for beacon attestations")
		for i := range res {
			res[i] = rules.FAILED
		}
		return res
	}
	log.Trace().Dur("elapsed", time.Since(started)).Msg("Stored states")

	return res
}

func (s *Service) fetchSignBeaconAttestationStates(ctx context.Context, pubKeys [][]byte) ([]*signBeaconAttestationState, error) {
	states := make([]*signBeaconAttestationState, len(pubKeys))
	var err error
	for i := range pubKeys {
		states[i], err = s.fetchSignBeaconAttestationState(ctx, pubKeys[i])
		if err != nil {
			return nil, err
		}
	}

	return states, nil
}

func (s *Service) runSignBeaconAttestationChecks(_ context.Context, metadata *rules.ReqMetadata, req *rules.SignBeaconAttestationData, state *signBeaconAttestationState) rules.Result {
	log := log.With().Str("client", metadata.Client).Str("account", metadata.Account).Str("rule", "sign beacon attestation").Logger()

	// The request must have the appropriate domain.
	if !bytes.Equal(req.Domain[0:4], e2types.DomainBeaconAttester[:]) {
		log.Warn().Str("domain", fmt.Sprintf("%#x", req.Domain)).Msg("Not approving non-beacon attestation due to incorrect domain")
		return rules.DENIED
	}

	sourceEpoch := req.Source.Epoch
	targetEpoch := req.Target.Epoch

	// The request target epoch must be greater than the request source epoch (or both 0).
	if (sourceEpoch != 0 || targetEpoch != 0) && (targetEpoch <= sourceEpoch) {
		log.Warn().
			Uint64("sourceEpoch", sourceEpoch).
			Uint64("targetEpoch", targetEpoch).
			Msg("Request target epoch equal to or lower than request source epoch")
		return rules.DENIED
	}

	if state.TargetEpoch != -1 {
		// The request target epoch must be greater than the previous request target epoch.
		if int64(targetEpoch) <= state.TargetEpoch {
			log.Warn().
				Int64("previousTargetEpoch", state.TargetEpoch).
				Uint64("targetEpoch", targetEpoch).
				Msg("Request target epoch equal to or lower than previous signed target epoch")
			return rules.DENIED
		}
	}

	if state.SourceEpoch != -1 {
		// The request source epoch must be greater than or equal to the previous request source epoch.
		if int64(sourceEpoch) < state.SourceEpoch {
			log.Warn().
				Int64("previousSourceEpoch", state.SourceEpoch).
				Uint64("sourceEpoch", sourceEpoch).
				Msg("Request source epoch lower than previous signed source epoch")
			return rules.DENIED
		}
	}

	state.SourceEpoch = int64(sourceEpoch)
	state.TargetEpoch = int64(targetEpoch)

	return rules.APPROVED
}

func (s *Service) storeSignBeaconAttestationStates(ctx context.Context, pubKeys [][]byte, states []*signBeaconAttestationState) error {
	if len(pubKeys) != len(states) {
		return errors.New("mismatch between number of pubkeys and number of states")
	}

	keys := make([][]byte, len(pubKeys))
	values := make([][]byte, len(states))
	for i := range keys {
		keys[i] = make([]byte, len(pubKeys[i])+len(actionSignBeaconAttestation))
		copy(keys[i], pubKeys[i])
		copy(keys[i][len(pubKeys[i]):], actionSignBeaconAttestation)
		values[i] = states[i].Encode()
	}

	err := s.store.BatchStore(ctx, keys, values)
	if err != nil {
		return err
	}

	if e := log.Trace(); e.Enabled() {
		for _, state := range states {
			log.Trace().Int64("source_epoch", state.SourceEpoch).Int64("target_epoch", state.TargetEpoch).Msg("Stored attestation state to store")
		}
	}
	return nil
}
