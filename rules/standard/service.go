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
	"context"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the structure that keeps track of rules.
type Service struct {
	store    *Store
	adminIPs []string
}

// log is a module-wide log.
var log zerolog.Logger

// New creates new rules.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "rules").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	store, err := NewStore(parameters.storagePath)
	if err != nil {
		return nil, err
	}

	s := &Service{
		store:    store,
		adminIPs: parameters.adminIPs,
	}

	// Close the store when the context is cancelled.
	go func() {
		<-ctx.Done()
		if err := s.Close(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to cleanly close rules storage")
		} else {
			log.Info().Msg("Closed rules storage")
		}
	}()

	return s, nil
}

// Close closes the database for the persistent rules information.
func (s *Service) Close(ctx context.Context) error {
	return s.store.Close(ctx)
}

var (
	// actionSign is the action of signing data.
	// currently unused as generic signing requires no slashing protection.
	// actionSign = []byte{0x01}
	// actionSignBeaconAttestation is the action of signing a beacon attestation.
	actionSignBeaconAttestation = []byte{0x02}
	// actionSignBeaconProposal is the action of signing a beacon proposal.
	actionSignBeaconProposal = []byte{0x03}
	// actionAccessAccount is the action of accessing an account.
	// currently unused as accesing an account requires no slashing protection.
	//nolint:godot
	// actionAccessAccount = []byte{0x04}
)
