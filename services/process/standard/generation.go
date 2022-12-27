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
	"time"

	"github.com/attestantio/dirk/core"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
)

// ErrNotFound is returned when a generation is not found.
var ErrNotFound = errors.New("not found")

// ErrInProgress is returned when a generation is in progress.
var ErrInProgress = errors.New("in progress")

// ErrNotInProgress is returned when a generation is not in progress.
var ErrNotInProgress = errors.New("not in progress")

// ErrNotCreated is returned when a key is not created.
var ErrNotCreated = errors.New("not created")

// generation holds information about a generation activity.
type generation struct {
	// Metadata.
	processStarted time.Time
	id             uint64

	// Information about the key to generate.
	account      string
	passphrase   []byte
	threshold    uint32
	participants []*core.Endpoint

	// Secrets to distribute to each participant.
	distributionSecrets map[uint64]bls.SecretKey

	// Information from each participant (including us).
	sharedSecrets map[uint64]bls.SecretKey
	sharedVVecs   map[uint64][]bls.PublicKey
}

// getGeneration fetches an active generation.
// This assumes that a write lock is already held on generationsMu.
func (s *Service) getGeneration(ctx context.Context, account string) (*generation, error) {
	span, _ := opentracing.StartSpanFromContext(ctx, "services.process.getGeneration")
	defer span.Finish()

	generator, exists := s.generations[account]
	if !exists {
		return nil, ErrNotFound
	}

	// Generations more than 180 seconds old need to be removed.
	if time.Since(generator.processStarted) > 180*time.Second {
		// Been too long; remove it.
		log.Debug().Str("account", account).Msg("Generation been active too long; invalidating")
		delete(s.generations, account)
		return nil, ErrNotFound
	}

	return generator, nil
}
