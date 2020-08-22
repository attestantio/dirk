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

package mock

import (
	"context"
	"fmt"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/testing/mock"
	"github.com/herumi/bls-eth-go-binary/bls"
)

type Service struct {
	id uint64
}

func New(id uint64) *Service {
	return &Service{
		id: id,
	}
}

// Prepare sends a request to the given participant to prepare for DKG.
func (s *Service) Prepare(ctx context.Context, recipient *core.Endpoint, account string, passphrase []byte, threshold uint32, participants []*core.Endpoint) error {
	process, exists := mock.Processes[recipient.ID]
	if !exists {
		return fmt.Errorf("unknown mock process %d", recipient.ID)
	}
	return process.OnPrepare(ctx, s.id, account, passphrase, threshold, participants)
}

// Execute sends a request to the given participant to execute the given DKG.
func (s *Service) Execute(ctx context.Context, recipient *core.Endpoint, account string) error {
	process, exists := mock.Processes[recipient.ID]
	if !exists {
		return fmt.Errorf("unknown mock process %d", recipient.ID)
	}
	return process.OnExecute(ctx, s.id, account)
}

// Commit sends a request to the given participant to commit the given DKG.
func (s *Service) Commit(ctx context.Context, recipient *core.Endpoint, account string, confirmationData []byte) ([]byte, []byte, error) {
	process, exists := mock.Processes[recipient.ID]
	if !exists {
		return nil, nil, fmt.Errorf("unknown mock process %d", recipient.ID)
	}
	return process.OnCommit(ctx, s.id, account, confirmationData)
}

// Abort sends a request to the given participant to abort the given DKG.
func (s *Service) Abort(ctx context.Context, recipient *core.Endpoint, account string) error {
	process, exists := mock.Processes[recipient.ID]
	if !exists {
		return fmt.Errorf("unknown mock process %d", recipient.ID)
	}
	return process.OnAbort(ctx, s.id, account)
}

// SendContribution sends a contribution to a recipient.
func (s *Service) SendContribution(ctx context.Context, recipient *core.Endpoint, account string, distributionSecret bls.SecretKey, verificationVector []bls.PublicKey) (bls.SecretKey, []bls.PublicKey, error) {
	process, exists := mock.Processes[recipient.ID]
	if !exists {
		return bls.SecretKey{}, nil, fmt.Errorf("unknown mock process %d", recipient.ID)
	}
	return process.OnContribute(ctx, s.id, account, distributionSecret, verificationVector)
}
