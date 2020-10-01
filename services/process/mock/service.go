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

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/peers"
	"github.com/attestantio/dirk/services/sender"
	"github.com/herumi/bls-eth-go-binary/bls"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Config is the configuration for the mock process service.
type Config struct {
	CheckerSvc           checker.Service
	SenderSvc            sender.Service
	PeersSvc             *peers.Service
	ID                   uint64
	Endpoints            map[uint64]string
	Stores               []e2wtypes.Store
	GenerationPassphrase []byte
}

// Service is a mock service for distributed key generation.
type Service struct {
}

// New creates a new process service.
func New() (*Service, error) {
	return &Service{}, nil
}

// OnPrepare is called when we receive a request from the given participant to prepare for DKG.
func (s *Service) OnPrepare(ctx context.Context, sender uint64, account string, passphrase []byte, threshold uint32, participants []*core.Endpoint) error {
	return nil
}

// OnExecute is called when we receive a request from the given participant to execute the given DKG.
func (s *Service) OnExecute(ctx context.Context, sender uint64, account string) error {
	return nil
}

// OnCommit is called when we receive a request from the given participant to commit the given DKG.
func (s *Service) OnCommit(ctx context.Context, sender uint64, account string, confirmationData []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}

// OnAbort is called when we receive a request from the given participant to abort the given DKG.
func (s *Service) OnAbort(ctx context.Context, sender uint64, account string) error {
	return nil
}

// OnGenerate is called when an request to generate a new key is received.
func (s *Service) OnGenerate(ctx context.Context, credentials *checker.Credentials, account string, passphrase []byte, threshold uint32, numParticipants uint32) ([]byte, []*core.Endpoint, error) {
	return nil, []*core.Endpoint{
		{
			ID:   1,
			Name: "server-1",
			Port: 10001,
		},
		{
			ID:   2,
			Name: "server-2",
			Port: 10002,
		},
	}, nil
}

// OnContribute is is called when we need to swap contributions with another participant.
func (s *Service) OnContribute(ctx context.Context, sender uint64, account string, secret bls.SecretKey, vVec []bls.PublicKey) (bls.SecretKey, []bls.PublicKey, error) {
	return bls.SecretKey{}, nil, nil
}
