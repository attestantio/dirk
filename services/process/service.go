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

package process

import (
	"context"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/checker"
	"github.com/herumi/bls-eth-go-binary/bls"
)

// Service is the interface for a DKG process.
type Service interface {
	// OnPrepare is called when we receive a request from the given participant to prepare for DKG.
	OnPrepare(ctx context.Context, sender uint64, account string, passphrase []byte, threshold uint32, participants []*core.Endpoint) error

	// OnExecute is called when we receive a request from the given participant to execute the given DKG.
	OnExecute(ctx context.Context, sender uint64, account string) error

	// OnCommit is called when we receive a request from the given participant to commit the given DKG.
	OnCommit(ctx context.Context, sender uint64, account string, confirmationData []byte) ([]byte, []byte, error)

	// OnAbort is called when we receive a request from the given participant to abort the given DKG.
	OnAbort(ctx context.Context, sender uint64, account string) error

	// OnGenerate is called when an request to generate a new key is received.
	OnGenerate(ctx context.Context, credentials *checker.Credentials, account string, passphrase []byte, threshold uint32, numParticipants uint32) ([]byte, []*core.Endpoint, error)

	// OnContribute is called when we need to swap contributions with another participant.
	OnContribute(ctx context.Context, sender uint64, account string, secret bls.SecretKey, vVec []bls.PublicKey) (bls.SecretKey, []bls.PublicKey, error)
}
