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

package sender

import (
	"context"

	"github.com/attestantio/dirk/core"
	"github.com/herumi/bls-eth-go-binary/bls"
)

// Service is the interface for a DKG sender.
type Service interface {
	// Prepare sends a request to the given participant to prepare for DKG.
	Prepare(ctx context.Context,
		recipient *core.Endpoint,
		account string,
		passphrase []byte,
		threshold uint32,
		participants []*core.Endpoint) error
	// Execute sends a request to the given participant to execute the given DKG.
	Execute(ctx context.Context, recipient *core.Endpoint, account string) error
	// Commit sends a request to the given participant to commit the given DKG.
	Commit(ctx context.Context, recipient *core.Endpoint, account string, confirmationData []byte) ([]byte, []byte, error)
	// Abort sends a request to the given participant to abort the given DKG.
	Abort(ctx context.Context, recipient *core.Endpoint, account string) error
	// SendContribution sends a contribution to a recipient.
	SendContribution(ctx context.Context, recipient *core.Endpoint, account string, distributionSecret bls.SecretKey, verificationVector []bls.PublicKey) (bls.SecretKey, []bls.PublicKey, error)
}
