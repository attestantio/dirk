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

package signer

import (
	context "context"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/checker"
)

// Service is the signer service.
type Service interface {
	// SignGeneric signs generic data.
	SignGeneric(ctx context.Context,
		credentials *checker.Credentials,
		accountName string,
		pubKey []byte,
		data *rules.SignData) (core.Result, []byte)

	// SignBeaconAttestation signs a beacon attestation.
	SignBeaconAttestation(ctx context.Context,
		credentials *checker.Credentials,
		accountName string,
		pubKey []byte,
		data *rules.SignBeaconAttestationData) (core.Result, []byte)

	// SignBeaconAttestations signs multiple beacon attestations.
	SignBeaconAttestations(ctx context.Context,
		credentials *checker.Credentials,
		accountName []string,
		pubKey [][]byte,
		data []*rules.SignBeaconAttestationData) ([]core.Result, [][]byte)

	// SignBeaconProposal signs a proposal for a beacon block.
	SignBeaconProposal(ctx context.Context,
		credentials *checker.Credentials,
		accountName string,
		pubKey []byte,
		data *rules.SignBeaconProposalData) (core.Result, []byte)
}
