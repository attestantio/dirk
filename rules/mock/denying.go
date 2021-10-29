// Copyright © 2021 Attestant Limited.
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

	"github.com/attestantio/dirk/rules"
)

type denyingService struct{}

// NewDenying creates a mock rules service that denies all requests.
func NewDenying() rules.Service {
	return &denyingService{}
}

// Name provides the name of the service.
func (s *denyingService) Name() string {
	return "denying"
}

// OnCreateAccount is called when a request to create an account needs to be approved.
func (s *denyingService) OnCreateAccount(ctx context.Context, metadata *rules.ReqMetadata, req *rules.CreateAccountData) rules.Result {
	return rules.DENIED
}

// OnListAccounts is called when a request to list accounts needs to be approved.
func (s *denyingService) OnListAccounts(ctx context.Context, metadata *rules.ReqMetadata, req *rules.AccessAccountData) rules.Result {
	return rules.DENIED
}

// OnLockAccount is called when a request to lock an account needs to be approved.
func (s *denyingService) OnLockAccount(ctx context.Context, metadata *rules.ReqMetadata, req *rules.LockAccountData) rules.Result {
	return rules.DENIED
}

// OnLockWallet is called when a request to lock a wallet needs to be approved.
func (s *denyingService) OnLockWallet(ctx context.Context, metadata *rules.ReqMetadata, req *rules.LockWalletData) rules.Result {
	return rules.DENIED
}

// OnSignBeaconAttestation is called when a request to sign a beacon block attestation needs to be approved.
func (s *denyingService) OnSignBeaconAttestation(ctx context.Context, metadata *rules.ReqMetadata, req *rules.SignBeaconAttestationData) rules.Result {
	return rules.DENIED
}

// OnSignBeaconAttestations is called when a request to sign multiple beacon block attestations needs to be approved.
func (s *denyingService) OnSignBeaconAttestations(ctx context.Context,
	metadata []*rules.ReqMetadata,
	req []*rules.SignBeaconAttestationData,
) []rules.Result {
	results := make([]rules.Result, len(req))
	for i := range req {
		results[i] = rules.DENIED
	}

	return results
}

// OnSignBeaconProposal is called when a request to sign a beacon block proposal needs to be approved.
func (s *denyingService) OnSignBeaconProposal(ctx context.Context, metadata *rules.ReqMetadata, req *rules.SignBeaconProposalData) rules.Result {
	return rules.DENIED
}

// OnSign is called when a request to sign generic data needs to be approved.
func (s *denyingService) OnSign(ctx context.Context, metadata *rules.ReqMetadata, req *rules.SignData) rules.Result {
	return rules.DENIED
}

// ExportSlashingProtection exports the slashing protection data.
func (s *denyingService) ExportSlashingProtection(ctx context.Context) (map[[48]byte]*rules.SlashingProtection, error) {
	return nil, nil
}

// ImportSlashingProtection impports the slashing protection data.
func (s *denyingService) ImportSlashingProtection(ctx context.Context, protection map[[48]byte]*rules.SlashingProtection) error {
	return nil
}

// OnUnlockAccount is called when a request to unlock an account needs to be approved.
func (s *denyingService) OnUnlockAccount(ctx context.Context, metadata *rules.ReqMetadata, req *rules.UnlockAccountData) rules.Result {
	return rules.DENIED
}

// OnUnlockWallet is called when a request to unlock a wallet needs to be approved.
func (s *denyingService) OnUnlockWallet(ctx context.Context, metadata *rules.ReqMetadata, req *rules.UnlockWalletData) rules.Result {
	return rules.DENIED
}
