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

package rules

import "context"

// ReqMetadata contains request-specific metadata that can be used by the rules to help decide if a request should
// succeed or be denied.
type ReqMetadata struct {
	Account string
	PubKey  []byte
	IP      string
	Client  string
}

// SignData is passed to 'Sign' rules.
type SignData struct {
	Domain []byte
	Data   []byte
}

// SignBeaconAttestationData is passed to 'OnSignBeaconAttestation' rules.
type SignBeaconAttestationData struct {
	Domain          []byte
	Slot            uint64
	CommitteeIndex  uint64
	BeaconBlockRoot []byte
	Source          *Checkpoint
	Target          *Checkpoint
}

// Checkpoint is part of SignBeaconAttestationData.
type Checkpoint struct {
	Epoch uint64
	Root  []byte
}

// SignBeaconProposalData is passed to 'OnSignBeaconProposal' rules.
type SignBeaconProposalData struct {
	Domain        []byte
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    []byte
	StateRoot     []byte
	BodyRoot      []byte
}

// AccessAccountData is passed to 'OnAccessAccount' rules.
type AccessAccountData struct {
	Paths []string
}

// LockWalletData is passed to 'OnLockWallet' rules.
type LockWalletData struct{}

// UnlockWalletData is passed to 'OnUnlockWallet' rules.
type UnlockWalletData struct{}

// LockAccountData is passed to 'OnLockAccount' rules.
type LockAccountData struct{}

// UnlockAccountData is passed to 'OnUnlockAccount' rules.
type UnlockAccountData struct{}

// Result represents the result of running a set of rules.
type Result int

const (
	UNKNOWN Result = iota
	APPROVED
	DENIED
	FAILED
)

// Service is the interface that must be followed by a remote ruler for approval of requests.
type Service interface {
	OnListAccounts(ctx context.Context, metadata *ReqMetadata, req *AccessAccountData) Result
	OnSign(ctx context.Context, metadata *ReqMetadata, req *SignData) Result
	OnSignBeaconAttestation(ctx context.Context, metadata *ReqMetadata, req *SignBeaconAttestationData) Result
	OnSignBeaconProposal(ctx context.Context, metadata *ReqMetadata, req *SignBeaconProposalData) Result
	OnLockWallet(ctx context.Context, metadata *ReqMetadata, req *LockWalletData) Result
	OnUnlockWallet(ctx context.Context, metadata *ReqMetadata, req *UnlockWalletData) Result
	OnLockAccount(ctx context.Context, metadata *ReqMetadata, req *LockAccountData) Result
	OnUnlockAccount(ctx context.Context, metadata *ReqMetadata, req *UnlockAccountData) Result
}
