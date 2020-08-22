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

package golang

import (
	"context"
	"fmt"

	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/opentracing/opentracing-go"
)

// RunRules runs a number of rules and returns a result.
func (s *Service) RunRules(ctx context.Context,
	credentials *checker.Credentials,
	action string,
	walletName string,
	accountName string,
	accountPubKey []byte,
	req interface{}) rules.Result {
	span, ctx := opentracing.StartSpanFromContext(ctx, "ruler.golang.RunRules")
	defer span.Finish()

	// Do not allow multiple parallel runs of this code for a public key.
	var lockKey [48]byte
	copy(lockKey[:], accountPubKey)
	s.locker.Lock(lockKey)
	defer s.locker.Unlock(lockKey)

	var name string
	if accountName == "" {
		name = walletName
	} else {
		name = fmt.Sprintf("%s/%s", walletName, accountName)
	}
	log := log.With().Str("account", name).Logger()

	metadata := s.assembleMetadata(ctx, credentials, accountName, accountPubKey)
	var result rules.Result
	switch action {
	case ruler.ActionSign:
		result = s.rules.OnSign(ctx, metadata, req.(*rules.SignData))
	case ruler.ActionSignBeaconProposal:
		result = s.rules.OnSignBeaconProposal(ctx, metadata, req.(*rules.SignBeaconProposalData))
	case ruler.ActionSignBeaconAttestation:
		result = s.rules.OnSignBeaconAttestation(ctx, metadata, req.(*rules.SignBeaconAttestationData))
	case ruler.ActionAccessAccount:
		result = s.rules.OnListAccounts(ctx, metadata, req.(*rules.AccessAccountData))
	case ruler.ActionLockWallet:
		result = s.rules.OnLockWallet(ctx, metadata, req.(*rules.LockWalletData))
	case ruler.ActionUnlockWallet:
		result = s.rules.OnUnlockWallet(ctx, metadata, req.(*rules.UnlockWalletData))
	case ruler.ActionLockAccount:
		result = s.rules.OnLockAccount(ctx, metadata, req.(*rules.LockAccountData))
	case ruler.ActionUnlockAccount:
		result = s.rules.OnUnlockAccount(ctx, metadata, req.(*rules.UnlockAccountData))
	}

	if result == rules.UNKNOWN {
		log.Error().Msg("Unknown result from rule")
		return rules.FAILED
	}
	return result
}

func (s *Service) assembleMetadata(ctx context.Context, credentials *checker.Credentials, accountName string, pubKey []byte) *rules.ReqMetadata {
	return &rules.ReqMetadata{
		Account: accountName,
		PubKey:  pubKey,
		IP:      credentials.IP,
		Client:  credentials.Client,
	}
}
