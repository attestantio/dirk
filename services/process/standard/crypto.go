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

	"github.com/attestantio/dirk/util"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
)

// contribution generates a contribution.
func (*Service) contribution(_ context.Context, generation *generation) error {
	threshold := generation.threshold
	participants := generation.participants

	// Create arrays of m secret and public (verification) keys.
	sks := make([]bls.SecretKey, threshold)
	verificationKeys := make([]bls.PublicKey, threshold)
	for i := uint32(0); i < threshold; i++ {
		sks[i] = bls.SecretKey{}
		sks[i].SetByCSPRNG()
		verificationKeys[i] = *sks[i].GetPublicKey()
	}

	// Generate a secret for each ID.
	secrets := make(map[uint64]bls.SecretKey, len(participants))
	for _, participant := range participants {
		secret := bls.SecretKey{}
		if err := secret.Set(sks, util.BLSID(participant.ID)); err != nil {
			return errors.Wrap(err, "failed to set contribution")
		}
		secrets[participant.ID] = secret
	}

	// Confirm the secrets.
	for k, v := range secrets {
		var vVecKey bls.PublicKey
		if err := vVecKey.Set(verificationKeys, util.BLSID(k)); err != nil {
			return errors.Wrap(err, "failed to create contribution")
		}
		if !v.GetPublicKey().IsEqual(&vVecKey) {
			return errors.New("failed to verify contribution")
		}
	}

	generation.sharedSecrets[generation.id] = secrets[generation.id]
	generation.sharedVVecs[generation.id] = verificationKeys
	generation.distributionSecrets = secrets

	return nil
}

// zeroContribution generates a contribution with the leading secret key 0, used to aggregate without altering an already-present key.
// func (s *Service) zeroContribution(ctx context.Context, generation *generation) error {
// 	threshold := generation.threshold
// 	participants := generation.participants
//
// 	// Create arrays of m secret and public (verification) keys.
// 	sks := make([]bls.SecretKey, threshold)
// 	verificationKeys := make([]bls.PublicKey, threshold)
// 	for i := uint32(0); i < threshold; i++ {
// 		sks[i] = bls.SecretKey{}
// 		if i > 0 {
// 			sks[i].SetByCSPRNG()
// 		}
// 		verificationKeys[i] = *sks[i].GetPublicKey()
// 	}
//
// 	// Generate a secret for each ID.
// 	secrets := make(map[uint64]bls.SecretKey, len(participants))
// 	for _, participant := range participants {
// 		secret := bls.SecretKey{}
// 		if err := secret.Set(sks, util.BLSID(participant.ID)); err != nil {
// 			return errors.Wrap(err, "failed to set contribution")
// 		}
// 		secrets[participant.ID] = secret
// 	}
//
// 	// Confirm the secrets.
// 	for k, v := range secrets {
// 		var vVecKey bls.PublicKey
// 		if err := vVecKey.Set(verificationKeys, util.BLSID(k)); err != nil {
// 			return errors.Wrap(err, "failed contribution generation")
// 		}
// 		if !v.GetPublicKey().IsEqual(&vVecKey) {
// 			return errors.New("failed contribution verification")
// 		}
// 	}
//
// 	generation.sharedSecrets[generation.id] = secrets[generation.id]
// 	generation.sharedVVecs[generation.id] = verificationKeys
// 	generation.distributionSecrets = secrets
//
// 	return nil
// }

// verifyContribution verifies another participant's contribution.
func verifyContribution(id uint64, secretShare bls.SecretKey, vVec []bls.PublicKey) bool {
	var vVecKey bls.PublicKey
	if err := vVecKey.Set(vVec, util.BLSID(id)); err != nil {
		return false
	}
	return secretShare.GetPublicKey().IsEqual(&vVecKey)
}
