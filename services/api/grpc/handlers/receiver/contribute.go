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

package receiver

import (
	context "context"

	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// Contribute receives and returns contributions.
func (h *Handler) Contribute(ctx context.Context, req *pb.ContributeRequest) (*pb.ContributeResponse, error) {
	senderID := h.senderID(ctx)
	if senderID == 0 {
		log.Warn().Interface("client", ctx.Value(&interceptors.ClientName{})).Msg("Failed to obtain participant ID of sender")
		return nil, errors.New("Unknown sender")
	}

	log := log.With().Str("account", req.GetAccount()).Uint64("peer", senderID).Logger()

	secret := bls.SecretKey{}
	if err := secret.Deserialize(req.GetSecret()); err != nil {
		log.Warn().Err(err).Msg("Received secret key is invalid")
		return nil, errors.New("Invalid secret key")
	}
	vVec := make([]bls.PublicKey, len(req.GetVerificationVector()))
	for i, key := range req.GetVerificationVector() {
		vVec[i] = bls.PublicKey{}
		if err := vVec[i].Deserialize(key); err != nil {
			log.Warn().Err(err).Msg("Received verification vector is invalid")
			return nil, errors.Wrap(err, "Invalid verification vector")
		}
	}
	log.Trace().Msg("Received valid contribution")

	retSecret, retVVec, err := h.process.OnContribute(ctx, senderID, req.GetAccount(), secret, vVec)
	if err != nil {
		log.Error().Err(err).Msg("Handle/generate contribution failed")
		return nil, errors.Wrap(err, "Failed to handle contribution")
	}

	resVVec := make([][]byte, len(retVVec))
	for i, key := range retVVec {
		resVVec[i] = key.Serialize()
	}
	res := &pb.ContributeResponse{
		Secret:             retSecret.Serialize(),
		VerificationVector: resVVec,
	}

	return res, nil
}
