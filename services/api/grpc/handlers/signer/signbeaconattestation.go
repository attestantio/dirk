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
	"strings"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/api/grpc/handlers"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// SignBeaconAttestation signs a attestation for a beacon block.
func (h *Handler) SignBeaconAttestation(ctx context.Context, req *pb.SignBeaconAttestationRequest) (*pb.SignResponse, error) {
	log.Trace().Msg("Handling request")

	res := &pb.SignResponse{}
	if req == nil {
		log.Warn().Str("result", "denied").Msg("Request not specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}
	if req.GetAccount() == "" && req.GetPublicKey() == nil {
		log.Warn().Str("result", "denied").Msg("Neither accout nor public key specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}
	if !strings.Contains(req.GetAccount(), "/") {
		log.Warn().Str("result", "denied").Msg("Invalid account specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}
	if req.Data == nil {
		log.Warn().Str("result", "denied").Msg("Request data not specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}
	if req.Data.Source == nil {
		log.Warn().Str("result", "denied").Msg("Request source checkpoint not specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}
	if req.Data.Target == nil {
		log.Warn().Str("result", "denied").Msg("Request target checkpoint not specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}

	data := &rules.SignBeaconAttestationData{
		Domain:          req.Domain,
		Slot:            req.Data.Slot,
		CommitteeIndex:  req.Data.CommitteeIndex,
		BeaconBlockRoot: req.Data.BeaconBlockRoot,
		Source: &rules.Checkpoint{
			Epoch: req.Data.Source.Epoch,
			Root:  req.Data.Source.Root,
		},
		Target: &rules.Checkpoint{
			Epoch: req.Data.Target.Epoch,
			Root:  req.Data.Target.Root,
		},
	}

	result, signature := h.signer.SignBeaconAttestation(ctx, handlers.GenerateCredentials(ctx), req.GetAccount(), req.GetPublicKey(), data)
	switch result {
	case core.ResultSucceeded:
		res.State = pb.ResponseState_SUCCEEDED
		res.Signature = signature
	case core.ResultDenied:
		res.State = pb.ResponseState_DENIED
	case core.ResultFailed:
		res.State = pb.ResponseState_FAILED
	case core.ResultUnknown:
		res.State = pb.ResponseState_UNKNOWN
	}

	log.Trace().Str("result", "succeeded").Msg("Success")
	return res, nil
}
