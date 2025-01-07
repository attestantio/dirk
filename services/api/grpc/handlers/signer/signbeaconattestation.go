// Copyright © 2020, 2025 Attestant Limited.
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
		log.Warn().Str("result", "denied").Msg("Neither account nor public key specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}
	if req.GetAccount() != "" && !strings.Contains(req.GetAccount(), "/") {
		log.Warn().Str("result", "denied").Msg("Invalid account specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}
	if req.GetData() == nil {
		log.Warn().Str("result", "denied").Msg("Request data not specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}
	if req.GetData().GetSource() == nil {
		log.Warn().Str("result", "denied").Msg("Request source checkpoint not specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}
	if req.GetData().GetTarget() == nil {
		log.Warn().Str("result", "denied").Msg("Request target checkpoint not specified")
		res.State = pb.ResponseState_DENIED
		return res, nil
	}

	data := &rules.SignBeaconAttestationData{
		Domain:          req.GetDomain(),
		Slot:            req.GetData().GetSlot(),
		CommitteeIndex:  req.GetData().GetCommitteeIndex(),
		BeaconBlockRoot: req.GetData().GetBeaconBlockRoot(),
		Source: &rules.Checkpoint{
			Epoch: req.GetData().GetSource().GetEpoch(),
			Root:  req.GetData().GetSource().GetRoot(),
		},
		Target: &rules.Checkpoint{
			Epoch: req.GetData().GetTarget().GetEpoch(),
			Root:  req.GetData().GetTarget().GetRoot(),
		},
	}

	result, signature := h.signer.SignBeaconAttestation(ctx, handlers.GenerateCredentials(ctx), req.GetAccount(), req.GetPublicKey(), data)
	switch result {
	case core.ResultSucceeded:
		res.State = pb.ResponseState_SUCCEEDED
		res.Signature = signature
		log.Trace().Str("result", "succeeded").Msg("Success")
	case core.ResultDenied:
		res.State = pb.ResponseState_DENIED
	case core.ResultFailed:
		res.State = pb.ResponseState_FAILED
	case core.ResultUnknown:
		res.State = pb.ResponseState_UNKNOWN
	}

	return res, nil
}
