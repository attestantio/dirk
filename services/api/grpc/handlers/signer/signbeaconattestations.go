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

// SignBeaconAttestations signs multiple beacon attestations.
func (h *Handler) SignBeaconAttestations(ctx context.Context, req *pb.SignBeaconAttestationsRequest) (*pb.MultisignResponse, error) {
	log.Trace().Msg("Handling request")

	res := &pb.MultisignResponse{}
	if req == nil {
		log.Warn().Str("result", "denied").Msg("Request not specified")
		res.Responses = make([]*pb.SignResponse, 1)
		res.Responses[0] = &pb.SignResponse{State: pb.ResponseState_DENIED}

		return res, nil
	}
	if len(req.GetRequests()) == 0 {
		log.Warn().Str("result", "denied").Msg("Request empty")
		res.Responses = make([]*pb.SignResponse, 1)
		res.Responses[0] = &pb.SignResponse{State: pb.ResponseState_DENIED}

		return res, nil
	}

	res.Responses = make([]*pb.SignResponse, len(req.GetRequests()))
	for i := range req.GetRequests() {
		res.Responses[i] = &pb.SignResponse{State: pb.ResponseState_UNKNOWN}
	}

	validateSignBeaconAttestationsRequests(ctx, req, res)
	for i := range req.GetRequests() {
		if res.GetResponses()[i].GetState() == pb.ResponseState_DENIED ||
			res.GetResponses()[i].GetState() == pb.ResponseState_FAILED {
			return res, nil
		}
	}

	accountNames := make([]string, len(req.GetRequests()))
	pubKeys := make([][]byte, len(req.GetRequests()))
	reqData := make([]*rules.SignBeaconAttestationData, len(req.GetRequests()))
	for i, request := range req.GetRequests() {
		accountNames[i] = request.GetAccount()
		pubKeys[i] = request.GetPublicKey()
		reqData[i] = &rules.SignBeaconAttestationData{
			Domain:          request.GetDomain(),
			Slot:            request.GetData().GetSlot(),
			CommitteeIndex:  request.GetData().GetCommitteeIndex(),
			BeaconBlockRoot: request.GetData().GetBeaconBlockRoot(),
			Source: &rules.Checkpoint{
				Epoch: request.GetData().GetSource().GetEpoch(),
				Root:  request.GetData().GetSource().GetRoot(),
			},
			Target: &rules.Checkpoint{
				Epoch: request.GetData().GetTarget().GetEpoch(),
				Root:  request.GetData().GetTarget().GetRoot(),
			},
		}
	}

	results, signatures := h.signer.SignBeaconAttestations(ctx, handlers.GenerateCredentials(ctx), accountNames, pubKeys, reqData)
	for i := range results {
		switch results[i] {
		case core.ResultSucceeded:
			res.Responses[i].State = pb.ResponseState_SUCCEEDED
			res.Responses[i].Signature = signatures[i]
		case core.ResultDenied:
			res.Responses[i].State = pb.ResponseState_DENIED
		case core.ResultFailed:
			res.Responses[i].State = pb.ResponseState_FAILED
		case core.ResultUnknown:
			res.Responses[i].State = pb.ResponseState_UNKNOWN
		}
	}

	return res, nil
}

func validateSignBeaconAttestationsRequests(_ context.Context,
	req *pb.SignBeaconAttestationsRequest,
	res *pb.MultisignResponse,
) {
	for i, request := range req.GetRequests() {
		if request == nil {
			log.Warn().Str("result", "denied").Msg("Request nil")
			res.Responses[i].State = pb.ResponseState_FAILED

			return
		}
		if request.GetAccount() == "" && request.GetPublicKey() == nil {
			log.Warn().Str("result", "denied").Msg("Neither account nor public key specified")
			res.Responses[i].State = pb.ResponseState_DENIED

			return
		}
		if request.GetAccount() != "" && !strings.Contains(request.GetAccount(), "/") {
			log.Warn().Str("result", "denied").Msg("Invalid account specified")
			res.Responses[i].State = pb.ResponseState_DENIED

			return
		}
		if request.GetData() == nil {
			log.Warn().Str("result", "denied").Msg("Request missing data")
			res.Responses[i].State = pb.ResponseState_DENIED

			return
		}
		if request.GetData().GetSource() == nil {
			log.Warn().Str("result", "denied").Msg("Request source checkpoint not specified")
			res.Responses[i].State = pb.ResponseState_DENIED

			return
		}
		if request.GetData().GetTarget() == nil {
			log.Warn().Str("result", "denied").Msg("Request target checkpoint not specified")
			res.Responses[i].State = pb.ResponseState_DENIED

			return
		}
	}
}
