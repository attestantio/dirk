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
	if len(req.Requests) == 0 {
		log.Warn().Str("result", "denied").Msg("Request empty")
		res.Responses = make([]*pb.SignResponse, 1)
		res.Responses[0] = &pb.SignResponse{State: pb.ResponseState_DENIED}
		return res, nil
	}

	res.Responses = make([]*pb.SignResponse, len(req.Requests))
	for i := range req.Requests {
		res.Responses[i] = &pb.SignResponse{State: pb.ResponseState_UNKNOWN}
	}

	for i := range req.Requests {
		if req.Requests[i] == nil {
			log.Warn().Str("result", "denied").Msg("Request nil")
			res.Responses[i].State = pb.ResponseState_FAILED
			return res, nil
		}
		if req.Requests[i].Data == nil {
			log.Warn().Str("result", "denied").Msg("Request missing data")
			res.Responses[i].State = pb.ResponseState_DENIED
			return res, nil
		}
		if req.Requests[i].Data.Source == nil {
			log.Warn().Str("result", "denied").Msg("Request source checkpoint not specified")
			res.Responses[i].State = pb.ResponseState_DENIED
			return res, nil
		}
		if req.Requests[i].Data.Target == nil {
			log.Warn().Str("result", "denied").Msg("Request target checkpoint not specified")
			res.Responses[i].State = pb.ResponseState_DENIED
			return res, nil
		}
	}

	accountNames := make([]string, len(req.Requests))
	pubKeys := make([][]byte, len(req.Requests))
	reqData := make([]*rules.SignBeaconAttestationData, len(req.Requests))
	for i := range req.Requests {
		accountNames[i] = req.Requests[i].GetAccount()
		pubKeys[i] = req.Requests[i].GetPublicKey()
		reqData[i] = &rules.SignBeaconAttestationData{
			Domain:          req.Requests[i].Domain,
			Slot:            req.Requests[i].Data.Slot,
			CommitteeIndex:  req.Requests[i].Data.CommitteeIndex,
			BeaconBlockRoot: req.Requests[i].Data.BeaconBlockRoot,
			Source: &rules.Checkpoint{
				Epoch: req.Requests[i].Data.Source.Epoch,
				Root:  req.Requests[i].Data.Source.Root,
			},
			Target: &rules.Checkpoint{
				Epoch: req.Requests[i].Data.Target.Epoch,
				Root:  req.Requests[i].Data.Target.Root,
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
