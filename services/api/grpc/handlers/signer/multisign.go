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

package signer

import (
	context "context"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/api/grpc/handlers"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// Multisign signs generic data.
func (h *Handler) Multisign(ctx context.Context, req *pb.MultisignRequest) (*pb.MultisignResponse, error) {
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

	for i, request := range req.GetRequests() {
		if request == nil {
			log.Warn().Str("result", "denied").Msg("Request nil")
			res.Responses[i].State = pb.ResponseState_FAILED

			return res, nil
		}
		if request.GetData() == nil {
			log.Warn().Str("result", "denied").Msg("Request data not specified")
			res.Responses[i].State = pb.ResponseState_DENIED

			return res, nil
		}
		if request.GetDomain() == nil {
			log.Warn().Str("result", "denied").Msg("Request domain not specified")
			res.Responses[i].State = pb.ResponseState_DENIED

			return res, nil
		}
	}

	accountNames := make([]string, len(req.GetRequests()))
	pubKeys := make([][]byte, len(req.GetRequests()))
	reqData := make([]*rules.SignData, len(req.GetRequests()))
	for i, request := range req.GetRequests() {
		accountNames[i] = request.GetAccount()
		pubKeys[i] = request.GetPublicKey()
		reqData[i] = &rules.SignData{
			Domain: request.GetDomain(),
			Data:   request.GetData(),
		}
	}

	results, signatures := h.signer.Multisign(ctx, handlers.GenerateCredentials(ctx), accountNames, pubKeys, reqData)
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
