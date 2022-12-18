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

package accountmanager

import (
	context "context"
	"errors"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/api/grpc/handlers"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// Lock locks an account.
func (h *Handler) Lock(ctx context.Context, req *pb.LockAccountRequest) (*pb.LockAccountResponse, error) {
	if req == nil {
		log.Warn().Str("result", "denied").Msg("Request not specified")
		return nil, errors.New("no request specified")
	}

	log.Trace().Str("account", req.GetAccount()).Msg("Lock account received")
	res := &pb.LockAccountResponse{}

	result, err := h.accountManager.Lock(ctx, handlers.GenerateCredentials(ctx), req.Account)
	if err != nil {
		log.Error().Err(err).Msg("Lock attempt resulted in error")
		res.State = pb.ResponseState_FAILED
	} else {
		switch result {
		case core.ResultSucceeded:
			res.State = pb.ResponseState_SUCCEEDED
		case core.ResultDenied:
			res.State = pb.ResponseState_DENIED
		case core.ResultFailed:
			res.State = pb.ResponseState_FAILED
		case core.ResultUnknown:
			res.State = pb.ResponseState_UNKNOWN
		}
	}

	return res, nil
}
