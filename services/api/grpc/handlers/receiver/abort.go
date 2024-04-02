// Copyright © 2020, 2024 Attestant Limited.
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
	"github.com/pkg/errors"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Abort handles the Abort() grpc call.
func (h *Handler) Abort(ctx context.Context, req *pb.AbortRequest) (*emptypb.Empty, error) {
	senderID := h.senderID(ctx)
	if senderID == 0 {
		log.Warn().Interface("client", ctx.Value(&interceptors.ClientName{})).Msg("Failed to obtain participant ID of sender")
		return nil, errors.New("Unknown sender")
	}
	log.Debug().Uint64("sender_id", senderID).Msg("Aborting as per request from sender")

	if err := h.process.OnAbort(ctx, senderID, req.GetAccount()); err != nil {
		log.Error().Err(err).Msg("Failed to abort distributed key generation")
		return nil, errors.New("Failed")
	}

	log.Trace().Msg("Completed abort successfully")
	return &emptypb.Empty{}, nil
}
