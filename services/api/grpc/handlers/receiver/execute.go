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
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// Execute handles the Execute() grpc call.
func (h *Handler) Execute(ctx context.Context, req *pb.ExecuteRequest) (*empty.Empty, error) {
	senderID := h.senderID(ctx)
	if senderID == 0 {
		log.Warn().Interface("client", ctx.Value(&interceptors.ClientName{})).Msg("Failed to obtain participant ID of sender")
		return nil, errors.New("Unknown sender")
	}
	log.Trace().Uint64("sender_id", senderID).Msg("Executing as per request from sender")

	err := h.process.OnExecute(ctx, senderID, req.Account)
	if err != nil {
		log.Error().Err(err).Msg("Failed to execute distributed key generation")
		return nil, err
	}

	log.Trace().Msg("Completed execution successfully")
	return &empty.Empty{}, nil
}
