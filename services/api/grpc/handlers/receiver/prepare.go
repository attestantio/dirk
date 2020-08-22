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
	"fmt"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// Prepare handles the Prepare() grpc call.
func (h *Handler) Prepare(ctx context.Context, req *pb.PrepareRequest) (*empty.Empty, error) {
	senderID := h.senderID(ctx)
	if senderID == 0 {
		log.Warn().Interface("client", ctx.Value(&interceptors.ClientName{})).Msg("Failed to obtain participant ID of sender")
		return nil, fmt.Errorf("unknown sender")
	}
	log.Trace().Uint64("sender_id", senderID).Msg("Preparing as per request from sender")

	participants := make([]*core.Endpoint, len(req.Participants))
	for i, participant := range req.Participants {
		participants[i] = &core.Endpoint{
			ID:   participant.Id,
			Name: participant.Name,
			Port: participant.Port,
		}
	}
	err := h.process.OnPrepare(ctx, senderID, req.Account, req.Passphrase, req.Threshold, participants)
	if err != nil {
		log.Error().Err(err).Msg("Failed to prepare for distributed key generation")
		return nil, errors.New("Failed to prepare")
	}

	log.Trace().Msg("Completed preparation successfully")
	return &empty.Empty{}, nil
}
