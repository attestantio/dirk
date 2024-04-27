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
)

func (h *Handler) senderID(ctx context.Context) uint64 {
	var senderID uint64
	if client, ok := ctx.Value(&interceptors.ClientName{}).(string); ok {
		for id, peer := range h.peers.All() {
			if peer.Name == client {
				senderID = id
				break
			}
		}
	}

	return senderID
}
