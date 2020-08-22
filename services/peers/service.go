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

package peers

import (
	"github.com/attestantio/dirk/core"
)

// Service provides peer information.
type Service interface {
	// Peer returns the peer with the given ID.
	Peer(id uint64) (*core.Endpoint, error)

	// All returns all peers.
	All() map[uint64]*core.Endpoint

	// Suitable returns peers that are suitable given the supplied requirements.
	Suitable(threshold uint32) ([]*core.Endpoint, error)
}
