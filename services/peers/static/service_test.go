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

package static_test

import (
	context "context"
	"os"
	"testing"

	staticpeers "github.com/attestantio/dirk/services/peers/static"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

func TestMain(m *testing.M) {
	if err := e2types.InitBLS(); err != nil {
		os.Exit(1)
	}
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func TestService(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name  string
		peers map[uint64]string
		err   string
	}{
		{
			name: "Empty",
			err:  "problem with parameters: no peers specified",
		},
		{
			name: "PeerEmpty",
			peers: map[uint64]string{
				1: "",
			},
			err: "malformed peer ",
		},
		{
			name: "PeerMalformed1",
			peers: map[uint64]string{
				1: "malformed",
			},
			err: "malformed peer malformed",
		},
		{
			name: "PeerMalformed2",
			peers: map[uint64]string{
				1: "malformed:",
			},
			err: "malformed peer port for malformed:",
		},
		{
			name: "PeerMalformed3",
			peers: map[uint64]string{
				1: "malformed:bad",
			},
			err: "malformed peer port for malformed:bad",
		},
		{
			name: "PeerDuplicateNames",
			peers: map[uint64]string{
				1: "dup:1001",
				2: "dup:1002",
			},
			err: "duplicate peer name dup",
		},
		{
			name: "Good",
			peers: map[uint64]string{
				1: "peer1:1001",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := staticpeers.New(ctx,
				staticpeers.WithPeers(test.peers),
			)
			if test.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, test.err)
			}
		})
	}
}
