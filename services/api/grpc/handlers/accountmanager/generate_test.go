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

package accountmanager_test

import (
	context "context"
	"testing"

	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name   string
		client string
		req    *pb.GenerateRequest
		err    string
		state  pb.ResponseState
	}{
		{
			name:  "Missing",
			state: pb.ResponseState_DENIED,
			err:   "no request specified",
		},
		{
			name:   "Empty",
			client: "Valid client",
			state:  pb.ResponseState_DENIED,
			err:    "no request specified",
		},
		{
			name:   "GoodSimpleGeneration",
			client: "Valid client",
			req: &pb.GenerateRequest{
				Account:    "Wallet 1/New Account",
				Passphrase: []byte("test"),
			},
			state: pb.ResponseState_SUCCEEDED,
		},
		{
			name:   "GoodCompositeGeneration",
			client: "Valid client",
			req: &pb.GenerateRequest{
				Account:          "Wallet 1/New Account",
				Participants:     uint32(3),
				SigningThreshold: uint32(2),
				Passphrase:       []byte("test"),
			},
			state: pb.ResponseState_SUCCEEDED,
		},
	}

	handler, err := Setup()
	require.Nil(t, err)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), &interceptors.ClientName{}, test.client)
			resp, err := handler.Generate(ctx, test.req)
			if test.err == "" {
				// Result expected.
				require.NoError(t, err)
				assert.Equal(t, test.state, resp.State)
			} else {
				// Error expected.
				assert.EqualError(t, err, test.err)
			}
		})
	}
}
