// Copyright © 2020, 2022 Attestant Limited.
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

package standard_test

import (
	"context"
	"os"
	"testing"

	"github.com/attestantio/dirk/rules"
	standardrules "github.com/attestantio/dirk/rules/standard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignBeaconProposal(t *testing.T) {
	ctx := context.Background()
	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)
	testRules, err := standardrules.New(ctx,
		standardrules.WithStoragePath(base),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		metadata *rules.ReqMetadata
		req      *rules.SignBeaconProposalData
		res      rules.Result
	}{
		{
			name:     "BadDomain",
			metadata: &rules.ReqMetadata{},
			req: &rules.SignBeaconProposalData{
				Domain: _byteStr(t, "0100000000000000000000000000000000000000000000000000000000000000"),
				Slot:   2,
			},
			res: rules.DENIED,
		},
		{
			name:     "Good",
			metadata: &rules.ReqMetadata{},
			req: &rules.SignBeaconProposalData{
				Domain: _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				Slot:   2,
			},
			res: rules.APPROVED,
		},
		{
			name:     "SameSlot",
			metadata: &rules.ReqMetadata{},
			req: &rules.SignBeaconProposalData{
				Domain: _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				Slot:   2,
			},
			res: rules.DENIED,
		},
		{
			name:     "LowerSlot",
			metadata: &rules.ReqMetadata{},
			req: &rules.SignBeaconProposalData{
				Domain: _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				Slot:   1,
			},
			res: rules.DENIED,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := testRules.OnSignBeaconProposal(ctx, test.metadata, test.req)
			assert.Equal(t, test.res, res)
		})
	}
}
