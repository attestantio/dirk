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
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/attestantio/dirk/rules"
	standardrules "github.com/attestantio/dirk/rules/standard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func _byteStr(t *testing.T, input string) []byte {
	bytes, err := hex.DecodeString(strings.TrimPrefix(input, "0x"))
	require.Nil(t, err)
	return bytes
}

func TestSign(t *testing.T) {
	ctx := context.Background()
	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)

	testRules, err := standardrules.New(ctx,
		standardrules.WithStoragePath(base),
		standardrules.WithAdminIPs([]string{"1.2.3.4", "5.6.7.8"}),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		metadata *rules.ReqMetadata
		req      *rules.SignData
		res      rules.Result
	}{
		{
			name: "MetadataNil",
			req: &rules.SignData{
				Data:   _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				Domain: _byteStr(t, "0200000000000000000000000000000000000000000000000000000000000000"),
			},
			res: rules.FAILED,
		},
		{
			name:     "AttestationDomain",
			metadata: &rules.ReqMetadata{},
			req: &rules.SignData{
				Domain: _byteStr(t, "0100000000000000000000000000000000000000000000000000000000000000"),
				Data:   _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
			},
			res: rules.DENIED,
		},
		{
			name:     "ProposalDomain",
			metadata: &rules.ReqMetadata{},
			req: &rules.SignData{
				Data:   _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				Domain: _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
			},
			res: rules.DENIED,
		},
		{
			name:     "Good",
			metadata: &rules.ReqMetadata{},
			req: &rules.SignData{
				Data:   _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				Domain: _byteStr(t, "0200000000000000000000000000000000000000000000000000000000000000"),
			},
			res: rules.APPROVED,
		},
		{
			name:     "NoVEIP",
			metadata: &rules.ReqMetadata{},
			req: &rules.SignData{
				Data:   _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				Domain: _byteStr(t, "0400000000000000000000000000000000000000000000000000000000000000"),
			},
			res: rules.DENIED,
		},
		{
			name: "InvalidVEIP",
			metadata: &rules.ReqMetadata{
				IP: "2.3.4.5",
			},
			req: &rules.SignData{
				Data:   _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				Domain: _byteStr(t, "0400000000000000000000000000000000000000000000000000000000000000"),
			},
			res: rules.DENIED,
		},
		{
			name: "GoodVEIP",
			metadata: &rules.ReqMetadata{
				IP: "5.6.7.8",
			},
			req: &rules.SignData{
				Data:   _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				Domain: _byteStr(t, "0400000000000000000000000000000000000000000000000000000000000000"),
			},
			res: rules.APPROVED,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := testRules.OnSign(ctx, test.metadata, test.req)
			assert.Equal(t, test.res, res)
		})
	}
}
