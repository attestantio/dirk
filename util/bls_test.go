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

package util_test

import (
	"testing"

	"github.com/attestantio/dirk/util"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/require"
)

func TestBLSID(t *testing.T) {
	if err := bls.Init(bls.BLS12_381); err != nil {
		panic(err)
	}
	if err := bls.SetETHmode(bls.EthModeDraft07); err != nil {
		panic(err)
	}

	tests := []struct {
		name   string
		input  uint64
		output string
	}{
		{
			name:   "Zero",
			input:  0,
			output: "0",
		},
		{
			name:   "One",
			input:  1,
			output: "1",
		},
		{
			name:   "TwoFiveSix",
			input:  256,
			output: "100",
		},
		{
			name:   "Max",
			input:  18446744073709551615,
			output: "ffffffffffffffff",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id := util.BLSID(test.input)
			require.Equal(t, test.output, id.GetHexString())
		})
	}
}
