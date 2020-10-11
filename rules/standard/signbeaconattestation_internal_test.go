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

package standard

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignBeaconAttestationStateEncode(t *testing.T) {
	tests := []struct {
		name  string
		state *signBeaconAttestationState
		res   []byte
	}{
		{
			name: "Nil",
			res:  []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:  "Empty",
			state: &signBeaconAttestationState{},
			res:   []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name:  "Source1000Target2000",
			state: &signBeaconAttestationState{SourceEpoch: 1000, TargetEpoch: 2000},
			res:   []byte{0x01, 0xe8, 0x003, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x007, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.res, test.state.Encode())
		})
	}
}

func TestSignBeaconAttestationStateDecode(t *testing.T) {
	tests := []struct {
		name    string
		encoded []byte
		res     *signBeaconAttestationState
		err     string
	}{
		{
			name: "Nil",
			err:  "no data supplied",
		},
		{
			name:    "Zero",
			encoded: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			res:     &signBeaconAttestationState{},
		},
		{
			name:    "InvalidVersion",
			encoded: []byte{0x02, 0x00, 0x000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:     "gob: unknown type id or corrupted data",
		},
		{
			name:    "Short",
			encoded: []byte{0x01, 0xe8, 0x003, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:     "invalid version 1 data size 16",
		},
		{
			name:    "Long",
			encoded: []byte{0x01, 0xe8, 0x003, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			err:     "invalid version 1 data size 18",
		},
		{
			name:    "Source1000Target2000",
			encoded: []byte{0x01, 0xe8, 0x003, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x007, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			res:     &signBeaconAttestationState{SourceEpoch: 1000, TargetEpoch: 2000},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := &signBeaconAttestationState{}
			err := state.Decode(test.encoded)
			if test.err != "" {
				assert.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.res, state)
			}
		})
	}
}
