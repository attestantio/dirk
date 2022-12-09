// Copyright © 2020 - 2022 Attestant Limited.
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
	"time"

	"github.com/attestantio/dirk/rules"
	standardrules "github.com/attestantio/dirk/rules/standard"
	"github.com/attestantio/dirk/testing/logger"
	"github.com/stretchr/testify/require"
)

func TestSignBeaconAttestations(t *testing.T) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(base)

	capture := logger.NewLogCapture()
	testRules, err := standardrules.New(ctx,
		standardrules.WithStoragePath(base),
	)
	require.NoError(t, err)

	tests := []struct {
		name     string
		metadata []*rules.ReqMetadata
		req      []*rules.SignBeaconAttestationData
		res      []rules.Result
		logErr   string
	}{
		{
			name: "Nil",
			res:  []rules.Result{},
		},
		{
			name: "MetadataNil",
			req: []*rules.SignBeaconAttestationData{
				{
					Domain: _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				},
			},
			res:    []rules.Result{rules.FAILED},
			logErr: "Mismatch between number of requests and number of metadata entries",
		},
		{
			name: "MetadataEmpty",
			req: []*rules.SignBeaconAttestationData{
				{
					Domain: _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				},
			},
			metadata: []*rules.ReqMetadata{},
			res:      []rules.Result{rules.FAILED},
			logErr:   "Mismatch between number of requests and number of metadata entries",
		},
		{
			name: "MetadataEntryEmpty",
			req: []*rules.SignBeaconAttestationData{
				{
					Domain: _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
				},
			},
			metadata: []*rules.ReqMetadata{
				nil,
			},
			res:    []rules.Result{rules.FAILED},
			logErr: "Nil metadata entry",
		},
		{
			name: "ReqNil",
			metadata: []*rules.ReqMetadata{
				{},
			},
			res:    []rules.Result{},
			logErr: "Mismatch between number of requests and number of metadata entries",
		},
		{
			name: "ReqEmpty",
			metadata: []*rules.ReqMetadata{
				{},
			},
			req:    []*rules.SignBeaconAttestationData{},
			res:    []rules.Result{},
			logErr: "Mismatch between number of requests and number of metadata entries",
		},
		{
			name: "ReqEntryNil",
			metadata: []*rules.ReqMetadata{
				{},
			},
			req: []*rules.SignBeaconAttestationData{
				nil,
			},
			res:    []rules.Result{rules.FAILED},
			logErr: "Nil req entry",
		},
		{
			name: "ReqEntryEmpty",
			metadata: []*rules.ReqMetadata{
				{},
			},
			req: []*rules.SignBeaconAttestationData{
				{},
			},
			res:    []rules.Result{rules.FAILED},
			logErr: "Nil req source",
		},
		{
			name: "ReqEntryTarget",
			metadata: []*rules.ReqMetadata{
				{},
			},
			req: []*rules.SignBeaconAttestationData{
				{
					Source: &rules.Checkpoint{},
				},
			},
			res:    []rules.Result{rules.FAILED},
			logErr: "Nil req target",
		},
		{
			name: "BadDomain",
			metadata: []*rules.ReqMetadata{
				{},
			},
			req: []*rules.SignBeaconAttestationData{
				{
					Domain: _byteStr(t, "0000000000000000000000000000000000000000000000000000000000000000"),
					Source: &rules.Checkpoint{},
					Target: &rules.Checkpoint{},
				},
			},
			res:    []rules.Result{rules.DENIED},
			logErr: "Not approving non-beacon attestation due to incorrect domain",
		},
		{
			name: "EqualEpochs",
			metadata: []*rules.ReqMetadata{
				{},
			},
			req: []*rules.SignBeaconAttestationData{
				{
					Domain: _byteStr(t, "0100000000000000000000000000000000000000000000000000000000000000"),
					Source: &rules.Checkpoint{
						Epoch: 5,
					},
					Target: &rules.Checkpoint{
						Epoch: 5,
					},
				},
			},
			res:    []rules.Result{rules.DENIED},
			logErr: "Request target epoch equal to or lower than request source epoch",
		},
		{
			name: "Good",
			metadata: []*rules.ReqMetadata{
				{},
			},
			req: []*rules.SignBeaconAttestationData{
				{
					Domain: _byteStr(t, "0100000000000000000000000000000000000000000000000000000000000000"),
					Source: &rules.Checkpoint{
						Epoch: 4,
					},
					Target: &rules.Checkpoint{
						Epoch: 5,
					},
				},
			},
			res: []rules.Result{rules.APPROVED},
		},
		{
			name: "SameTargetAsStored",
			metadata: []*rules.ReqMetadata{
				{},
			},
			req: []*rules.SignBeaconAttestationData{
				{
					Domain: _byteStr(t, "0100000000000000000000000000000000000000000000000000000000000000"),
					Source: &rules.Checkpoint{
						Epoch: 4,
					},
					Target: &rules.Checkpoint{
						Epoch: 5,
					},
				},
			},
			res:    []rules.Result{rules.DENIED},
			logErr: "Request target epoch equal to or lower than previous signed target epoch",
		},
		{
			name: "EarlierSourceThanStored",
			metadata: []*rules.ReqMetadata{
				{},
			},
			req: []*rules.SignBeaconAttestationData{
				{
					Domain: _byteStr(t, "0100000000000000000000000000000000000000000000000000000000000000"),
					Source: &rules.Checkpoint{
						Epoch: 3,
					},
					Target: &rules.Checkpoint{
						Epoch: 6,
					},
				},
			},
			res:    []rules.Result{rules.DENIED},
			logErr: "Request source epoch lower than previous signed source epoch",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res := testRules.OnSignBeaconAttestations(ctx, test.metadata, test.req)
			require.Equal(t, test.res, res)
			if test.logErr != "" {
				capture.AssertHasEntry(t, test.logErr)
			}
			capture.ClearEntries()
		})
	}

	// Cancel the context and wait for it to take effect.
	cancelFunc()
	time.Sleep(100 * time.Millisecond)
}
