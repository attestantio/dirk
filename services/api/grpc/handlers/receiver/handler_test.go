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

package receiver_test

import (
	"context"
	"os"
	"testing"

	"github.com/attestantio/dirk/core"
	receiverhandler "github.com/attestantio/dirk/services/api/grpc/handlers/receiver"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	"github.com/attestantio/dirk/services/peers"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	process "github.com/attestantio/dirk/services/process"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	mocksender "github.com/attestantio/dirk/services/sender/mock"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

func TestMain(m *testing.M) {
	if err := e2types.InitBLS(); err != nil {
		os.Exit(1)
	}
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func TestNew(t *testing.T) {
	ctx := context.Background()

	senderSvc := mocksender.New(1)

	stores, err := core.InitStores(ctx, nil)
	require.NoError(t, err)

	fetcherSvc, err := memfetcher.New(ctx,
		memfetcher.WithStores(stores),
	)
	require.NoError(t, err)

	peersSvc, err := staticpeers.New(ctx,
		staticpeers.WithPeers(map[uint64]string{
			1: "signer-test01:8881",
			2: "signer-test02:8882",
			3: "signer-test03:8883",
		}))
	require.NoError(t, err)

	checkerSvc, err := mockchecker.New(zerolog.Disabled)
	require.NoError(t, err)

	unlockerSvc, err := localunlocker.New(context.Background(),
		localunlocker.WithAccountPassphrases([]string{"Test account 1 passphrase"}))
	require.NoError(t, err)

	processSvc, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checkerSvc),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(1),
		standardprocess.WithPeers(peersSvc),
		standardprocess.WithSender(senderSvc),
		standardprocess.WithFetcher(fetcherSvc),
		standardprocess.WithStores(stores),
		standardprocess.WithUnlocker(unlockerSvc),
	)
	require.NoError(t, err)

	tests := []struct {
		name    string
		process process.Service
		peers   peers.Service
		err     string
	}{
		{
			name: "Nil",
			err:  "problem with parameters: no peers specified",
		},
		{
			name:  "ProcessMissing",
			peers: peersSvc,
			err:   "problem with parameters: no process specified",
		},
		{
			name:    "PeersMissing",
			process: processSvc,
			err:     "problem with parameters: no peers specified",
		},
		{
			name:    "Good",
			process: processSvc,
			peers:   peersSvc,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := receiverhandler.New(context.Background(),
				receiverhandler.WithLogLevel(zerolog.Disabled),
				receiverhandler.WithProcess(test.process),
				receiverhandler.WithPeers(test.peers),
			)
			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
