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

package standard_test

import (
	context "context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/checker"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	"github.com/attestantio/dirk/services/fetcher"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/attestantio/dirk/services/metrics/prometheus"
	"github.com/attestantio/dirk/services/peers"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	"github.com/attestantio/dirk/services/process"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	"github.com/attestantio/dirk/services/sender"
	sendermock "github.com/attestantio/dirk/services/sender/mock"
	"github.com/attestantio/dirk/services/unlocker"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	"github.com/attestantio/dirk/testing/mock"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Helper to create a process service.
func createProcessService(ctx context.Context, id uint64) (process.Service, error) {
	stores := []e2wtypes.Store{scratch.New()}
	if _, err := distributed.CreateWallet(ctx, "Test", stores[0], keystorev4.New()); err != nil {
		return nil, err
	}
	peers, err := staticpeers.New(ctx,
		staticpeers.WithPeers(map[uint64]string{
			1: "signer-test01:8881",
			2: "signer-test02:8882",
			3: "signer-test03:8883",
		}),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create peers service")
	}

	checkerSvc, err := mockchecker.New(zerolog.Disabled)
	if err != nil {
		return nil, err
	}
	unlockerSvc, err := localunlocker.New(context.Background(),
		localunlocker.WithAccountPassphrases([]string{"Test account 1 passphrase"}))
	if err != nil {
		return nil, err
	}

	fetcherSvc, err := memfetcher.New(ctx,
		memfetcher.WithStores(stores),
		memfetcher.WithEncryptor(keystorev4.New()),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create memory fetcher")
	}

	process, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checkerSvc),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(id),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(sendermock.New(id)),
		standardprocess.WithFetcher(fetcherSvc),
		standardprocess.WithStores(stores),
		standardprocess.WithUnlocker(unlockerSvc),
	)
	if err != nil {
		return nil, err
	}
	mock.Processes[id] = process

	return process, nil
}

func TestMain(m *testing.M) {
	if err := e2types.InitBLS(); err != nil {
		os.Exit(1)
	}
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func TestNew(t *testing.T) {
	ctx := context.Background()

	stores, err := core.InitStores(ctx, nil)
	require.NoError(t, err)

	endpoints := map[uint64]string{
		1: "signer-test01:8881",
		2: "signer-test02:8882",
		3: "signer-test03:8883",
	}

	fetcherSvc, err := memfetcher.New(ctx,
		memfetcher.WithStores(stores),
		memfetcher.WithEncryptor(keystorev4.New()),
	)
	require.NoError(t, err)

	peersSvc, err := staticpeers.New(ctx,
		staticpeers.WithPeers(endpoints),
	)
	require.NoError(t, err)

	checkerSvc, err := mockchecker.New(zerolog.Disabled)
	require.NoError(t, err)

	unlockerSvc, err := localunlocker.New(context.Background(),
		localunlocker.WithAccountPassphrases([]string{"Test account 1 passphrase"}))
	require.NoError(t, err)

	monitorSvc, err := prometheus.New(ctx, prometheus.WithAddress("localhost:11111"))
	require.NoError(t, err)

	senderSvc := sendermock.New(1)

	tests := []struct {
		name                 string
		monitor              metrics.Service
		peers                peers.Service
		checker              checker.Service
		stores               []e2wtypes.Store
		endpoints            map[uint64]string
		generationPassphrase []byte
		sender               sender.Service
		fetcher              fetcher.Service
		unlocker             unlocker.Service
		id                   uint64
		err                  string
	}{
		{
			name: "Nil",
			err:  "problem with parameters: no checker specified",
		},
		{
			name:                 "CheckerMissing",
			peers:                peersSvc,
			stores:               stores,
			endpoints:            endpoints,
			generationPassphrase: []byte("secret"),
			sender:               senderSvc,
			fetcher:              fetcherSvc,
			unlocker:             unlockerSvc,
			id:                   1,
			err:                  "problem with parameters: no checker specified",
		},
		{
			name:                 "SenderSvcMissing",
			monitor:              monitorSvc,
			peers:                peersSvc,
			checker:              checkerSvc,
			stores:               stores,
			endpoints:            endpoints,
			generationPassphrase: []byte("secret"),
			fetcher:              fetcherSvc,
			unlocker:             unlockerSvc,
			id:                   1,
			err:                  "problem with parameters: no sender specified",
		},
		{
			name:                 "FetcherSvcMissing",
			monitor:              monitorSvc,
			peers:                peersSvc,
			checker:              checkerSvc,
			stores:               stores,
			endpoints:            endpoints,
			generationPassphrase: []byte("secret"),
			sender:               senderSvc,
			unlocker:             unlockerSvc,
			id:                   1,
			err:                  "problem with parameters: no fetcher specified",
		},
		{
			name:                 "UnlockerSvcMissing",
			monitor:              monitorSvc,
			peers:                peersSvc,
			checker:              checkerSvc,
			stores:               stores,
			endpoints:            endpoints,
			generationPassphrase: []byte("secret"),
			sender:               senderSvc,
			fetcher:              fetcherSvc,
			id:                   1,
			err:                  "problem with parameters: no unlocker specified",
		},
		{
			name:                 "PeersMissing",
			checker:              checkerSvc,
			stores:               stores,
			endpoints:            endpoints,
			generationPassphrase: []byte("secret"),
			sender:               senderSvc,
			fetcher:              fetcherSvc,
			unlocker:             unlockerSvc,
			id:                   1,
			err:                  "problem with parameters: no peers specified",
		},
		{
			name:                 "StoresMissing",
			peers:                peersSvc,
			checker:              checkerSvc,
			endpoints:            endpoints,
			generationPassphrase: []byte("secret"),
			sender:               senderSvc,
			fetcher:              fetcherSvc,
			unlocker:             unlockerSvc,
			id:                   1,
			err:                  "problem with parameters: no stores specified",
		},
		{
			name:                 "IDMissing",
			peers:                peersSvc,
			checker:              checkerSvc,
			stores:               stores,
			endpoints:            endpoints,
			generationPassphrase: []byte("secret"),
			sender:               senderSvc,
			fetcher:              fetcherSvc,
			unlocker:             unlockerSvc,
			err:                  "problem with parameters: no ID specified",
		},
		{
			name:                 "Good",
			peers:                peersSvc,
			checker:              checkerSvc,
			stores:               stores,
			endpoints:            endpoints,
			generationPassphrase: []byte("secret"),
			sender:               senderSvc,
			fetcher:              fetcherSvc,
			unlocker:             unlockerSvc,
			id:                   1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := standardprocess.New(ctx,
				standardprocess.WithMonitor(test.monitor),
				standardprocess.WithPeers(test.peers),
				standardprocess.WithChecker(test.checker),
				standardprocess.WithStores(test.stores),
				standardprocess.WithGenerationPassphrase(test.generationPassphrase),
				standardprocess.WithSender(test.sender),
				standardprocess.WithFetcher(test.fetcher),
				standardprocess.WithUnlocker(test.unlocker),
				standardprocess.WithID(test.id),
			)

			if test.err != "" {
				require.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOnPrepare(t *testing.T) {
	ctx := context.Background()
	service, err := createProcessService(ctx, 1)
	require.NoError(t, err)

	endpoints := []*core.Endpoint{
		{ID: 1, Name: "signer-test01", Port: 8881},
		{ID: 2, Name: "signer-test02", Port: 8882},
		{ID: 3, Name: "signer-test03", Port: 8883},
	}
	err = service.OnPrepare(ctx, 1, "Test/Test", []byte("test"), 2, endpoints)
	assert.NoError(t, err)
}

func TestOnPrepareTwice(t *testing.T) {
	ctx := context.Background()
	service, err := createProcessService(ctx, 1)
	require.NoError(t, err)

	endpoints := []*core.Endpoint{
		{ID: 1, Name: "signer-test01", Port: 8881},
		{ID: 2, Name: "signer-test02", Port: 8882},
		{ID: 3, Name: "signer-test03", Port: 8883},
	}
	err = service.OnPrepare(ctx, 1, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)

	// Duplicate account; should complain.
	err = service.OnPrepare(ctx, 1, "Test/Test", []byte("test"), 2, endpoints)
	assert.EqualError(t, err, standardprocess.ErrInProgress.Error())
}

func TestOnExecuteNotInProgress(t *testing.T) {
	ctx := context.Background()
	service, err := createProcessService(ctx, 1)
	require.NoError(t, err)

	// Attempt to execute a test that isn't in progres; should complain.
	err = service.OnExecute(ctx, 1, "Test/Test")
	assert.EqualError(t, err, standardprocess.ErrNotInProgress.Error())
}

func TestOnExecute(t *testing.T) {
	ctx := context.Background()
	service1, err := createProcessService(ctx, 1)
	mock.Processes[1] = service1
	require.NoError(t, err)
	service2, err := createProcessService(ctx, 2)
	mock.Processes[2] = service2
	require.NoError(t, err)
	service3, err := createProcessService(ctx, 3)
	require.NoError(t, err)
	mock.Processes[3] = service3

	endpoints := []*core.Endpoint{
		{ID: 1, Name: "signer-test01", Port: 8881},
		{ID: 2, Name: "signer-test02", Port: 8882},
		{ID: 3, Name: "signer-test03", Port: 8883},
	}
	err = service1.OnPrepare(ctx, 1, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)
	err = service2.OnPrepare(ctx, 2, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)
	err = service3.OnPrepare(ctx, 3, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)
	err = service1.OnExecute(ctx, 1, "Test/Test")
	assert.NoError(t, err)
}

func TestOnExecuteDuplicateContribution(t *testing.T) {
	ctx := context.Background()
	service1, err := createProcessService(ctx, 1)
	require.NoError(t, err)
	service2, err := createProcessService(ctx, 2)
	require.NoError(t, err)
	service3, err := createProcessService(ctx, 3)
	require.NoError(t, err)

	endpoints := []*core.Endpoint{
		{ID: 1, Name: "signer-test01", Port: 8881},
		{ID: 2, Name: "signer-test02", Port: 8882},
		{ID: 3, Name: "signer-test03", Port: 8883},
	}
	err = service1.OnPrepare(ctx, 1, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)
	err = service2.OnPrepare(ctx, 2, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)
	err = service3.OnPrepare(ctx, 3, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)
	err = service1.OnExecute(ctx, 1, "Test/Test")
	assert.NoError(t, err)

	err = service1.OnExecute(ctx, 1, "Test/Test")
	assert.True(t, strings.HasPrefix(err.Error(), "duplicate contribution from "))
}

func TestOnAbortNotInProgress(t *testing.T) {
	ctx := context.Background()
	service, err := createProcessService(ctx, 1)
	require.NoError(t, err)

	// Attempt to abort a test that isn't in progres; should complain.
	err = service.OnAbort(ctx, 1, "Test/Test")
	assert.EqualError(t, err, standardprocess.ErrNotInProgress.Error())
}

func TestOnAbort(t *testing.T) {
	ctx := context.Background()
	service, err := createProcessService(ctx, 1)
	require.NoError(t, err)
	endpoints := []*core.Endpoint{
		{ID: 1, Name: "signer-test01", Port: 8881},
		{ID: 2, Name: "signer-test02", Port: 8882},
		{ID: 3, Name: "signer-test03", Port: 8883},
	}
	err = service.OnPrepare(ctx, 1, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)

	err = service.OnAbort(ctx, 1, "Test/Test")
	assert.NoError(t, err)
}

func TestOnCommitNotInProgress(t *testing.T) {
	ctx := context.Background()
	service, err := createProcessService(ctx, 1)
	require.NoError(t, err)

	_, _, err = service.OnCommit(ctx, 1, "Test/Test", []byte("Confirmation data"))
	assert.EqualError(t, err, standardprocess.ErrNotInProgress.Error())
}

func TestOnCommitMissingContributions(t *testing.T) {
	ctx := context.Background()
	service, err := createProcessService(ctx, 1)
	require.NoError(t, err)

	endpoints := []*core.Endpoint{
		{ID: 1, Name: "signer-test01", Port: 8881},
		{ID: 2, Name: "signer-test02", Port: 8882},
		{ID: 3, Name: "signer-test03", Port: 8883},
	}
	err = service.OnPrepare(ctx, 1, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)

	_, _, err = service.OnCommit(ctx, 1, "Test/Test", []byte("Confirmation data"))
	assert.EqualError(t, err, "have 1 contributions ([1]) , need 3 ([1 2 3]), aborting")
}

func TestOnCommit(t *testing.T) {
	ctx := context.Background()
	service1, err := createProcessService(ctx, 1)
	require.NoError(t, err)
	service2, err := createProcessService(ctx, 2)
	require.NoError(t, err)
	service3, err := createProcessService(ctx, 3)
	require.NoError(t, err)

	endpoints := []*core.Endpoint{
		{ID: 1, Name: "signer-test01", Port: 8881},
		{ID: 2, Name: "signer-test02", Port: 8882},
		{ID: 3, Name: "signer-test03", Port: 8883},
	}
	err = service1.OnPrepare(ctx, 1, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)
	err = service2.OnPrepare(ctx, 2, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)
	err = service3.OnPrepare(ctx, 3, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)

	err = service1.OnExecute(ctx, 1, "Test/Test")
	assert.NoError(t, err)
	err = service2.OnExecute(ctx, 2, "Test/Test")
	assert.NoError(t, err)
	err = service3.OnExecute(ctx, 3, "Test/Test")
	assert.NoError(t, err)

	_, _, err = service1.OnCommit(ctx, 1, "Test/Test", []byte("Confirmation data"))
	assert.NoError(t, err)
	_, _, err = service2.OnCommit(ctx, 2, "Test/Test", []byte("Confirmation data"))
	assert.NoError(t, err)
	_, _, err = service3.OnCommit(ctx, 3, "Test/Test", []byte("Confirmation data"))
	assert.NoError(t, err)
}

func TestTimeout(t *testing.T) {
	ctx := context.Background()
	service, err := createProcessService(ctx, 1)
	require.NoError(t, err)

	endpoints := []*core.Endpoint{
		{ID: 1, Name: "signer-test01", Port: 8881},
		{ID: 2, Name: "signer-test02", Port: 8882},
		{ID: 3, Name: "signer-test03", Port: 8883},
	}
	err = service.OnPrepare(ctx, 1, "Test/Test", []byte("test"), 2, endpoints)
	require.NoError(t, err)

	// Timeout for requests is 10 seconds.
	time.Sleep(11 * time.Second)

	err = service.OnAbort(ctx, 1, "Test/Test")
	assert.EqualError(t, err, standardprocess.ErrNotInProgress.Error())
}
