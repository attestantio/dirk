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
	context "context"
	"os"
	"path/filepath"
	"testing"

	"github.com/attestantio/dirk/core"
	receiverhandler "github.com/attestantio/dirk/services/api/grpc/handlers/receiver"
	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	memfetcher "github.com/attestantio/dirk/services/fetcher/mem"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	mocksender "github.com/attestantio/dirk/services/sender/mock"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	"github.com/attestantio/dirk/testing/mock"
	"github.com/attestantio/dirk/testing/resources"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

func TestNonInitiator(t *testing.T) {
	ctx := context.Background()
	base, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	require.NoError(t, resources.SetupCerts(base))
	defer os.RemoveAll(base)

	peers, err := staticpeers.New(ctx,
		staticpeers.WithPeers(map[uint64]string{
			1: "signer-test01:8881",
			2: "signer-test02:8882",
			3: "signer-test03:8883",
		}))
	require.NoError(t, err)

	checker, err := mockchecker.New(zerolog.Disabled)
	require.NoError(t, err)

	unlocker, err := localunlocker.New(context.Background(),
		localunlocker.WithAccountPassphrases([]string{"Test account 1 passphrase"}))
	require.NoError(t, err)

	// Create receiver 1.
	stores1, err := core.InitStores(ctx, []*core.Store{
		{
			Name:     "Local",
			Type:     "filesystem",
			Location: filepath.Join(base, "wallets1"),
		},
	})
	require.NoError(t, err)
	_, err = distributed.CreateWallet(ctx, "Test", stores1[0], keystorev4.New())
	require.NoError(t, err)
	fetcher1, err := memfetcher.New(ctx,
		memfetcher.WithStores(stores1),
	)
	require.NoError(t, err)
	process1, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checker),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(1),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(mocksender.New(1)),
		standardprocess.WithFetcher(fetcher1),
		standardprocess.WithStores(stores1),
		standardprocess.WithUnlocker(unlocker),
		standardprocess.WithGenerationPassphrase([]byte("test")),
	)
	require.NoError(t, err)
	mock.Processes[1] = process1

	receiver1, err := receiverhandler.New(ctx,
		receiverhandler.WithLogLevel(zerolog.Disabled),
		receiverhandler.WithPeers(peers),
		receiverhandler.WithProcess(process1),
	)
	require.NoError(t, err)

	// Create receiver 2.
	stores2, err := core.InitStores(ctx, []*core.Store{
		{
			Name:     "Local",
			Type:     "filesystem",
			Location: filepath.Join(base, "wallets2"),
		},
	})
	require.NoError(t, err)
	_, err = distributed.CreateWallet(ctx, "Test", stores2[0], keystorev4.New())
	require.NoError(t, err)
	fetcher2, err := memfetcher.New(ctx,
		memfetcher.WithStores(stores2),
	)
	require.NoError(t, err)
	process2, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checker),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(2),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(mocksender.New(2)),
		standardprocess.WithFetcher(fetcher2),
		standardprocess.WithStores(stores2),
		standardprocess.WithUnlocker(unlocker),
		standardprocess.WithGenerationPassphrase([]byte("test")),
	)
	require.NoError(t, err)
	mock.Processes[2] = process2

	receiver2, err := receiverhandler.New(ctx,
		receiverhandler.WithLogLevel(zerolog.Disabled),
		receiverhandler.WithPeers(peers),
		receiverhandler.WithProcess(process2),
	)
	require.NoError(t, err)

	// Create receiver 3.
	stores3, err := core.InitStores(ctx, []*core.Store{
		{
			Name:     "Local",
			Type:     "filesystem",
			Location: filepath.Join(base, "wallets3"),
		},
	})
	require.NoError(t, err)
	_, err = distributed.CreateWallet(ctx, "Test", stores3[0], keystorev4.New())
	require.NoError(t, err)
	fetcher3, err := memfetcher.New(ctx,
		memfetcher.WithStores(stores3),
	)
	require.NoError(t, err)
	process3, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checker),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(3),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(mocksender.New(3)),
		standardprocess.WithFetcher(fetcher3),
		standardprocess.WithStores(stores3),
		standardprocess.WithUnlocker(unlocker),
		standardprocess.WithGenerationPassphrase([]byte("test")),
	)
	require.NoError(t, err)
	mock.Processes[3] = process3

	receiver3, err := receiverhandler.New(ctx,
		receiverhandler.WithLogLevel(zerolog.Disabled),
		receiverhandler.WithPeers(peers),
		receiverhandler.WithProcess(process3),
	)
	require.NoError(t, err)

	participants := []*pb.Endpoint{
		{Id: 1, Name: "signer-test01", Port: 8881},
		{Id: 2, Name: "signer-test02", Port: 8882},
		{Id: 3, Name: "signer-test03", Port: 8883},
	}
	ctx = context.WithValue(ctx, &interceptors.ClientName{}, "signer-test01")
	prepareReq := &pb.PrepareRequest{
		Account:      "Test/Test",
		Threshold:    2,
		Participants: participants,
	}
	_, err = receiver1.Prepare(ctx, prepareReq)
	require.NoError(t, err)
	_, err = receiver2.Prepare(ctx, prepareReq)
	require.NoError(t, err)
	_, err = receiver3.Prepare(ctx, prepareReq)
	require.NoError(t, err)

	executeReq := &pb.ExecuteRequest{
		Account: "Test/Test",
	}
	_, err = receiver1.Execute(ctx, executeReq)
	require.NoError(t, err)
	_, err = receiver2.Execute(ctx, executeReq)
	require.NoError(t, err)
	_, err = receiver3.Execute(ctx, executeReq)
	require.NoError(t, err)

	commitReq := &pb.CommitRequest{
		Account: "Test/Test",
	}
	commit1Resp, err := receiver1.Commit(ctx, commitReq)
	require.NoError(t, err)
	commit2Resp, err := receiver2.Commit(ctx, commitReq)
	require.NoError(t, err)
	commit3Resp, err := receiver3.Commit(ctx, commitReq)
	require.NoError(t, err)
	assert.Equal(t, commit1Resp.PublicKey, commit2Resp.PublicKey)
	assert.Equal(t, commit2Resp.PublicKey, commit3Resp.PublicKey)

	// Ensure the account has been created.
	_, createdAccount1, err := fetcher1.FetchAccount(ctx, "Test/Test")
	require.NoError(t, err)
	require.Equal(t, commit1Resp.PublicKey, createdAccount1.(e2wtypes.DistributedAccount).CompositePublicKey().Marshal())
}
