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
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/attestantio/dirk/core"
	receiverhandler "github.com/attestantio/dirk/services/api/grpc/handlers/receiver"
	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	mockchecker "github.com/attestantio/dirk/services/checker/mock"
	staticpeers "github.com/attestantio/dirk/services/peers/static"
	standardprocess "github.com/attestantio/dirk/services/process/standard"
	localunlocker "github.com/attestantio/dirk/services/unlocker/local"
	"github.com/attestantio/dirk/testing/resources"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

func TestNonInitiator(t *testing.T) {
	ctx := context.Background()
	base, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	require.NoError(t, resources.SetupCerts(base))
	defer os.RemoveAll(base)

	stores, err := core.InitStores(ctx, []*core.Store{
		{
			Name:     "Local",
			Type:     "filesystem",
			Location: filepath.Join(base, "wallets"),
		},
	})
	require.NoError(t, err)

	peers, err := staticpeers.New(ctx,
		staticpeers.WithPeers(map[uint64]string{
			1: "signer-test01:8881",
			2: "signer-test02:8882",
			3: "signer-test03:8883",
		}))
	require.NoError(t, err)

	checker, err := mockchecker.New()
	require.NoError(t, err)

	unlocker, err := localunlocker.New(context.Background(),
		localunlocker.WithAccountPassphrases([]string{"Test account 1 passphrase"}))
	require.NoError(t, err)

	// Create receiver 1.
	sender1, err := createSender(ctx, "signer-test01", base)
	require.NoError(t, err)
	process1, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checker),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(1),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(sender1),
		standardprocess.WithStores(stores),
		standardprocess.WithUnlocker(unlocker),
		standardprocess.WithGenerationPassphrase([]byte("test")),
	)
	require.NoError(t, err)

	receiver1, err := receiverhandler.New(ctx,
		receiverhandler.WithLogLevel(zerolog.Disabled),
		receiverhandler.WithPeers(peers),
		receiverhandler.WithProcess(process1),
	)
	require.NoError(t, err)

	// Create receiver 2.
	sender2, err := createSender(ctx, "signer-test02", base)
	require.NoError(t, err)
	process2, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checker),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(2),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(sender2),
		standardprocess.WithStores(stores),
		standardprocess.WithUnlocker(unlocker),
		standardprocess.WithGenerationPassphrase([]byte("test")),
	)
	require.NoError(t, err)

	receiver2, err := receiverhandler.New(ctx,
		receiverhandler.WithLogLevel(zerolog.Disabled),
		receiverhandler.WithPeers(peers),
		receiverhandler.WithProcess(process2),
	)
	require.NoError(t, err)

	// Create receiver 3.
	sender3, err := createSender(ctx, "signer-test03", base)
	require.NoError(t, err)
	process3, err := standardprocess.New(ctx,
		standardprocess.WithChecker(checker),
		standardprocess.WithGenerationPassphrase([]byte("secret")),
		standardprocess.WithID(3),
		standardprocess.WithPeers(peers),
		standardprocess.WithSender(sender3),
		standardprocess.WithStores(stores),
		standardprocess.WithUnlocker(unlocker),
		standardprocess.WithGenerationPassphrase([]byte("test")),
	)
	require.NoError(t, err)

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
}
