// Copyright © 2020, 2021 Attestant Limited.
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

package daemon_test

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/attestantio/dirk/testing/daemon"
	"github.com/stretchr/testify/require"
)

func TestDaemon(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx := context.Background()
	// #nosec G404
	port := uint32(12000 + rand.Intn(4000))
	_, path, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("signer-test01:%d", port)})
	require.NoError(t, err)
	os.RemoveAll(path)
}

func TestCancelDaemon(t *testing.T) {
	_, err := net.LookupIP("signer-test01")
	if err != nil {
		t.Skip("test signer addresses not configured; skipping test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	// #nosec G404
	port := uint32(12000 + rand.Intn(4000))
	_, path, err := daemon.New(ctx, "", 1, port, map[uint64]string{1: fmt.Sprintf("signer-test01:%d", port)})
	require.NoError(t, err)
	defer os.RemoveAll(path)
	require.True(t, endpointAlive(fmt.Sprintf("signer-test01:%d", port)))
	cancel()
	// Sleep for a second to allow graceful stop of the daemon.
	time.Sleep(time.Second)
	require.False(t, endpointAlive(fmt.Sprintf("signer-test01:%d", port)))
}

func endpointAlive(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}
