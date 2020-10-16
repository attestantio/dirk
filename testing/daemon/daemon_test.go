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

package daemon_test

import (
	"context"
	"testing"

	"github.com/attestantio/dirk/testing/daemon"
	"github.com/stretchr/testify/require"
)

func TestDaemon(t *testing.T) {
	ctx := context.Background()
	_, _, err := daemon.New(ctx, "", 1, 12345, map[uint64]string{1: "server-test01:12345"})
	require.NoError(t, err)
}
