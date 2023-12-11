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

package syncmap_test

import (
	"context"
	"sync"
	"testing"

	"github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/attestantio/dirk/services/metrics/prometheus"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	monitor, err := prometheus.New(ctx, prometheus.WithAddress("localhost:11111"))
	require.NoError(t, err)

	tests := []struct {
		name    string
		monitor metrics.LockerMonitor
		err     string
	}{
		{
			name: "Nil",
		},
		{
			name: "Good",
		},
		{
			name:    "WithMonitor",
			monitor: monitor,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := syncmap.New(context.Background(),
				syncmap.WithMonitor(test.monitor))
			if test.err == "" {
				require.Nil(t, err)
			} else {
				require.NotNil(t, err)
				require.EqualError(t, err, test.err)
			}
		})
	}
}

func TestLocking(t *testing.T) {
	ctx := context.Background()

	locker, err := syncmap.New(ctx, syncmap.WithLogLevel(zerolog.Disabled))
	require.Nil(t, err)

	testKey := [48]byte{}

	var wg sync.WaitGroup
	// Kick off 16 goroutines each incrementing the counter 1024 times.
	counter := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			for i := 0; i < 1024; i++ {
				locker.Lock(testKey)
				counter++
				locker.Unlock(testKey)
			}
			wg.Done()
		}()
	}
	wg.Wait()

	assert.Equal(t, 16*1024, counter)
}

func TestBadUnlock(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	ctx := context.Background()
	locker, err := syncmap.New(ctx)
	require.Nil(t, err)

	testKey := [48]byte{}

	assert.Panics(t, func() { locker.Unlock(testKey) })
}
