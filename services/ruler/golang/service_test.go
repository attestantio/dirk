// Copyright © 2021 Attestant Limited.
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

package golang_test

import (
	"context"
	"testing"

	mockrules "github.com/attestantio/dirk/rules/mock"
	"github.com/attestantio/dirk/services/locker/syncmap"
	"github.com/attestantio/dirk/services/metrics/prometheus"
	"github.com/attestantio/dirk/services/ruler/golang"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	ctx := context.Background()
	monitor, err := prometheus.New(ctx, prometheus.WithAddress("localhost:11111"))
	require.NoError(t, err)
	locker, err := syncmap.New(ctx)
	require.NoError(t, err)
	rules := mockrules.New()

	tests := []struct {
		name       string
		parameters []golang.Parameter
		err        string
	}{
		{
			name: "Nil",
			err:  "problem with parameters: no locker specified",
		},
		{
			name: "LockerMissing",
			parameters: []golang.Parameter{
				golang.WithLogLevel(zerolog.Disabled),
				golang.WithMonitor(monitor),
				golang.WithRules(rules),
			},
			err: "problem with parameters: no locker specified",
		},
		{
			name: "RulesMissing",
			parameters: []golang.Parameter{
				golang.WithLogLevel(zerolog.Disabled),
				golang.WithMonitor(monitor),
				golang.WithLocker(locker),
			},
			err: "problem with parameters: no rules specified",
		},
		{
			name: "Good",
			parameters: []golang.Parameter{
				golang.WithLogLevel(zerolog.Disabled),
				golang.WithMonitor(monitor),
				golang.WithLocker(locker),
				golang.WithRules(rules),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := golang.New(context.Background(), test.parameters...)
			if test.err == "" {
				require.Nil(t, err)
			} else {
				require.NotNil(t, err)
				require.EqualError(t, err, test.err)
			}
		})
	}
}
