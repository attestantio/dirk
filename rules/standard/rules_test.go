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
	"context"
	"os"
	"testing"

	standardrules "github.com/attestantio/dirk/rules/standard"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	os.Exit(m.Run())
}

func TestRules(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		logLevel zerolog.Level
		validIPs []string
		err      string
	}{
		{
			name: "PathEmpty",
			err:  `problem with parameters: no storage path specified`,
		},
		{
			name: "PathDisallowed",
			path: "/",
			err:  `Cannot write pid file "/LOCK": open /LOCK: permission denied`,
		},
		{
			name: "PathBad",
			path: "/no/such/path",
			err:  `Error Creating Dir: "/no/such/path": mkdir /no/such/path: no such file or directory`,
		},
		{
			name:     "PathGood",
			logLevel: zerolog.Disabled,
			path:     os.TempDir(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := standardrules.New(context.Background(),
				standardrules.WithLogLevel(test.logLevel),
				standardrules.WithStoragePath(test.path),
				standardrules.WithAdminIPs(test.validIPs),
			)
			if test.err != "" {
				assert.EqualError(t, err, test.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
				assert.NoError(t, res.Close(context.Background()))
			}
		})
	}
}
