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
	"strings"
	"testing"

	standardrules "github.com/attestantio/dirk/rules/standard"
	"github.com/attestantio/dirk/testing/logger"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestRules(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		logLevel zerolog.Level
		validIPs []string
		err      []string
		// logMsg, if set, is a warning message that must have been logged (rather than
		// causing New() to fail).
		logMsg string
	}{
		{
			name: "PathEmpty",
			err:  []string{`problem with parameters: no storage path specified`},
		},
		{
			name: "PathDisallowed",
			path: "/",
			err:  []string{`Cannot write pid file "/LOCK": open /LOCK: read-only file system`},
		},
		{
			name: "PathBad",
			path: "/no/such/path",
			err: []string{`Error Creating Dir: "/no/such/path": mkdir /no/such/path: no such file or directory`,
				`Cannot write pid file "/LOCK": open /LOCK: permission denied`}, // Different errors on different OSes
		},
		{
			name:     "PathGood",
			logLevel: zerolog.Disabled,
			path:     os.TempDir(),
		},
		{
			name:     "AdminIPsCIDRGood",
			logLevel: zerolog.Disabled,
			path:     os.TempDir(),
			validIPs: []string{"1.2.3.4", "2001:db8::1", "10.0.0.0/8", "::1/128"},
		},
		{
			// Invalid entries must not prevent Dirk from starting; they are logged and
			// skipped instead, as they can only narrow the set of trusted addresses.
			name:     "AdminIPsBad",
			logLevel: zerolog.ErrorLevel,
			path:     os.TempDir(),
			validIPs: []string{"not-an-ip"},
			logMsg:   "Invalid admin IP address; ignoring entry",
		},
		{
			name:     "AdminIPsBadCIDR",
			logLevel: zerolog.ErrorLevel,
			path:     os.TempDir(),
			validIPs: []string{"10.0.0.0/33"},
			logMsg:   "Invalid admin IP CIDR range; ignoring entry",
		},
		{
			// "10.1.2.3/24" has non-zero host bits: net.ParseCIDR would otherwise
			// silently widen this to the whole "10.1.2.0/24" network.
			name:     "AdminIPsCIDRHostBits",
			logLevel: zerolog.ErrorLevel,
			path:     os.TempDir(),
			validIPs: []string{"10.1.2.3/24"},
			logMsg:   "Admin IP CIDR range has non-zero host bits; ignoring entry",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			res, err := standardrules.New(context.Background(),
				standardrules.WithLogLevel(test.logLevel),
				standardrules.WithStoragePath(test.path),
				standardrules.WithAdminIPs(test.validIPs),
			)
			if len(test.err) > 0 {
				found := strings.ContainsAny(err.Error(), strings.Join(test.err, ","))
				assert.True(t, found, "error should contain one of: %s", strings.Join(test.err, ","))
			} else {
				require.NoError(t, err)
				require.NotNil(t, res)
				if test.logMsg != "" {
					capture.AssertHasEntry(t, test.logMsg)
				}
				assert.NoError(t, res.Close(context.Background()))
			}
		})
	}
}
