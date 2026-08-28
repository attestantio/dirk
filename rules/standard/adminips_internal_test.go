// Copyright © 2026 Attestant Limited.
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

package standard

import (
	"testing"

	"github.com/attestantio/dirk/testing/logger"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// TestParseAdminIPsLogVisibility confirms that an invalid admin IP entry is reported
// even when the module is configured with a log level above warn.  A malformed entry
// narrows the set of addresses trusted for voluntary exits, so it must not be silenced.
func TestParseAdminIPsLogVisibility(t *testing.T) {
	tests := []struct {
		name     string
		logLevel zerolog.Level
		entries  []string
		logMsg   string
	}{
		{
			name:     "InvalidCIDRAtFatalLevel",
			logLevel: zerolog.FatalLevel,
			entries:  []string{"10.0.0.0/33"},
			logMsg:   "Invalid admin IP CIDR range; ignoring entry",
		},
		{
			name:     "CIDRHostBitsAtDisabledLevel",
			logLevel: zerolog.Disabled,
			entries:  []string{"10.1.2.3/24"},
			logMsg:   "Admin IP CIDR range has non-zero host bits; ignoring entry",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := logger.NewLogCapture()
			log := zerologger.With().Logger().Level(test.logLevel)

			require.Empty(t, parseAdminIPs(test.entries, log))
			capture.AssertHasEntry(t, test.logMsg)
		})
	}
}
