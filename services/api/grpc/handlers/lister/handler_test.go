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

package lister_test

import (
	context "context"
	"testing"

	handler "github.com/attestantio/dirk/services/api/grpc/handlers/lister"
	"github.com/attestantio/dirk/services/lister"
	mocklister "github.com/attestantio/dirk/services/lister/mock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	listerSvc := mocklister.New()
	tests := []struct {
		name     string
		err      string
		logLevel zerolog.Level
		lister   lister.Service
	}{
		{
			name: "Empty",
			err:  "problem with parameters: no lister specified",
		},
		{
			name:     "ListerMissing",
			logLevel: zerolog.Disabled,
			err:      "problem with parameters: no lister specified",
		},
		{
			name:     "Good",
			logLevel: zerolog.Disabled,
			lister:   listerSvc,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := handler.New(context.Background(),
				handler.WithLogLevel(test.logLevel),
				handler.WithLister(test.lister),
			)
			if test.err == "" {
				// Result expected.
				require.NoError(t, err)
				assert.NotNil(t, handler)
			} else {
				// Error expected.
				assert.EqualError(t, err, test.err)
			}
		})
	}
}
