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

package accountmanager_test

import (
	context "context"
	"testing"

	"github.com/attestantio/dirk/services/accountmanager"
	mockaccountmanager "github.com/attestantio/dirk/services/accountmanager/mock"
	handler "github.com/attestantio/dirk/services/api/grpc/handlers/accountmanager"
	"github.com/attestantio/dirk/services/process"
	mockprocess "github.com/attestantio/dirk/services/process/mock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	accountManagerSvc := mockaccountmanager.New()
	processSvc, err := mockprocess.New()
	require.NoError(t, err)
	tests := []struct {
		name           string
		err            string
		logLevel       zerolog.Level
		accountManager accountmanager.Service
		process        process.Service
	}{
		{
			name: "Empty",
			err:  "problem with parameters: no account manager specified",
		},
		{
			name:     "AccountManagerMissing",
			logLevel: zerolog.Disabled,
			process:  processSvc,
			err:      "problem with parameters: no account manager specified",
		},
		{
			name:           "ProcessMissing",
			logLevel:       zerolog.Disabled,
			accountManager: accountManagerSvc,
			err:            "problem with parameters: no process specified",
		},
		{
			name:           "Good",
			logLevel:       zerolog.Disabled,
			accountManager: accountManagerSvc,
			process:        processSvc,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler, err := handler.New(context.Background(),
				handler.WithLogLevel(test.logLevel),
				handler.WithAccountManager(test.accountManager),
				handler.WithProcess(test.process),
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
