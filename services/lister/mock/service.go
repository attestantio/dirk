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

package mock

import (
	"context"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/checker"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the mock lister service.
type Service struct{}

// New creates a new mock lister service.
func New() *Service {
	return &Service{}
}

// ListAccounts lists accessible accounts given by the paths.
func (s *Service) ListAccounts(_ context.Context,
	_ *checker.Credentials,
	_ []string,
) (
	core.Result,
	[]e2wtypes.Account,
) {
	return core.ResultSucceeded, make([]e2wtypes.Account, 0)
}
