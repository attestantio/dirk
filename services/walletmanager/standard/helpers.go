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

package standard

import (
	context "context"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/checker"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// preCheck carries out pre-checks for all account manager requests.
func (s *Service) preCheck(ctx context.Context, credentials *checker.Credentials, name string, action string) (e2wtypes.Wallet, core.Result) {
	// Fetch the account.
	wallet, result := s.fetchWallet(ctx, name)
	if result != core.ResultSucceeded {
		return nil, result
	}

	// Check if the account is allowed to carry out the requested action.
	result = s.checkAccess(ctx, credentials, wallet.Name(), action)
	if result != core.ResultSucceeded {
		return nil, result
	}

	return wallet, core.ResultSucceeded
}

// fetchWallet fetches a wallet by name.
func (s *Service) fetchWallet(ctx context.Context, name string) (e2wtypes.Wallet, core.Result) {
	if name == "" {
		log.Debug().Str("result", "denied").Msg("Wallet not supplied; denied")
		return nil, core.ResultDenied
	}

	wallet, err := s.fetcher.FetchWallet(ctx, name)
	if err != nil {
		log.Debug().Err(err).Str("result", "denied").Msg("Did not obtain wallet; denied")
		return nil, core.ResultDenied
	}

	return wallet, core.ResultSucceeded
}

// checkAccess returns true if the client can access the account.
func (s *Service) checkAccess(ctx context.Context, credentials *checker.Credentials, accountName string, action string) core.Result {
	if s.checker.Check(ctx, credentials, accountName, action) {
		return core.ResultSucceeded
	}
	return core.ResultDenied
}
