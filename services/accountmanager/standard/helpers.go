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
	"fmt"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/checker"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// preCheck carries out pre-checks for all account manager requests.
func (s *Service) preCheck(ctx context.Context, credentials *checker.Credentials, name string, pubKey []byte, action string) (e2wtypes.Wallet, e2wtypes.Account, core.Result) {
	// Fetch the account.
	wallet, account, result := s.fetchAccount(ctx, name, pubKey)
	if result != core.ResultSucceeded {
		return nil, nil, result
	}
	accountName := fmt.Sprintf("%s/%s", wallet.Name(), account.Name())

	// Check if the account is allowed to carry out the requested action.
	result = s.checkAccess(ctx, credentials, accountName, action)
	if result != core.ResultSucceeded {
		return nil, nil, result
	}

	return wallet, account, core.ResultSucceeded
}

// fetchAccount fetches an account by either name or public key, depending on which has been supplied.
func (s *Service) fetchAccount(ctx context.Context, name string, pubKey []byte) (e2wtypes.Wallet, e2wtypes.Account, core.Result) {
	if name == "" && pubKey == nil {
		log.Warn().Str("result", "denied").Msg("Neither account nor public key supplied; denied")
		return nil, nil, core.ResultDenied
	}

	var wallet e2wtypes.Wallet
	var account e2wtypes.Account
	var err error
	if pubKey == nil {
		wallet, account, err = s.fetcher.FetchAccount(ctx, name)
	} else {
		wallet, account, err = s.fetcher.FetchAccountByKey(ctx, pubKey)
	}

	if err != nil {
		log.Warn().Err(err).Str("result", "denied").Msg("Did not obtain account; denied")
		return nil, nil, core.ResultDenied
	}

	return wallet, account, core.ResultSucceeded
}

// checkAccess returns true if the client can access the account.
func (s *Service) checkAccess(ctx context.Context, credentials *checker.Credentials, accountName string, action string) core.Result {
	if s.checker.Check(ctx, credentials, accountName, action) {
		return core.ResultSucceeded
	}
	return core.ResultDenied
}
