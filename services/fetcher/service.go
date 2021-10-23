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

package fetcher

import (
	"context"

	types "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is the interface for a wallet and account fetching service.
type Service interface {
	FetchWallet(ctx context.Context, path string) (types.Wallet, error)
	FetchAccount(ctx context.Context, path string) (types.Wallet, types.Account, error)
	FetchAccountByKey(ctx context.Context, pubKey []byte) (types.Wallet, types.Account, error)
	FetchAccounts(ctx context.Context, path string) (map[string]types.Account, error)
	AddAccount(ctx context.Context, wallet types.Wallet, account types.Account) error
}
