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

	"github.com/google/uuid"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Wallet is a mock wallet structure.
type Wallet struct {
	id   uuid.UUID
	name string
}

// NewWallet creates a new wallet.
func NewWallet(name string) *Wallet {
	uuid, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}
	return &Wallet{
		id:   uuid,
		name: name,
	}
}

// ID provides the ID for the wallet.
func (a *Wallet) ID() uuid.UUID {
	return a.id
}

// Name provides the name for the wallet.
func (a *Wallet) Name() string {
	return a.name
}

// Type returns the type for the wallet.
func (a *Wallet) Type() string {
	return "mock"
}

// Version returns the version for the wallet.
func (a *Wallet) Version() uint {
	return 1
}

// Accounts returns the accounts in the wallet.
func (a *Wallet) Accounts(_ context.Context) <-chan e2wtypes.Account {
	ch := make(chan e2wtypes.Account, 1024)
	close(ch)
	return ch
}
