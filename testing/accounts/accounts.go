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

package accounts

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Setup sets up a number of well-known accounts in a store.
func Setup(ctx context.Context) (e2wtypes.Store, error) {
	if err := e2types.InitBLS(); err != nil {
		return nil, errors.Wrap(err, "failed to setup BLS")
	}

	// Create a store.
	store := scratch.New()
	encryptor := keystorev4.New()

	seed := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	}
	wallet1, err := hd.CreateWallet(ctx, "Wallet 1", []byte("Wallet 1 passphrase"), store, encryptor, seed)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create wallet 1")
	}
	if err := wallet1.(e2wtypes.WalletLocker).Unlock(ctx, []byte("Wallet 1 passphrase")); err != nil {
		return nil, errors.Wrap(err, "failed to unlock wallet 1")
	}
	accounts := []string{
		"Account 1",
		"Account 2",
		"Account 3",
		"Account 4",
		"A different account",
		"Deny this account",
	}
	for _, account := range accounts {
		if _, err := wallet1.(e2wtypes.WalletAccountCreator).CreateAccount(ctx, account, []byte(account+" passphrase")); err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to create account %s", account))
		}
	}
	if err := wallet1.(e2wtypes.WalletLocker).Lock(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to lock wallet")
	}

	wallet2, err := distributed.CreateWallet(ctx, "Wallet 2", store, encryptor)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create wallet 2")
	}
	if err := wallet2.(e2wtypes.WalletLocker).Unlock(ctx, nil); err != nil {
		return nil, errors.Wrap(err, "failed to create wallet 2")
	}
	if _, err := wallet2.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(
		ctx,
		"Account 1",
		[]byte{0x01, 0xe7, 0x48, 0xd0, 0x98, 0xd3, 0xbc, 0xb4, 0x77, 0xd6, 0x36, 0xf1, 0x9d, 0x51, 0x03, 0x99, 0xae, 0x18, 0x20, 0x5f, 0xad, 0xf9, 0x81, 0x4e, 0xe6, 0x70, 0x52, 0xf8, 0x8c, 0x1f, 0x77, 0xc0},
		2,
		[][]byte{
			{0xb3, 0xbb, 0x6b, 0x7a, 0x8d, 0x80, 0x9e, 0x59, 0x54, 0x44, 0x72, 0x85, 0x3d, 0x21, 0x94, 0x99, 0x76, 0x5b, 0xf0, 0x1d, 0x14, 0xde, 0x1e, 0x05, 0x49, 0xbd, 0x6f, 0xc2, 0xa8, 0x66, 0x27, 0xac, 0x90, 0x33, 0x26, 0x4c, 0x84, 0xcd, 0x50, 0x3b, 0x63, 0x39, 0xe3, 0x33, 0x47, 0x26, 0x56, 0x2f},
			{0xa9, 0xca, 0x9c, 0xf7, 0xfa, 0x2d, 0x0a, 0xb1, 0xd5, 0xd5, 0x2d, 0x2d, 0x8f, 0x79, 0xf6, 0x8c, 0x50, 0xc5, 0x29, 0x6b, 0xfc, 0xe8, 0x15, 0x46, 0xc2, 0x54, 0xdf, 0x68, 0xea, 0xac, 0x04, 0x18, 0x71, 0x7b, 0x2f, 0x9f, 0xc6, 0x65, 0x5c, 0xbb, 0xdd, 0xb1, 0x45, 0xda, 0xeb, 0x28, 0x2c, 0x00},
		},
		map[uint64]string{1: "foo:1", 2: "bar:2", 3: "baz:3"},
		[]byte("Account 1 passphrase")); err != nil {
		return nil, errors.Wrap(err, "failed to import account 1")
	}
	if err := wallet2.(e2wtypes.WalletLocker).Lock(ctx); err != nil {
		return nil, errors.Wrap(err, "failed to lock wallet")
	}

	return store, nil
}
