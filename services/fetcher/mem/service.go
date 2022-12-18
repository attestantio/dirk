// Copyright © 2020, 2021 Attestant Limited.
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

package mem

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/attestantio/dirk/services/metrics"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-bytesutil"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	nd "github.com/wealdtech/go-eth2-wallet-nd/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service contains an in-memory cache of wallets and accounts.
type Service struct {
	monitor        metrics.FetcherMonitor
	pubKeyPaths    map[[48]byte]string
	wallets        map[string]e2wtypes.Wallet
	walletAccounts map[string]map[string]e2wtypes.Account
	// Read-write copy of some information to allow for
	// dynamic addition of accounts without requiring mutexes
	// for normal access.
	rwPubKeyPaths    map[[48]byte]string
	rwWalletAccounts map[string]map[string]e2wtypes.Account
	rwMu             sync.RWMutex
}

// module-wide log.
var log zerolog.Logger

// New creates a new in-memory fetcher.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "fetcher").Str("impl", "mem").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	wallets, walletAccounts, pubKeyPaths, err := populateCaches(ctx, parameters.stores, parameters.encryptor)
	if err != nil {
		return nil, errors.Wrap(err, "failed to populate caches")
	}

	s := &Service{
		monitor:          parameters.monitor,
		pubKeyPaths:      pubKeyPaths,
		wallets:          wallets,
		walletAccounts:   walletAccounts,
		rwPubKeyPaths:    make(map[[48]byte]string),
		rwWalletAccounts: make(map[string]map[string]e2wtypes.Account),
	}

	return s, nil
}

// FetchWallet fetches the wallet.
func (s *Service) FetchWallet(ctx context.Context, path string) (e2wtypes.Wallet, error) {
	walletName, _, err := e2wallet.WalletAndAccountNames(path)
	if err != nil {
		log.Warn().Msg("Invalid path")
		return nil, errors.Wrap(err, "invalid path")
	}

	wallet, exists := s.wallets[walletName]
	if exists {
		log.Trace().Str("wallet", walletName).Msg("Wallet found in cache")
		return wallet, nil
	}
	log.Trace().Str("wallet", walletName).Msg("Wallet not found in cache")

	return nil, errors.New("wallet not found")
}

// FetchAccount fetches the account given its name.
func (s *Service) FetchAccount(ctx context.Context, path string) (e2wtypes.Wallet, e2wtypes.Account, error) {
	// Fetch the account name.
	walletName, accountName, err := e2wallet.WalletAndAccountNames(path)
	if err != nil {
		log.Warn().Msg("Invalid path")
		return nil, nil, errors.Wrap(err, "invalid path")
	}

	wallet, exists := s.wallets[walletName]
	if !exists {
		return nil, nil, errors.New("failed to find wallet")
	}

	walletAccounts, exists := s.walletAccounts[walletName]
	if exists {
		account, exists := walletAccounts[accountName]
		if exists {
			return wallet, account, nil
		}
	}

	// Try the rw cache.
	s.rwMu.RLock()
	defer s.rwMu.RUnlock()
	walletAccounts, exists = s.rwWalletAccounts[walletName]
	if exists {
		account, exists := walletAccounts[accountName]
		if exists {
			return wallet, account, nil
		}
	}

	return nil, nil, errors.New("failed to find account")
}

// FetchAccountByKey fetches the account given its public key.
func (s *Service) FetchAccountByKey(ctx context.Context, pubKey []byte) (e2wtypes.Wallet, e2wtypes.Account, error) {
	path, exists := s.pubKeyPaths[bytesutil.ToBytes48(pubKey)]
	if !exists {
		s.rwMu.RLock()
		path, exists = s.rwPubKeyPaths[bytesutil.ToBytes48(pubKey)]
		s.rwMu.RUnlock()
		if !exists {
			return nil, nil, errors.New("public key not known")
		}
	}

	return s.FetchAccount(ctx, path)
}

// FetchAccounts fetches all accounts for the wallet.
func (s *Service) FetchAccounts(ctx context.Context, path string) (map[string]e2wtypes.Account, error) {
	// Fetch the wallet name.
	walletName, _, err := e2wallet.WalletAndAccountNames(path)
	if err != nil {
		log.Warn().Msg("Invalid path")
		return nil, errors.Wrap(err, "invalid path")
	}

	walletAccounts, exists := s.walletAccounts[walletName]
	s.rwMu.RLock()
	defer s.rwMu.RUnlock()
	rwWalletAccounts, rwExists := s.rwWalletAccounts[walletName]
	if !exists && !rwExists {
		return nil, errors.New("found no accounts for wallet")
	}
	if rwExists {
		allWalletAccounts := make(map[string]e2wtypes.Account, len(walletAccounts)+len(rwWalletAccounts))
		for k, v := range walletAccounts {
			allWalletAccounts[k] = v
		}
		for k, v := range rwWalletAccounts {
			allWalletAccounts[k] = v
		}
		walletAccounts = allWalletAccounts
	}

	return walletAccounts, nil
}

// AddAccount adds an account to the fetcher's internal stores.
func (s *Service) AddAccount(ctx context.Context, wallet e2wtypes.Wallet, account e2wtypes.Account) error {
	s.rwMu.Lock()
	defer s.rwMu.Unlock()
	if _, exists := s.wallets[wallet.Name()]; !exists {
		return errors.New("failed to find wallet")
	}
	if _, exists := s.rwWalletAccounts[wallet.Name()]; !exists {
		s.rwWalletAccounts[wallet.Name()] = make(map[string]e2wtypes.Account)
	}
	s.rwWalletAccounts[wallet.Name()][account.Name()] = account

	path := fmt.Sprintf("%s/%s", wallet.Name(), account.Name())
	s.rwPubKeyPaths[bytesutil.ToBytes48(account.PublicKey().Marshal())] = path

	return nil
}

// populateCaches populates wallet and account caches for the service.
func populateCaches(ctx context.Context,
	stores []e2wtypes.Store,
	encryptor e2wtypes.Encryptor,
) (
	map[string]e2wtypes.Wallet,
	map[string]map[string]e2wtypes.Account,
	map[[48]byte]string,
	error,
) {
	log.Trace().Msg("Populating fetcher caches")

	wallets := make(map[string]e2wtypes.Wallet)
	walletAccounts := make(map[string]map[string]e2wtypes.Account)
	pubKeyPaths := make(map[[48]byte]string)
	var mu sync.Mutex

	var wg sync.WaitGroup
	var err error
	for _, store := range stores {
		for walletBytes := range store.RetrieveWallets() {
			wg.Add(1)
			go func(
				mu *sync.Mutex,
				store e2wtypes.Store,
				walletBytes []byte,
				wallets map[string]e2wtypes.Wallet,
				walletAccounts map[string]map[string]e2wtypes.Account,
				pubKeyPaths map[[48]byte]string,
				wg *sync.WaitGroup) {
				defer wg.Done()
				var wallet e2wtypes.Wallet
				wallet, err = walletFromBytes(ctx, walletBytes, store, encryptor)
				if err != nil {
					log.Error().Err(err).Msg("failed to decode wallet")
					return
				}
				mu.Lock()
				wallets[wallet.Name()] = wallet
				mu.Unlock()
				log.Trace().Str("wallet", wallet.Name()).Msg("Found wallet")

				// Add each individual accounts.
				accounts := make(map[string]e2wtypes.Account)
				for account := range wallet.Accounts(ctx) {
					accounts[account.Name()] = account
					path := fmt.Sprintf("%s/%s", wallet.Name(), account.Name())
					mu.Lock()
					pubKeyPaths[bytesutil.ToBytes48(account.PublicKey().Marshal())] = path
					mu.Unlock()
					log.Trace().Str("wallet", wallet.Name()).Str("account", account.Name()).Msg("Stored account")
				}
				mu.Lock()
				walletAccounts[wallet.Name()] = accounts
				mu.Unlock()
			}(&mu, store, walletBytes, wallets, walletAccounts, pubKeyPaths, &wg)
		}
	}
	wg.Wait()

	if err != nil {
		return nil, nil, nil, err
	}
	return wallets, walletAccounts, pubKeyPaths, nil
}

func walletFromBytes(ctx context.Context, data []byte, store e2wtypes.Store, encryptor e2wtypes.Encryptor) (e2wtypes.Wallet, error) {
	if store == nil {
		return nil, errors.New("no store provided")
	}
	if encryptor == nil {
		return nil, errors.New("no encryptor provided")
	}
	if data == nil {
		return nil, errors.New("no data provided")
	}

	type walletInfo struct {
		ID   uuid.UUID `json:"uuid"`
		Name string    `json:"name"`
		Type string    `json:"type"`
	}

	info := &walletInfo{}
	err := json.Unmarshal(data, info)
	if err != nil {
		return nil, err
	}
	var wallet e2wtypes.Wallet
	switch info.Type {
	case "nd", "non-deterministic":
		wallet, err = nd.DeserializeWallet(ctx, data, store, encryptor)
	case "hd", "hierarchical deterministic":
		wallet, err = hd.DeserializeWallet(ctx, data, store, encryptor)
	case "distributed":
		wallet, err = distributed.DeserializeWallet(ctx, data, store, encryptor)
	default:
		return nil, fmt.Errorf("unsupported wallet type %q", info.Type)
	}
	return wallet, err
}
