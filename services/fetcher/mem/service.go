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

package mem

import (
	"bytes"
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
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	hd "github.com/wealdtech/go-eth2-wallet-hd/v2"
	nd "github.com/wealdtech/go-eth2-wallet-nd/v2"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service contains an in-memory cache of wallets and accounts.
type Service struct {
	monitor       metrics.FetcherMonitor
	stores        []e2wtypes.Store
	pubKeyPaths   map[[48]byte]string
	pubKeyPathsMx sync.RWMutex
	wallets       map[string]e2wtypes.Wallet
	walletsMx     sync.RWMutex
	accounts      map[string]e2wtypes.Account
	accountsMx    sync.RWMutex
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

	s := &Service{
		monitor:     parameters.monitor,
		stores:      parameters.stores,
		pubKeyPaths: make(map[[48]byte]string),
		wallets:     make(map[string]e2wtypes.Wallet),
		accounts:    make(map[string]e2wtypes.Account),
	}

	return s, nil
}

// FetchWallet fetches the wallet.
func (s *Service) FetchWallet(ctx context.Context, path string) (e2wtypes.Wallet, error) {
	log := log.With().Str("path", path).Logger()
	log.Trace().Msg("Fetching wallet")

	walletName, _, err := e2wallet.WalletAndAccountNames(path)
	if err != nil {
		log.Warn().Msg("Invalid path")
		return nil, errors.Wrap(err, "invalid path")
	}

	// Return wallet from cache if present.
	s.walletsMx.RLock()
	wallet, exists := s.wallets[walletName]
	s.walletsMx.RUnlock()
	if exists {
		log.Trace().Msg("Wallet found in cache")
		return wallet, nil
	}

	for _, store := range s.stores {
		wallet, err = e2wallet.OpenWallet(walletName, e2wallet.WithStore(store))
		if err == nil {
			break
		}
	}
	if wallet == nil {
		log.Warn().Msg("Wallet not found")
		return nil, errors.New("wallet not found")
	}

	s.walletsMx.Lock()
	s.wallets[walletName] = wallet
	s.walletsMx.Unlock()

	log.Trace().Msg("Wallet found in store")
	return wallet, nil
}

// FetchAccount fetches the account given its name.
func (s *Service) FetchAccount(ctx context.Context, path string) (e2wtypes.Wallet, e2wtypes.Account, error) {
	log := log.With().Str("path", path).Logger()
	log.Trace().Msg("Fetching account")

	// Fetch account and store in cache if present.
	wallet, err := s.FetchWallet(ctx, path)
	if err != nil {
		return nil, nil, err
	}

	// Return account from cache if present.
	s.accountsMx.RLock()
	account, exists := s.accounts[path]
	s.accountsMx.RUnlock()
	if exists {
		log.Trace().Msg("Account found in cache")
		return wallet, account, nil
	}

	// Need to fetch manually
	_, accountName, err := e2wallet.WalletAndAccountNames(path)
	if err != nil {
		log.Warn().Msg("Invalid path")
		return nil, nil, errors.Wrap(err, "invalid path")
	}
	accountByNameProvider, isProvider := wallet.(e2wtypes.WalletAccountByNameProvider)
	if !isProvider {
		log.Warn().Msg("Account cannot be fetched by name")
		return nil, nil, errors.New("wallet does not allow fetching account by name")
	}
	account, err = accountByNameProvider.AccountByName(ctx, accountName)
	if err != nil {
		log.Warn().Err(err).Msg("Account not found")
		return nil, nil, errors.Wrap(err, "failed to obtain account by name")
	}
	s.accountsMx.Lock()
	s.accounts[path] = account
	s.accountsMx.Unlock()
	s.pubKeyPathsMx.Lock()
	s.pubKeyPaths[bytesutil.ToBytes48(account.(e2wtypes.AccountPublicKeyProvider).PublicKey().Marshal())] = fmt.Sprintf("%s/%s", wallet.Name(), account.Name())
	s.pubKeyPathsMx.Unlock()

	log.Trace().Msg("Account found in store")
	return wallet, account, nil
}

// FetchAccountByKey fetches the account given its public key.
func (s *Service) FetchAccountByKey(ctx context.Context, pubKey []byte) (e2wtypes.Wallet, e2wtypes.Account, error) {
	log := log.With().Str("public_key", fmt.Sprintf("%#x", pubKey)).Logger()
	log.Trace().Msg("Fetching account by key")

	// See if we already know this key.
	s.pubKeyPathsMx.RLock()
	account, exists := s.pubKeyPaths[bytesutil.ToBytes48(pubKey)]
	s.pubKeyPathsMx.RUnlock()
	if exists {
		log.Trace().Msg("Account found in cache")
		return s.FetchAccount(ctx, account)
	}

	// We don't.  Trawl wallets to find the result.
	encryptor := keystorev4.New()
	for _, store := range s.stores {
		for walletBytes := range store.RetrieveWallets() {
			wallet, err := walletFromBytes(ctx, walletBytes, store, encryptor)
			if err != nil {
				log.Error().Err(err).Msg("Failed to decode wallet")
				continue
			}
			for account := range wallet.Accounts(ctx) {
				if bytes.Equal(account.(e2wtypes.AccountPublicKeyProvider).PublicKey().Marshal(), pubKey) {
					// Found it.
					path := fmt.Sprintf("%s/%s", wallet.Name(), account.Name())
					s.accountsMx.Lock()
					s.accounts[path] = account
					s.accountsMx.Unlock()
					s.pubKeyPathsMx.Lock()
					s.pubKeyPaths[bytesutil.ToBytes48(pubKey)] = path
					s.pubKeyPathsMx.Unlock()

					log.Trace().Msg("Account found in store")
					return wallet, account, nil
				}
			}
		}
	}

	log.Trace().Msg("Account not found")
	return nil, nil, errors.New("account not found")
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
	default:
		return nil, fmt.Errorf("unsupported wallet type %q", info.Type)
	}
	return wallet, err
}
