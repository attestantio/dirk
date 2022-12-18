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
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/fetcher"
	"github.com/attestantio/dirk/services/peers"
	"github.com/attestantio/dirk/services/sender"
	"github.com/attestantio/dirk/services/unlocker"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
	distributed "github.com/wealdtech/go-eth2-wallet-distributed"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// Service is used to manage the process of distributed key generation operations.
type Service struct {
	checkerSvc           checker.Service
	fetcherSvc           fetcher.Service
	senderSvc            sender.Service
	peersSvc             peers.Service
	unlockerSvc          unlocker.Service
	encryptor            e2wtypes.Encryptor
	id                   uint64
	stores               []e2wtypes.Store
	generationPassphrase []byte

	generations   map[string]*generation
	generationsMu sync.RWMutex
}

// module-wide log.
var log zerolog.Logger

// New creates a new process service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "process").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		checkerSvc:           parameters.checker,
		fetcherSvc:           parameters.fetcher,
		unlockerSvc:          parameters.unlocker,
		senderSvc:            parameters.sender,
		peersSvc:             parameters.peers,
		id:                   parameters.id,
		stores:               parameters.stores,
		encryptor:            parameters.encryptor,
		generationPassphrase: parameters.generationPassphrase,
		generations:          make(map[string]*generation),
	}

	return s, nil
}

// OnPrepare is called when we receive a request from the given participant to prepare for DKG.
func (s *Service) OnPrepare(ctx context.Context,
	sender uint64,
	account string,
	passphrase []byte,
	threshold uint32,
	participants []*core.Endpoint) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "services.process.OnPrepare")
	defer span.Finish()
	log.Trace().Uint64("sender_id", sender).Str("account", account).Msg("Preparing for distributed key generation")

	s.generationsMu.Lock()
	defer s.generationsMu.Unlock()

	if _, err := s.getGeneration(ctx, account); err == nil {
		log.Debug().Uint64("sender_id", sender).Str("account", account).Msg("Already in progress")
		return ErrInProgress
	}

	s.generations[account] = &generation{
		processStarted: time.Now(),
		id:             s.id,
		account:        account,
		passphrase:     passphrase,
		threshold:      threshold,
		participants:   participants,
		sharedSecrets:  make(map[uint64]bls.SecretKey),
		sharedVVecs:    make(map[uint64][]bls.PublicKey),
	}

	if err := s.contribution(ctx, s.generations[account]); err != nil {
		log.Debug().Uint64("sender_id", sender).Str("account", account).Msg("Failed to generate our own contribution")
		return errors.Wrap(err, "failed to generate own contribution")
	}

	return nil
}

// OnExecute is called when we receive a request from the given participant to execute the given DKG.
func (s *Service) OnExecute(ctx context.Context, sender uint64, account string) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "services.process.OnExecute")
	defer span.Finish()
	log.Trace().Uint64("sender", sender).Str("account", account).Msg("Executing")

	s.generationsMu.Lock()
	defer s.generationsMu.Unlock()

	generation, err := s.getGeneration(ctx, account)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotInProgress
		}
		return err
	}

	// We need to swap secrets with all the other participants.
	// Initiate calls to any participants with a higher ID than us.
	verificationVector := generation.sharedVVecs[generation.id]
	for id, distributionSecret := range generation.distributionSecrets {
		if id > s.id {
			peer, err := s.peersSvc.Peer(id)
			if err != nil {
				return errors.Wrap(err, "failed to obtain peer")
			}
			log.Trace().Uint64("id", s.id).Uint64("peer", id).Msg("Initiating contribution swap")
			recipientSecret, recipientVVec, err := s.senderSvc.SendContribution(ctx, peer, account, distributionSecret, verificationVector)
			if err != nil {
				return errors.Wrap(err, "failed to send contribution")
			}
			if !verifyContribution(generation.id, recipientSecret, recipientVVec) {
				log.Warn().Msg("Contribution invalid")
				return fmt.Errorf("invalid contribution from %d", id)
			}
			if _, exists := generation.sharedSecrets[id]; exists {
				return fmt.Errorf("duplicate contribution from %d", id)
			}
			generation.sharedSecrets[id] = recipientSecret
			generation.sharedVVecs[id] = recipientVVec
		}
	}
	return nil
}

// OnCommit is called when we receive a request from the given participant to commit the given DKG.
func (s *Service) OnCommit(ctx context.Context, sender uint64, account string, confirmationData []byte) ([]byte, []byte, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "services.process.OnCommit")
	defer span.Finish()

	s.generationsMu.Lock()
	defer s.generationsMu.Unlock()

	generation, err := s.getGeneration(ctx, account)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, ErrNotInProgress
	}

	if len(generation.sharedSecrets) != len(generation.participants) {
		contributedParticipants := make([]uint64, 0)
		for k := range generation.sharedSecrets {
			contributedParticipants = append(contributedParticipants, k)
		}
		allParticipants := make([]uint64, len(generation.participants))
		for k := range generation.participants {
			allParticipants[k] = generation.participants[k].ID
		}

		return nil, nil, fmt.Errorf("have %d contributions (%v) , need %d (%v), aborting", len(generation.sharedSecrets), contributedParticipants, len(allParticipants), allParticipants)
	}
	if len(generation.sharedVVecs) != len(generation.participants) {
		return nil, nil, fmt.Errorf("have %d contributions, need %d, aborting", len(generation.sharedVVecs), len(generation.participants))
	}

	privateKey := bls.SecretKey{}
	for k := range generation.sharedSecrets {
		sharedSecret := generation.sharedSecrets[k]
		privateKey.Add(&sharedSecret)
	}
	aggregateVVec := make([]bls.PublicKey, generation.threshold)
	for _, sharedVVec := range generation.sharedVVecs {
		for i := range sharedVVec {
			aggregateVVec[i].Add(&sharedVVec[i])
		}
	}

	passphrase := generation.passphrase
	if passphrase == nil {
		passphrase = s.generationPassphrase
	}
	err = s.storeDistributedKey(ctx, generation.account, passphrase, privateKey, generation.threshold, aggregateVVec, generation.participants)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create key")
		return nil, nil, errors.Wrap(err, ErrNotCreated.Error())
	}

	// Attempt to retrieve the key to ensure it has been stored properly.
	walletName, accountName, err := e2wallet.WalletAndAccountNames(account)
	if err != nil {
		log.Warn().Err(err).Str("path", account).Msg("Failed to obtain wallet and accout names from path")
		return nil, nil, ErrNotCreated
	}
	retrievedWallet, err := distributed.OpenWallet(ctx, walletName, s.stores[0], s.encryptor)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to retrieve wallet for created account")
		return nil, nil, ErrNotCreated
	}
	accountByNameProvider, isProvider := retrievedWallet.(e2wtypes.WalletAccountByNameProvider)
	if !isProvider {
		log.Info().Msg("Wallet does not support fetching accounts by name")
		return nil, nil, errors.New("wallet does not support fetching accounts by name")
	}
	_, err = accountByNameProvider.AccountByName(ctx, accountName)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to retrieve created account")
		return nil, nil, ErrNotCreated
	}

	sig := privateKey.SignByte(confirmationData)

	delete(s.generations, account)
	return aggregateVVec[0].Serialize(), sig.Serialize(), nil
}

// OnAbort is called when we receive a request from the given participant to abort the given DKG.
func (s *Service) OnAbort(ctx context.Context, sender uint64, account string) error {
	span, ctx := opentracing.StartSpanFromContext(ctx, "services.process.OnAbort")
	defer span.Finish()

	s.generationsMu.Lock()
	defer s.generationsMu.Unlock()

	_, err := s.getGeneration(ctx, account)
	if errors.Is(err, ErrNotFound) {
		return ErrNotInProgress
	}

	delete(s.generations, account)

	return nil
}

// OnContribute is called when we need to swap contributions with another participant.
func (s *Service) OnContribute(ctx context.Context, sender uint64, account string, secret bls.SecretKey, vVec []bls.PublicKey) (bls.SecretKey, []bls.PublicKey, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "services.process.OnContribute")
	defer span.Finish()

	s.generationsMu.Lock()
	defer s.generationsMu.Unlock()

	generation, err := s.getGeneration(ctx, account)
	if err != nil {
		return bls.SecretKey{}, nil, err
	}

	if !verifyContribution(generation.id, secret, vVec) {
		log.Warn().Uint64("sender", sender).Str("account", account).Msg("Received invalid contribution")
		return bls.SecretKey{}, nil, fmt.Errorf("invalid contribution from %d", sender)
	}

	// Store the contributed information.
	generation.sharedSecrets[sender] = secret
	generation.sharedVVecs[sender] = vVec

	// We return our unique generated secret for the sender, and our own verification vector.
	return generation.distributionSecrets[sender], generation.sharedVVecs[generation.id], nil

}

func (s *Service) storeDistributedKey(ctx context.Context,
	account string,
	passphrase []byte,
	privateKey bls.SecretKey,
	threshold uint32,
	verificationVector []bls.PublicKey,
	participants []*core.Endpoint) error {
	store := s.stores[0]

	walletName, accountName, err := e2wallet.WalletAndAccountNames(account)
	if err != nil {
		return errors.Wrap(err, "failed to parse account")
	}

	vVec := make([][]byte, len(verificationVector))
	for i := range verificationVector {
		vVec[i] = verificationVector[i].Serialize()
	}
	wallet, err := distributed.OpenWallet(ctx, walletName, store, s.encryptor)
	if err != nil {
		return errors.Wrap(err, "failed to open wallet")
	}

	locker, isLocker := wallet.(e2wtypes.WalletLocker)
	if isLocker {
		if err := locker.Unlock(ctx, []byte{}); err != nil {
			return errors.Wrap(err, "failed to unlock wallet")
		}
		defer func() {
			if err := locker.Lock(ctx); err != nil {
				log.Warn().Str("wallet", wallet.Name()).Msg("Failed to lock")
			}

		}()
	}

	walletParticipants := make(map[uint64]string, len(participants))
	for i := range participants {
		walletParticipants[participants[i].ID] = participants[i].ConnectAddress()
	}
	generatedAccount, err := wallet.(e2wtypes.WalletDistributedAccountImporter).ImportDistributedAccount(ctx, accountName, privateKey.Serialize(), threshold, vVec, walletParticipants, passphrase)
	if err != nil {
		return errors.Wrap(err, "failed to import account")
	}
	if err := s.fetcherSvc.AddAccount(ctx, wallet, generatedAccount); err != nil {
		// Warn but do not propagate this error.
		log.Warn().Err(err).Msg("Failed to add account to internal cache, will be unavailable until restart")
	}

	return nil
}
