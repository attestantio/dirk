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
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/attestantio/dirk/util"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	wallet "github.com/wealdtech/go-eth2-wallet"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// OnGenerate is called when an request to generate a new key is received.
func (s *Service) OnGenerate(ctx context.Context,
	credentials *checker.Credentials,
	account string,
	passphrase []byte,
	signingThreshold uint32,
	numParticipants uint32,
) ([]byte, []*core.Endpoint, error) {
	// Check parameters.
	if numParticipants == 0 {
		log.Warn().Msg("Zero participants")
		return nil, nil, errors.New("zero participants")
	}
	if signingThreshold > numParticipants {
		log.Warn().Uint32("participants", numParticipants).Uint32("signing_threshold", signingThreshold).Msg("Signing threshold too high")
		return nil, nil, errors.New("signing threshold too high")
	}
	if signingThreshold <= numParticipants/2 {
		log.Warn().Uint32("participants", numParticipants).Uint32("signing_threshold", signingThreshold).Msg("Signing threshold too low")
		return nil, nil, errors.New("signing threshold too low")
	}

	log := log.With().Str("account", account).Logger()
	// Ensure we don't already have this account.
	walletName, accountName, err := wallet.WalletAndAccountNames(account)
	if err != nil {
		log.Warn().Msg("Invalid account supplied")
		return nil, nil, errors.Wrap(err, "invalid account")
	}
	wallet, err := wallet.OpenWallet(walletName, wallet.WithStore(s.stores[0]))
	if err != nil {
		log.Warn().Err(err).Msg("Unknown wallet supplied")
		return nil, nil, errors.Wrap(err, "unknown wallet")
	}
	accountByNameProvider, isProvider := wallet.(e2wtypes.WalletAccountByNameProvider)
	if !isProvider {
		log.Error().Msg("Wallet does not support fetching accounts by name")
		return nil, nil, errors.New("wallet does not support fetching accounts by name")
	}
	_, err = accountByNameProvider.AccountByName(ctx, accountName)
	if err == nil {
		log.Error().Err(err).Msg("Account already exists")
		return nil, nil, errors.New("account already exists")
	}

	checkRes := s.checkAccess(ctx, credentials, account, ruler.ActionCreateAccount)
	if checkRes != core.ResultSucceeded {
		log.Debug().Msg("Create refused")
		return nil, nil, errors.New("failed rules check")
	}
	log.Trace().Msg("Create allowed")

	if numParticipants == 1 {
		// Only 1 participant means we are generating a standard account.
		pubKey, err := s.generate(ctx, wallet, accountName, passphrase)
		if err != nil {
			log.Error().Err(err).Msg("Failed to generate account")
			return nil, nil, errors.New("failed account generation")
		}
		return pubKey, nil, err
	}
	return s.generateDistributed(ctx, wallet, account, passphrase, signingThreshold, numParticipants)
}

func (s *Service) generate(ctx context.Context, wallet e2wtypes.Wallet, accountName string, passphrase []byte) ([]byte, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "services.process.generate")
	defer span.Finish()

	if wallet.Type() == "distributed" {
		log.Error().Msg("Incorrect wallet type to create key")
		return nil, errors.New("wallet does not support account creation")
	}

	locker, isLocker := wallet.(e2wtypes.WalletLocker)
	if isLocker {
		unlocked, err := s.unlockerSvc.UnlockWallet(ctx, wallet)
		if err != nil {
			return nil, errors.Wrap(err, "failed to unlock wallet")
		}
		if !unlocked {
			return nil, errors.New("failed to unlock wallet with known passphrases")
		}
		defer func() {
			if err := locker.Lock(ctx); err != nil {
				log.Warn().Err(err).Msg("failed to lock wallet")
			}
		}()
	}

	createdAccount, err := wallet.(e2wtypes.WalletAccountCreator).CreateAccount(ctx, accountName, passphrase)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create account")
	}

	if err := s.fetcherSvc.AddAccount(ctx, wallet, createdAccount); err != nil {
		// Warn but do not propagate this error.
		log.Warn().Err(err).Msg("Failed to add account to internal cache, will be unavailable until restart")
	}

	return createdAccount.PublicKey().Marshal(), nil
}

func (s *Service) generateDistributed(ctx context.Context, wallet e2wtypes.Wallet, account string, passphrase []byte, signingThreshold uint32, numParticipants uint32) ([]byte, []*core.Endpoint, error) {
	span, ctx := opentracing.StartSpanFromContext(ctx, "services.process.generateDistributed")
	defer span.Finish()

	if wallet.Type() != "distributed" {
		log.Error().Msg("Incorrect wallet type to generate distributed key")
		return nil, nil, errors.New("wallet does not support distributed generation")
	}

	participants, err := s.peersSvc.Suitable(numParticipants)
	if err != nil {
		log.Error().Err(err).Msg("Failed to select suitable participants")
		return nil, nil, errors.New("no suitable participants")
	}

	// Send prepare request to all participants.
	for _, participant := range participants {
		log.Trace().Str("endpoint", participant.String()).Msg("Sending prepare request to endpoint")
		if err := s.senderSvc.Prepare(ctx, participant, account, passphrase, signingThreshold, participants); err != nil {
			log.Error().Err(err).Str("endpoint", participant.String()).Msg("Failed to prepare on endpoint")
			return nil, nil, errors.Wrap(err, "failed to prepare endpoints")
		}
	}

	// Send execute request to all participants.
	for _, participant := range participants {
		log.Trace().Str("endpoint", participant.String()).Msg("Sending execute request to endpoint")
		if err := s.senderSvc.Execute(ctx, participant, account); err != nil {
			log.Error().Err(err).Str("endpoint", participant.String()).Msg("Failed to execute on endpoint")
			return nil, nil, errors.Wrap(err, "failed to execute generation")
		}
	}

	// Send commit request to all endpoints.
	pubKeys := make([][]byte, len(participants))
	// Confirmation data is 32 random bytes.
	confirmationData := make([]byte, 32)
	n, err := rand.Read(confirmationData)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate commit data")
	}
	if n != 32 {
		return nil, nil, errors.New("failed to generate enough commit data")
	}
	confirmationSigs := make([][]byte, len(participants))

	type result struct {
		PubKey           []byte
		ConfirmationSig  []byte
		Err              error
		ParticipantIndex int
	}

	ch := make(chan result, len(participants))
	var wg sync.WaitGroup

	for i, participant := range participants {
		wg.Add(1)
		go func(i int, participant *core.Endpoint) {
			defer wg.Done()
			log.Trace().Str("endpoint", participant.String()).Msg("Sending commit request to endpoint")
			pubKey, confirmationSig, err := s.senderSvc.Commit(ctx, participant, account, confirmationData)
			ch <- result{PubKey: pubKey, ConfirmationSig: confirmationSig, Err: err, ParticipantIndex: i}
		}(i, participant)
	}

	wg.Wait()
	close(ch)

	for result := range ch {
		participantIndex := result.ParticipantIndex
		pubKeys[participantIndex], confirmationSigs[participantIndex], err = result.PubKey, result.ConfirmationSig, result.Err
		if err != nil {
			log.Error().Err(err).Str("endpoint", participants[participantIndex].String()).Msg("Failed to commit on endpoint")
			return nil, nil, errors.Wrap(err, "failed to complete generation")
		}
		if len(result.PubKey) == 0 {
			log.Error().Uint64("participant", participants[participantIndex].ID).Msg("Received empty public key from participant on commit")
			return nil, nil, errors.New("failed to complete generation")
		}
		if len(result.ConfirmationSig) == 0 {
			log.Error().Uint64("participant", participants[participantIndex].ID).Msg("Received empty confirmation signature from participant on commit")
			return nil, nil, errors.New("failed to complete generation")
		}
	}

	for i := range pubKeys {
		if !bytes.Equal(pubKeys[i], pubKeys[(i+1)%len(pubKeys)]) {
			log.Error().Msg("pubkey mismatch")
			return nil, nil, errors.New("Invalid generation")
		}
	}

	// Check composite signatures.
	ids := make([]bls.ID, signingThreshold)
	sigs := make([]bls.Sign, signingThreshold)
	pubKey := bls.PublicKey{}
	if err := pubKey.Deserialize(pubKeys[0]); err != nil {
		log.Error().Err(err).Msg("Failed to deserialize public key")
		return nil, nil, errors.New("Invalid generation")
	}
	compositeSig := bls.Sign{}
	for i := 0; i < len(participants)+1-int(signingThreshold); i++ {
		for j := 0; j < int(signingThreshold); j++ {
			ids[j] = *util.BLSID(participants[i+j].ID)
			sigs[j] = bls.Sign{}
			if err := sigs[j].Deserialize(confirmationSigs[i+j]); err != nil {
				log.Error().Err(err).Msg("Failed to deserialize confirmation signature")
				return nil, nil, errors.New("Invalid generation")
			}
		}
		if err := compositeSig.Recover(sigs, ids); err != nil {
			log.Error().Err(err).Msg("Failed to recover composite signature")
			return nil, nil, errors.New("Invalid generation")
		}
		if !compositeSig.VerifyByte(&pubKey, confirmationData) {
			log.Error().Err(err).Msg("Failed to confirm composite signature")
			return nil, nil, errors.New("Invalid generation")
		}
	}

	log.Trace().Str("account", account).Str("pubKey", fmt.Sprintf("%x", pubKeys[0])).Msg("Generated account")
	return pubKeys[0], participants, nil
}
