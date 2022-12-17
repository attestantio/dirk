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

package golang

import (
	"context"
	"fmt"
	"sync"

	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/attestantio/dirk/util"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
)

// RunRules runs a number of rules and returns a result.
func (s *Service) RunRules(ctx context.Context,
	credentials *checker.Credentials,
	action string,
	rulesData []*ruler.RulesData,
) []rules.Result {
	span, ctx := opentracing.StartSpanFromContext(ctx, "ruler.golang.RunRules")
	defer span.Finish()

	// There must be some data.
	if len(rulesData) == 0 {
		log.Debug().Msg("Received no rules data entries")
		return []rules.Result{rules.FAILED}
	}
	results := make([]rules.Result, len(rulesData))
	for i := range rulesData {
		results[i] = rules.UNKNOWN
	}
	for i := range rulesData {
		if rulesData[i] == nil {
			log.Debug().Msg("Received nil rules data")
			results[i] = rules.FAILED
			return results
		}
		if rulesData[i].Data == nil {
			log.Debug().Msg("Received nil data in rules data")
			results[i] = rules.FAILED
			return results
		}
	}

	// Only some actions require locking.
	if action == ruler.ActionSign ||
		action == ruler.ActionSignBeaconProposal ||
		action == ruler.ActionSignBeaconAttestation {
		// We cannot allow multiple requests for the same public key.
		pubKeyMap := make(map[[48]byte]bool)
		for i := range rulesData {
			var key [48]byte
			if len(rulesData[i].PubKey) == 0 {
				log.Debug().Msg("Received no pubkey in rules data")
				results[i] = rules.FAILED
				return results
			}
			copy(key[:], rulesData[i].PubKey)
			if _, exists := pubKeyMap[key]; exists {
				log.Debug().Str("pubkey", fmt.Sprintf("%#x", rulesData[i].PubKey)).Msg("Multiple requests for same key")
				results[i] = rules.FAILED
				return results
			}
			pubKeyMap[key] = true
		}

		// Throw a lock around the entire locking process.  This avoids situations where two concurrent
		// goroutines try locking (a,b) and (b,a), respectively, and cause a deadlock.
		s.locker.PreLock()
		// Lock each public key as we come to it, to ensure that there can only be a single active rule
		// (and hence data update) for a given public key at any time.
		for i := range rulesData {
			var lockKey [48]byte
			copy(lockKey[:], rulesData[i].PubKey)
			s.locker.Lock(lockKey)
			defer s.locker.Unlock(lockKey)
		}
		s.locker.PostLock()
	}

	return s.runRules(ctx, credentials, action, rulesData)
}

// runRules runs a number of rules and returns a result.
// It assumes that validation checks have already been carried out against the data, and that
// suitable locks are held against the relevant public keys.
func (s *Service) runRules(ctx context.Context,
	credentials *checker.Credentials,
	action string,
	rulesData []*ruler.RulesData,
) []rules.Result {
	if len(rulesData) > 1 && action == ruler.ActionSignBeaconAttestation {
		return s.runRulesForMultipleBeaconAttestations(ctx, credentials, rulesData)
	}

	results := make([]rules.Result, len(rulesData))
	for i := range rulesData {
		results[i] = rules.UNKNOWN
	}
	_, err := util.Scatter(len(rulesData), func(offset int, entries int, _ *sync.RWMutex) (interface{}, error) {
		for i := offset; i < offset+entries; i++ {
			if rulesData[i] == nil {
				continue
			}
			var name string
			if rulesData[i].AccountName == "" {
				name = rulesData[i].WalletName
			} else {
				name = fmt.Sprintf("%s/%s", rulesData[i].WalletName, rulesData[i].AccountName)
			}
			log := log.With().Str("account", name).Logger()

			metadata, err := s.assembleMetadata(ctx, credentials, rulesData[i].AccountName, rulesData[i].PubKey)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to assemble metadata")
				results[i] = rules.FAILED
				continue
			}
			switch action {
			case ruler.ActionSign:
				rulesData, isExpectedType := rulesData[i].Data.(*rules.SignData)
				if !isExpectedType {
					log.Warn().Msg("Data not of expected type")
					results[i] = rules.FAILED
					continue
				}
				results[i] = s.rules.OnSign(ctx, metadata, rulesData)
			case ruler.ActionSignBeaconProposal:
				reqData, isExpectedType := rulesData[i].Data.(*rules.SignBeaconProposalData)
				if !isExpectedType {
					log.Warn().Msg("Data not of expected type")
					results[i] = rules.FAILED
					continue
				}
				results[i] = s.rules.OnSignBeaconProposal(ctx, metadata, reqData)
			case ruler.ActionSignBeaconAttestation:
				reqData, isExpectedType := rulesData[i].Data.(*rules.SignBeaconAttestationData)
				if !isExpectedType {
					log.Warn().Msg("Data not of expected type")
					results[i] = rules.FAILED
					continue
				}
				results[i] = s.rules.OnSignBeaconAttestation(ctx, metadata, reqData)
			case ruler.ActionAccessAccount:
				reqData, isExpectedType := rulesData[i].Data.(*rules.AccessAccountData)
				if !isExpectedType {
					log.Warn().Msg("Data not of expected type")
					results[i] = rules.FAILED
					continue
				}
				results[i] = s.rules.OnListAccounts(ctx, metadata, reqData)
			case ruler.ActionLockWallet:
				reqData, isExpectedType := rulesData[i].Data.(*rules.LockWalletData)
				if !isExpectedType {
					log.Warn().Msg("Data not of expected type")
					results[i] = rules.FAILED
					continue
				}
				results[i] = s.rules.OnLockWallet(ctx, metadata, reqData)
			case ruler.ActionUnlockWallet:
				reqData, isExpectedType := rulesData[i].Data.(*rules.UnlockWalletData)
				if !isExpectedType {
					log.Warn().Msg("Data not of expected type")
					results[i] = rules.FAILED
					continue
				}
				results[i] = s.rules.OnUnlockWallet(ctx, metadata, reqData)
			case ruler.ActionLockAccount:
				reqData, isExpectedType := rulesData[i].Data.(*rules.LockAccountData)
				if !isExpectedType {
					log.Warn().Msg("Data not of expected type")
					results[i] = rules.FAILED
					continue
				}
				results[i] = s.rules.OnLockAccount(ctx, metadata, reqData)
			case ruler.ActionUnlockAccount:
				reqData, isExpectedType := rulesData[i].Data.(*rules.UnlockAccountData)
				if !isExpectedType {
					log.Warn().Msg("Data not of expected type")
					results[i] = rules.FAILED
					continue
				}
				results[i] = s.rules.OnUnlockAccount(ctx, metadata, reqData)
			case ruler.ActionCreateAccount:
				reqData, isExpectedType := rulesData[i].Data.(*rules.CreateAccountData)
				if !isExpectedType {
					log.Warn().Msg("Data not of expected type")
					results[i] = rules.FAILED
					continue
				}
				results[i] = s.rules.OnCreateAccount(ctx, metadata, reqData)
			default:
				log.Warn().Str("action", action).Msg("Unknown action")
				results[i] = rules.FAILED
			}
			if results[i] == rules.UNKNOWN {
				log.Error().Msg("Unknown result from rule")
				results[i] = rules.FAILED
			}
		}
		return nil, nil
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to scatter rules")
	}

	return results
}

// runRulesForMultipleBeaconAttestations is the fast path for multisigning beacon attestations.
func (s *Service) runRulesForMultipleBeaconAttestations(ctx context.Context,
	credentials *checker.Credentials,
	rulesData []*ruler.RulesData,
) []rules.Result {
	results := make([]rules.Result, len(rulesData))
	for i := range rulesData {
		results[i] = rules.UNKNOWN
	}

	metadatas := make([]*rules.ReqMetadata, len(rulesData))
	reqData := make([]*rules.SignBeaconAttestationData, len(rulesData))

	_, err := util.Scatter(len(rulesData), func(offset int, entries int, _ *sync.RWMutex) (interface{}, error) {
		for i := offset; i < offset+entries; i++ {
			if rulesData[i].AccountName == "" {
				log.Warn().Msg("Missing account")
				results[i] = rules.FAILED
				break
			}
			name := fmt.Sprintf("%s/%s", rulesData[i].WalletName, rulesData[i].AccountName)
			log := log.With().Str("account", name).Logger()

			// We are strict here; any failure in metadata or data will result in an immediate return.
			// This ensures that the later code is simplified, and user errors are picked up quickly.
			var err error
			metadatas[i], err = s.assembleMetadata(ctx, credentials, rulesData[i].AccountName, rulesData[i].PubKey)
			if err != nil {
				log.Warn().Err(err).Msg("Failed to assemble metadata")
				results[i] = rules.FAILED
				break
			}
			data, isBeaconAttestationData := rulesData[i].Data.(*rules.SignBeaconAttestationData)
			if !isBeaconAttestationData {
				log.Warn().Msg("Data is not for signing beacon attestation")
				results[i] = rules.FAILED
				break
			}
			reqData[i] = data
		}
		return nil, nil
	})
	if err != nil {
		log.Error().Err(err).Msg("Failed to scatter signing preparation")
	}

	for i := range results {
		if results[i] == rules.FAILED {
			return results
		}
	}

	return s.rules.OnSignBeaconAttestations(ctx, metadatas, reqData)
}

func (*Service) assembleMetadata(_ context.Context, credentials *checker.Credentials, accountName string, pubKey []byte) (*rules.ReqMetadata, error) {
	if credentials == nil {
		return nil, errors.New("no credentials")
	}

	// All requests must have a client.
	if credentials.Client == "" {
		return nil, errors.New("no client in credentials")
	}

	return &rules.ReqMetadata{
		Account: accountName,
		PubKey:  pubKey,
		IP:      credentials.IP,
		Client:  credentials.Client,
	}, nil
}
