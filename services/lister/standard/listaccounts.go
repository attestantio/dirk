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
	"regexp"
	"strings"
	"time"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/ruler"
	wallet "github.com/wealdtech/go-eth2-wallet"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ListAccounts lists accounts.
func (s *Service) ListAccounts(ctx context.Context, credentials *checker.Credentials, paths []string) (core.Result, []e2wtypes.Account) {
	ctx, span := otel.Tracer("attestantio.dirk.services.lister.standard").Start(ctx, "ListAccounts")
	defer span.End()
	started := time.Now()

	if credentials == nil {
		log.Error().Msg("No credentials supplied")
		return core.ResultFailed, nil
	}
	span.SetAttributes(attribute.String("client", credentials.Client))

	log := log.With().
		Str("request_id", credentials.RequestID).
		Strs("paths", paths).
		Str("client", credentials.Client).
		Logger()
	log.Trace().Msg("Request received")

	accounts := make([]e2wtypes.Account, 0)
	for _, path := range paths {
		log := log.With().Str("path", path).Logger()
		walletName, accountPath, err := wallet.WalletAndAccountNames(path)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to obtain wallet and account names from path")
			continue
		}
		if walletName == "" {
			log.Warn().Msg("Empty wallet in path")
			continue
		}

		var accountRegex *regexp.Regexp
		if accountPath != "" {
			if !strings.HasPrefix(accountPath, "^") {
				accountPath = fmt.Sprintf("^%s", accountPath)
			}
			if !strings.HasSuffix(accountPath, "$") {
				accountPath = fmt.Sprintf("%s$", accountPath)
			}
			accountRegex, err = regexp.Compile(accountPath)
			if err != nil {
				log.Warn().Err(err).Msg("Invalid account regular expression")
				continue
			}
		}

		wallet, err := s.fetcher.FetchWallet(ctx, path)
		if err != nil {
			log.Debug().Err(err).Msg("Failed to obtain wallet")
			continue
		}

		walletAccounts, err := s.fetcher.FetchAccounts(ctx, wallet.Name())
		if err != nil {
			log.Debug().Err(err).Msg("Failed to obtain accounts")
			continue
		}

		numWalletAccounts := 0
		for _, walletAccount := range walletAccounts {
			if accountRegex == nil || accountRegex.Match([]byte(walletAccount.Name())) {
				accountName := fmt.Sprintf("%s/%s", wallet.Name(), walletAccount.Name())
				log := log.With().Str("account", accountName).Logger()
				checkRes := s.checkAccess(ctx, credentials, accountName, ruler.ActionAccessAccount)
				if checkRes != core.ResultSucceeded {
					log.Debug().Msg("Access refused")
					continue
				}
				log.Trace().Msg("Access allowed")

				// Confirm listing of the key.
				var pubKey []byte
				pubKeyProvider, isProvider := walletAccount.(e2wtypes.AccountPublicKeyProvider)
				if !isProvider {
					log.Warn().Msg("No public key available")
					continue
				}
				pubKey = pubKeyProvider.PublicKey().Marshal()

				if compositePubKeyProvider, isProvider := walletAccount.(e2wtypes.AccountCompositePublicKeyProvider); isProvider {
					pubKey = compositePubKeyProvider.CompositePublicKey().Marshal()
				}
				data := &rules.AccessAccountData{
					Paths: paths,
				}

				rulesData := []*ruler.RulesData{
					{
						WalletName:  wallet.Name(),
						AccountName: walletAccount.Name(),
						PubKey:      pubKey,
						Data:        data,
					},
				}
				results := s.ruler.RunRules(ctx, credentials, ruler.ActionAccessAccount, rulesData)
				if results[0] == rules.APPROVED {
					accounts = append(accounts, walletAccount)
					numWalletAccounts++
				}
			}
		}
		span.AddEvent("Obtained accounts from wallet", trace.WithAttributes(
			attribute.String("wallet", walletName),
			attribute.Int("accounts", numWalletAccounts),
		))
	}

	log.Trace().Str("result", "succeeded").Dur("elapsed", time.Since(started)).Int("accounts", len(accounts)).Msg("Success")
	span.AddEvent("Obtained all accounts", trace.WithAttributes(attribute.Int("accounts", len(accounts))))
	s.monitor.ListAccountsCompleted(started)
	return core.ResultSucceeded, accounts
}
