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

package static

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
)

// Service checks access against a static list.
type Service struct {
	monitor metrics.CheckerMonitor
	access  map[string][]*path
}

type path struct {
	wallet     *regexp.Regexp
	account    *regexp.Regexp
	operations []string
}

// module-wide log.
var log zerolog.Logger

// New creates a new static checker.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "checker").Str("impl", "static").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		monitor: parameters.monitor,
		access:  parameters.access,
	}

	perms := make(map[string]int)
	for host := range s.access {
		perms[host] = len(s.access[host])
	}
	s.monitor.PermissionsObtained(perms)

	return s, nil
}

// Check checks the client to see if the account is allowed.
func (s *Service) Check(_ context.Context, credentials *checker.Credentials, account string, operation string) bool {
	log.Trace().Str("account", account).Str("operation", operation).Msg("Checking permissions for operation")

	if credentials == nil {
		log.Error().Str("result", "failed").Msg("No credentials")
		return false
	}
	if credentials.Client == "" {
		log.Warn().Str("result", "denied").Msg("No client name")
		return false
	}
	log := log.With().Str("account", account).Str("operation", operation).Str("client", credentials.Client).Str("account", account).Logger()

	walletName, accountName, err := e2wallet.WalletAndAccountNames(account)
	if err != nil {
		log.Warn().Err(err).Str("result", "denied").Msg("Invalid path")
		return false
	}
	if walletName == "" {
		log.Warn().Err(err).Str("result", "denied").Msg("Missing wallet name")
		return false
	}

	paths, exists := s.access[credentials.Client]
	if !exists {
		log.Warn().Str("result", "denied").Msg("No rules for client")
		return false
	}

	antiOperation := fmt.Sprintf("~%s", operation)
	for _, path := range paths {
		if path.wallet.MatchString(walletName) && path.account.MatchString(accountName) {
			for i := range path.operations {
				if strings.EqualFold(path.operations[i], "none") || strings.EqualFold(path.operations[i], antiOperation) {
					log.Trace().Str("result", "denied").Msg("Negative permission matched")
					return false
				}
				if strings.EqualFold(path.operations[i], "all") || strings.EqualFold(path.operations[i], operation) {
					log.Trace().Str("result", "succeeded").Msg("Positive permission matched")
					return true
				}
			}
		}
	}

	log.Trace().Str("result", "denied").Msg("No matching rules")
	return false
}
