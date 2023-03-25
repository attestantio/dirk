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

	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/fetcher"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/attestantio/dirk/services/unlocker"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service is the signer handler.
type Service struct {
	monitor  metrics.WalletManagerMonitor
	checker  checker.Service
	fetcher  fetcher.Service
	ruler    ruler.Service
	unlocker unlocker.Service
}

// module-wide log.
var log zerolog.Logger

// New creates a new wallet manager service.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "walletmanager").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	return &Service{
		monitor:  parameters.monitor,
		unlocker: parameters.unlocker,
		checker:  parameters.checker,
		fetcher:  parameters.fetcher,
		ruler:    parameters.ruler,
	}, nil
}
