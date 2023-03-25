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

package accountmanager

import (
	context "context"

	"github.com/attestantio/dirk/services/accountmanager"
	"github.com/attestantio/dirk/services/process"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
)

// Handler is the account manager handler.
type Handler struct {
	pb.UnimplementedAccountManagerServer
	accountManager accountmanager.Service
	process        process.Service
}

// module-wide log.
var log zerolog.Logger

// New creates a new signer handler.
func New(_ context.Context, params ...Parameter) (*Handler, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	log = zerologger.With().Str("handler", "account_manager").Str("impl", "grpc").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	h := &Handler{
		accountManager: parameters.accountManager,
		process:        parameters.process,
	}

	return h, nil
}
