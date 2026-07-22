// Copyright © 2026 Attestant Limited.
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

	"github.com/attestantio/dirk/rules"
	"github.com/opentracing/opentracing-go"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

// OnSignVoluntaryExit is called when a request to sign a voluntary exit needs to be approved.
// The request has already been authorised by the client's "Sign voluntary exit" permission,
// so no additional source IP address check is carried out.
func (s *Service) OnSignVoluntaryExit(ctx context.Context, metadata *rules.ReqMetadata, req *rules.SignData) rules.Result {
	span, _ := opentracing.StartSpanFromContext(ctx, "rules.OnSignVoluntaryExit")
	defer span.Finish()

	if metadata == nil {
		s.log.Warn().Msg("No metadata to evaluate request")
		return rules.FAILED
	}
	log := s.log.With().Str("client", metadata.Client).Str("account", metadata.Account).Str("rule", "sign voluntary exit").Logger()

	if req == nil {
		log.Warn().Msg("No request data to evaluate request")
		return rules.FAILED
	}

	if len(req.Domain) < 4 || !bytes.Equal(req.Domain[0:4], e2types.DomainVoluntaryExit[:]) {
		log.Warn().Msg("Not signing non-voluntary exit request with voluntary exit signer")
		return rules.DENIED
	}

	return rules.APPROVED
}
