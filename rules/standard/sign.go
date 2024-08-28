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

	"github.com/attestantio/dirk/rules"
	"github.com/opentracing/opentracing-go"
	e2types "github.com/wealdtech/go-eth2-types/v2"
)

// OnSign is called when a request to sign generic data needs to be approved.
func (s *Service) OnSign(ctx context.Context, metadata *rules.ReqMetadata, req *rules.SignData) rules.Result {
	span, _ := opentracing.StartSpanFromContext(ctx, "rules.OnSign")
	defer span.Finish()

	if metadata == nil {
		s.log.Warn().Msg("No metadata to evaluate request")
		return rules.FAILED
	}
	log := s.log.With().Str("client", metadata.Client).Str("account", metadata.Account).Str("rule", "sign").Logger()

	if bytes.Equal(req.Domain[0:4], e2types.DomainBeaconAttester[:]) {
		log.Warn().Msg("Not signing beacon attestation request with generic signer")
		return rules.DENIED
	}
	if bytes.Equal(req.Domain[0:4], e2types.DomainBeaconProposer[:]) {
		log.Warn().Msg("Not signing beacon proposal request with generic signer")
		return rules.DENIED
	}

	// Voluntary exit requests must come from an approved IP address.
	if bytes.Equal(req.Domain[0:4], e2types.DomainVoluntaryExit[:]) {
		if metadata.IP == "" {
			log.Warn().Msg("Not signing voluntary exit request from unknown source")
			return rules.DENIED
		}
		validIP := false
		for i := range s.adminIPs {
			if metadata.IP == s.adminIPs[i] {
				validIP = true
				break
			}
		}
		if !validIP {
			log.Warn().Str("request_ip", metadata.IP).Msg("Not signing voluntary exit request from unapproved IP address")
			return rules.DENIED
		}
	}

	return rules.APPROVED
}
