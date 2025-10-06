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
	"crypto/tls"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-majordomo"
)

type Service struct {
	ctx        context.Context
	majordomo  majordomo.Service
	certPEMURI string
	certKeyURI string

	currentCert atomic.Pointer[tls.Certificate]
}

// module-wide log.
var log zerolog.Logger

// New creates a new cert manager service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "certmanager").Str("impl", "standard").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	// Load the certificates immediately.
	certPEMBlock, err := parameters.majordomo.Fetch(ctx, parameters.certPEMURI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server certificate")
	}
	certKeyBlock, err := parameters.majordomo.Fetch(ctx, parameters.certKeyURI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain server key")
	}

	// Initialise the certificate pair.
	serverCert, err := tls.X509KeyPair(certPEMBlock, certKeyBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load certificate pair")
	}
	if len(serverCert.Certificate) == 0 {
		return nil, errors.New("certificate file does not contain a certificate")
	}
	cert := serverCert.Leaf
	if cert.NotAfter.Before(time.Now()) {
		log.Warn().Time("expiry", cert.NotAfter).Msg("Server certificate expired")
	}

	log.Info().Str("issued_to", cert.Subject.CommonName).Str("issued_by", cert.Issuer.CommonName).Time("valid_until", cert.NotAfter).Msg("Server certificate loaded")

	out := &Service{
		ctx:        ctx,
		majordomo:  parameters.majordomo,
		certPEMURI: parameters.certPEMURI,
		certKeyURI: parameters.certKeyURI,
	}
	out.currentCert.Store(&serverCert)
	return out, nil
}

// Return the certificate.
func (s *Service) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.currentCert.Load(), nil
}
