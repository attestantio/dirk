// Copyright © 2025 Attestant Limited.
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
	"crypto/x509"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	"github.com/wealdtech/go-majordomo"
)

type Service struct {
	majordomo     majordomo.Service
	reloadTimeout time.Duration
	certPEMURI    string
	certKeyURI    string

	lastReloadAttemptTime time.Time
	currentCertMutext     sync.RWMutex
	currentCert           atomic.Pointer[tls.Certificate]
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
	cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil || cert == nil {
		return nil, errors.Wrap(err, "failed to parse server certificate")
	}
	if cert.NotAfter.Before(time.Now()) {
		log.Warn().Time("expiry", cert.NotAfter).Msg("Server certificate expired")
	}

	log.Info().Str("issued_to", cert.Subject.CommonName).Str("issued_by", cert.Issuer.CommonName).Time("valid_until", cert.NotAfter).Msg("Server certificate loaded")

	out := &Service{
		majordomo:     parameters.majordomo,
		certPEMURI:    parameters.certPEMURI,
		certKeyURI:    parameters.certKeyURI,
		reloadTimeout: parameters.reloadTimeout,
	}
	out.currentCert.Store(&serverCert)
	return out, nil
}

// TryReloadCertificate tries to reload the certificate. Can be called asynchronously and on demand.
func (s *Service) TryReloadCertificate(ctx context.Context) {
	if !s.currentCertMutext.TryLock() {
		// Certificate is already being reloaded; do nothing.
		return
	}
	defer s.currentCertMutext.Unlock()

	s.lastReloadAttemptTime = time.Now()

	if s.reloadTimeout > 0 {
		var cancel context.CancelFunc
		// Give up on the reload if it takes longer than the reload timeout.
		ctx, cancel = context.WithDeadline(ctx, s.lastReloadAttemptTime.Add(s.reloadTimeout))
		defer cancel()
	}

	certPEMBlock, err := s.majordomo.Fetch(ctx, s.certPEMURI)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain server certificate during reload")
		return
	}
	certKeyBlock, err := s.majordomo.Fetch(ctx, s.certKeyURI)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to obtain server key during reload")
		return
	}

	// Load the certificate pair.
	serverCert, err := tls.X509KeyPair(certPEMBlock, certKeyBlock)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to load certificate pair during reload")
		return
	}
	if len(serverCert.Certificate) == 0 {
		log.Warn().Msg("Certificate file does not contain a certificate")
		return
	}
	cert, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil || cert == nil {
		log.Warn().Msg("Failed to parse certificate")
		return
	}

	newExpiry := cert.NotAfter
	if newExpiry.Before(time.Now()) {
		log.Warn().
			Str("issued_to", cert.Subject.CommonName).
			Str("issued_by", cert.Issuer.CommonName).
			Time("expiry", newExpiry).
			Msg("Server certificate expired, send SIGHUP to reload it.")
		return
	}

	log.Info().Str("issued_to", cert.Subject.CommonName).Str("issued_by", cert.Issuer.CommonName).Time("valid_until", newExpiry).Msg("Server certificate reloaded successfully")

	s.currentCert.Store(&serverCert)
}

// GetCertificate returns the certificate.
func (s *Service) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	currentCert := s.currentCert.Load()
	cert, err := x509.ParseCertificate(currentCert.Certificate[0])
	if err != nil || cert == nil {
		log.Warn().Msg("Failed to parse certificate")
		return nil, errors.New("Could not parse certificate")
	}

	// Do we want to reload automatically the certificate if it is expired?
	// If not, shall we return an error or just use the existing certificate?
	// The code block below should be un if we don't want to reload automatically the certificate if it is expired.
	expiry := cert.NotAfter
	if expiry.Before(time.Now()) {
		log.Warn().
			Str("issued_to", cert.Subject.CommonName).
			Str("issued_by", cert.Issuer.CommonName).
			Time("expiry", expiry).
			Msg("Server certificate expired, reloading it...")
		// Reload the certificate.
		s.TryReloadCertificate(context.Background())
	}

	// Use the existing certificate.
	// It will use the expired certificate if it is not reloaded successfully.
	return currentCert, nil
}
