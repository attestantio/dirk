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

package grpc

import (
	"github.com/attestantio/dirk/services/accountmanager"
	"github.com/attestantio/dirk/services/certmanager"
	"github.com/attestantio/dirk/services/lister"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/attestantio/dirk/services/peers"
	"github.com/attestantio/dirk/services/process"
	"github.com/attestantio/dirk/services/signer"
	"github.com/attestantio/dirk/services/walletmanager"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel       zerolog.Level
	monitor        metrics.APIMonitor
	peers          peers.Service
	process        process.Service
	accountManager accountmanager.Service
	walletManager  walletmanager.Service
	lister         lister.Service
	signer         signer.Service
	certManager    certmanager.Service
	name           string
	listenAddress  string
	id             uint64
	caCert         []byte
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(p *parameters)
}

type parameterFunc func(*parameters)

func (f parameterFunc) apply(p *parameters) {
	f(p)
}

// WithLogLevel sets the log level for the module.
func WithLogLevel(logLevel zerolog.Level) Parameter {
	return parameterFunc(func(p *parameters) {
		p.logLevel = logLevel
	})
}

// WithMonitor sets the monitor for this module.
func WithMonitor(monitor metrics.APIMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithLister sets the lister for this module.
func WithLister(service lister.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.lister = service
	})
}

// WithProcess sets the process for this module.
func WithProcess(service process.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.process = service
	})
}

// WithSigner sets the signer for this module.
func WithSigner(service signer.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.signer = service
	})
}

// WithPeers sets the peers for this module.
func WithPeers(service peers.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.peers = service
	})
}

// WithWalletManager sets the wallet manager for this module.
func WithWalletManager(service walletmanager.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.walletManager = service
	})
}

// WithAccountManager sets the account manager for this module.
func WithAccountManager(service accountmanager.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.accountManager = service
	})
}

// WithName sets the name for the server.
func WithName(name string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.name = name
	})
}

// WithID sets the id for the server.
func WithID(id uint64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.id = id
	})
}

// WithListenAddress sets the listen address for the server.
func WithListenAddress(listenAddress string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.listenAddress = listenAddress
	})
}

// WithCertManager sets the cert manager for this module.
func WithCertManager(service certmanager.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.certManager = service
	})
}

// WithCACert sets the CA certificate for this module.
func WithCACert(caCert []byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.caCert = caCert
	})
}

// validateRequiredServices checks that all required service dependencies are present.
func validateRequiredServices(p *parameters) error {
	requiredServices := []struct {
		service interface{}
		name    string
	}{
		{p.signer, "signer"},
		{p.lister, "lister"},
		{p.process, "process"},
		{p.walletManager, "wallet manager"},
		{p.accountManager, "account manager"},
		{p.peers, "peers"},
		{p.certManager, "cert manager"},
	}

	for _, req := range requiredServices {
		if req.service == nil {
			return errors.New("no " + req.name + " specified")
		}
	}
	return nil
}

// validateRequiredStrings checks that all required string parameters are present.
func validateRequiredStrings(p *parameters) error {
	requiredStrings := []struct {
		value string
		name  string
	}{
		{p.name, "name"},
		{p.listenAddress, "listen address"},
	}

	for _, req := range requiredStrings {
		if req.value == "" {
			return errors.New("no " + req.name + " specified")
		}
	}
	return nil
}

// validateRequiredNumbers checks that all required numeric parameters are present.
func validateRequiredNumbers(p *parameters) error {
	if p.id == 0 {
		return errors.New("no ID specified")
	}
	return nil
}

// validateCertificate checks that the certificate manager has a valid certificate.
func validateCertificate(certManager certmanager.Service) error {
	cert, err := certManager.GetCertificate(nil)
	if err != nil {
		return errors.Wrap(err, "failed to get server certificate")
	}
	if len(cert.Certificate) == 0 {
		return errors.New("no server certificate specified")
	}
	return nil
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
	}
	for _, p := range params {
		if p != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		// Use no-op monitor.
		parameters.monitor = &noopMonitor{}
	}

	if err := validateRequiredServices(&parameters); err != nil {
		return nil, err
	}

	if err := validateRequiredStrings(&parameters); err != nil {
		return nil, err
	}

	if err := validateRequiredNumbers(&parameters); err != nil {
		return nil, err
	}

	if err := validateCertificate(parameters.certManager); err != nil {
		return nil, err
	}

	return &parameters, nil
}
