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

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel: zerolog.GlobalLevel(),
	}
	for _, p := range params {
		if params != nil {
			p.apply(&parameters)
		}
	}

	if parameters.monitor == nil {
		// Use no-op monitor.
		parameters.monitor = &noopMonitor{}
	}
	if parameters.signer == nil {
		return nil, errors.New("no signer specified")
	}
	if parameters.lister == nil {
		return nil, errors.New("no lister specified")
	}
	if parameters.process == nil {
		return nil, errors.New("no process specified")
	}
	if parameters.walletManager == nil {
		return nil, errors.New("no wallet manager specified")
	}
	if parameters.accountManager == nil {
		return nil, errors.New("no account manager specified")
	}
	if parameters.peers == nil {
		return nil, errors.New("no peers specified")
	}
	if parameters.name == "" {
		return nil, errors.New("no name specified")
	}
	if parameters.id == 0 {
		return nil, errors.New("no ID specified")
	}
	if parameters.listenAddress == "" {
		return nil, errors.New("no listen address specified")
	}
	if parameters.certManager == nil {
		return nil, errors.New("no cert manager specified")
	}
	cert, err := parameters.certManager.GetCertificate(nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get server certificate")
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("no server certificate specified")
	}

	return &parameters, nil
}
