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
	"time"

	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/fetcher"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/attestantio/dirk/services/peers"
	"github.com/attestantio/dirk/services/sender"
	"github.com/attestantio/dirk/services/unlocker"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type parameters struct {
	logLevel             zerolog.Level
	monitor              metrics.ProcessMonitor
	checker              checker.Service
	fetcher              fetcher.Service
	sender               sender.Service
	unlocker             unlocker.Service
	encryptor            e2wtypes.Encryptor
	id                   uint64
	peers                peers.Service
	stores               []e2wtypes.Store
	generationPassphrase []byte
	generationTimeout    time.Duration
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
func WithMonitor(monitor metrics.ProcessMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithChecker sets the checker for this module.
func WithChecker(service checker.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.checker = service
	})
}

// WithFetcher sets the account fetcher for this module.
func WithFetcher(service fetcher.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.fetcher = service
	})
}

// WithSender sets the sender for this module.
func WithSender(service sender.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.sender = service
	})
}

// WithUnlocker sets the unlocker for this module.
func WithUnlocker(service unlocker.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.unlocker = service
	})
}

// WithEncryptor sets the encryptor for this module.
func WithEncryptor(encryptor e2wtypes.Encryptor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.encryptor = encryptor
	})
}

// WithPeers sets the peers for this module.
func WithPeers(service peers.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.peers = service
	})
}

// WithID sets the ID for this module.
func WithID(id uint64) Parameter {
	return parameterFunc(func(p *parameters) {
		p.id = id
	})
}

// WithStores sets the stores for this module.
func WithStores(stores []e2wtypes.Store) Parameter {
	return parameterFunc(func(p *parameters) {
		p.stores = stores
	})
}

// WithGenerationPassphrase sets the generation passphrase for this module.
func WithGenerationPassphrase(generationPassphrase []byte) Parameter {
	return parameterFunc(func(p *parameters) {
		p.generationPassphrase = generationPassphrase
	})
}

// WithGenerationTimeout sets the generation timeout for this module.
func WithGenerationTimeout(generationTimeout time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.generationTimeout = generationTimeout
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:          zerolog.GlobalLevel(),
		encryptor:         keystorev4.New(),
		generationTimeout: 70 * time.Second,
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
	if parameters.checker == nil {
		return nil, errors.New("no checker specified")
	}
	if parameters.fetcher == nil {
		return nil, errors.New("no fetcher specified")
	}
	if parameters.sender == nil {
		return nil, errors.New("no sender specified")
	}
	if parameters.unlocker == nil {
		return nil, errors.New("no unlocker specified")
	}
	if parameters.encryptor == nil {
		return nil, errors.New("no encryptor specified")
	}
	if parameters.id == 0 {
		return nil, errors.New("no ID specified")
	}
	if parameters.peers == nil {
		return nil, errors.New("no peers specified")
	}
	if parameters.stores == nil {
		return nil, errors.New("no stores specified")
	}

	return &parameters, nil
}
