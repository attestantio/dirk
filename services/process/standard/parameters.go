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
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/attestantio/dirk/services/peers"
	"github.com/attestantio/dirk/services/sender"
	"github.com/attestantio/dirk/services/unlocker"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type parameters struct {
	logLevel             zerolog.Level
	monitor              metrics.ProcessMonitor
	checker              checker.Service
	sender               sender.Service
	unlocker             unlocker.Service
	id                   uint64
	peers                peers.Service
	stores               []e2wtypes.Store
	generationPassphrase []byte
}

// Parameter is the interface for service parameters.
type Parameter interface {
	apply(*parameters)
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
func WithChecker(checker checker.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.checker = checker
	})
}

// WithSender sets the sender for this module.
func WithSender(sender sender.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.sender = sender
	})
}

// WithUnlocker sets the unlocker for this module.
func WithUnlocker(unlocker unlocker.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.unlocker = unlocker
	})
}

// WithPeers sets the peers for this module.
func WithPeers(peers peers.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.peers = peers
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
	if parameters.checker == nil {
		return nil, errors.New("no checker specified")
	}
	if parameters.sender == nil {
		return nil, errors.New("no sender specified")
	}
	if parameters.unlocker == nil {
		return nil, errors.New("no unlocker specified")
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
