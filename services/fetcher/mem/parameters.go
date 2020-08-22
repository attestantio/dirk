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

package mem

import (
	"github.com/attestantio/dirk/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type parameters struct {
	logLevel zerolog.Level
	monitor  metrics.FetcherMonitor
	stores   []e2wtypes.Store
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
func WithMonitor(monitor metrics.FetcherMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithStores sets the stores for this module.
func WithStores(stores []e2wtypes.Store) Parameter {
	return parameterFunc(func(p *parameters) {
		p.stores = stores
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
	if parameters.stores == nil {
		return nil, errors.New("no stores specified")
	}
	if len(parameters.stores) == 0 {
		return nil, errors.New("no stores specified")
	}

	return &parameters, nil
}
