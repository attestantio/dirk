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
	"github.com/attestantio/dirk/services/fetcher"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/attestantio/dirk/services/ruler"
	"github.com/attestantio/dirk/services/unlocker"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel zerolog.Level
	monitor  metrics.SignerMonitor
	checker  checker.Service
	fetcher  fetcher.Service
	ruler    ruler.Service
	unlocker unlocker.Service
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
func WithMonitor(monitor metrics.SignerMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithChecker sets the access checker for this module.
func WithChecker(checker checker.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.checker = checker
	})
}

// WithRuler sets the ruler for this module.
func WithRuler(ruler ruler.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.ruler = ruler
	})
}

// WithUnlocker sets the account unlocker for this module.
func WithUnlocker(unlocker unlocker.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.unlocker = unlocker
	})
}

// WithFetcher sets the account fetcher for this module.
func WithFetcher(fetcher fetcher.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.fetcher = fetcher
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
	if parameters.ruler == nil {
		return nil, errors.New("no ruler specified")
	}
	if parameters.unlocker == nil {
		return nil, errors.New("no unlocker specified")
	}
	if parameters.fetcher == nil {
		return nil, errors.New("no fetcher specified")
	}

	return &parameters, nil
}
