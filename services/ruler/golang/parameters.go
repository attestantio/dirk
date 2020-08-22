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

package golang

import (
	"github.com/attestantio/dirk/rules"
	"github.com/attestantio/dirk/services/locker"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

type parameters struct {
	logLevel zerolog.Level
	monitor  metrics.RulerMonitor
	rules    rules.Service
	locker   locker.Service
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
func WithMonitor(monitor metrics.RulerMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithLocker sets the locker for this module.
func WithLocker(locker locker.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.locker = locker
	})
}

// WithRules sets the rules for this module.
func WithRules(rules rules.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.rules = rules
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
	if parameters.locker == nil {
		return nil, errors.New("no locker specified")
	}
	if parameters.rules == nil {
		return nil, errors.New("no rules specified")
	}

	return &parameters, nil
}
