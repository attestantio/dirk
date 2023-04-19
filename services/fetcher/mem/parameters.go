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
	"time"

	"github.com/attestantio/dirk/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

type parameters struct {
	logLevel  zerolog.Level
	monitor   metrics.FetcherMonitor
	encryptor e2wtypes.Encryptor
	stores    []e2wtypes.Store

	refreshInterval time.Duration
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

// WithEncryptor sets the encryptor for this module.
func WithEncryptor(encryptor e2wtypes.Encryptor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.encryptor = encryptor
	})
}

// WithStores sets the stores for this module.
func WithStores(stores []e2wtypes.Store) Parameter {
	return parameterFunc(func(p *parameters) {
		p.stores = stores
	})
}

// WithRefreshInterval sets the refresh interval for new accounts
func WithRefreshInterval(value time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.refreshInterval = value
	})
}

// parseAndCheckParameters parses and checks parameters to ensure that mandatory parameters are present and correct.
func parseAndCheckParameters(params ...Parameter) (*parameters, error) {
	parameters := parameters{
		logLevel:  zerolog.GlobalLevel(),
		encryptor: keystorev4.New(),
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
	if parameters.encryptor == nil {
		return nil, errors.New("no encryptor specified")
	}
	if len(parameters.stores) == 0 {
		return nil, errors.New("no stores specified")
	}

	return &parameters, nil
}
