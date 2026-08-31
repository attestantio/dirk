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
	"time"

	"github.com/rs/zerolog"
	"github.com/wealdtech/go-majordomo"
)

type parameters struct {
	logLevel        zerolog.Level
	majordomo       majordomo.Service
	reloadThreshold time.Duration
	reloadInterval  time.Duration
	certPEMURI      string
	certKeyURI      string
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

// WithMajordomo sets the majordomo for this module.
func WithMajordomo(service majordomo.Service) Parameter {
	return parameterFunc(func(p *parameters) {
		p.majordomo = service
	})
}

// WithReloadThreshold sets the reload threshold for the module.
func WithReloadThreshold(reloadThreshold time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.reloadThreshold = reloadThreshold
	})
}

// WithReloadInterval sets the reload interval for the module.
func WithReloadInterval(reloadInterval time.Duration) Parameter {
	return parameterFunc(func(p *parameters) {
		p.reloadInterval = reloadInterval
	})
}

// WithCertKeyURI sets the key URI for the module.
func WithCertKeyURI(certKeyURI string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.certKeyURI = certKeyURI
	})
}

// WithCertPEMURI sets the PEM URI for the module.
func WithCertPEMURI(certPEMURI string) Parameter {
	return parameterFunc(func(p *parameters) {
		p.certPEMURI = certPEMURI
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

	return &parameters, nil
}
