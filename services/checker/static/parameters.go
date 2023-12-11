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

package static

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	e2wallet "github.com/wealdtech/go-eth2-wallet"
)

type parameters struct {
	logLevel    zerolog.Level
	monitor     metrics.CheckerMonitor
	permissions map[string][]*checker.Permissions
	access      map[string][]*path
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
func WithMonitor(monitor metrics.CheckerMonitor) Parameter {
	return parameterFunc(func(p *parameters) {
		p.monitor = monitor
	})
}

// WithPermissions sets the permissions for this module.
func WithPermissions(permissions map[string][]*checker.Permissions) Parameter {
	return parameterFunc(func(p *parameters) {
		p.permissions = permissions
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

	parameters.access = make(map[string][]*path, len(parameters.permissions))
	for client, permissions := range parameters.permissions {
		if client == "" {
			return nil, errors.New("invalid client name for permission")
		}

		if len(permissions) == 0 {
			return nil, fmt.Errorf("client %s requires at least one permission", client)
		}

		paths := make([]*path, len(permissions))
		for i, permission := range permissions {
			walletName, accountName, err := e2wallet.WalletAndAccountNames(permission.Path)
			if err != nil {
				return nil, fmt.Errorf("invalid account path %s", permission.Path)
			}
			if walletName == "" {
				return nil, errors.New("wallet cannot be blank")
			}
			walletRegex, err := regexify(walletName)
			if err != nil {
				return nil, fmt.Errorf("invalid wallet regex %s", walletName)
			}
			accountRegex, err := regexify(accountName)
			if err != nil {
				return nil, fmt.Errorf("invalid account regex %s", accountName)
			}
			log.Trace().Str("wallet", walletRegex.String()).Str("account", accountRegex.String()).Strs("operations", permission.Operations).Msg("Adding permission")
			paths[i] = &path{
				wallet:     walletRegex,
				account:    accountRegex,
				operations: permission.Operations,
			}
		}
		parameters.access[client] = paths
	}

	return &parameters, nil
}

// regexify turns a name in to a regex.  It attaches anchors if required, and also makes the regex case-insensitive.
func regexify(name string) (*regexp.Regexp, error) {
	// Empty equates to all.
	if name == "" {
		name = "(?i).*"
	}
	// Anchor if required.
	if !strings.HasPrefix(name, "^") {
		name = fmt.Sprintf("^%s", name)
	}
	if !strings.HasSuffix(name, "$") {
		name = fmt.Sprintf("%s$", name)
	}
	// Case insensitivity if required.
	if !strings.HasPrefix(name, "(?i)") {
		name = fmt.Sprintf("(?i)%s", name)
	}

	return regexp.Compile(name)
}
