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

// Package metrics tracks various metrics that measure the performance of dirk.
package metrics

import (
	"time"

	"github.com/attestantio/dirk/core"
)

// Service is the generic metrics service.
type Service interface{}

// BaseMonitor provides base information about the instance.
type BaseMonitor interface {
	// Build is called when the build number is established.
	Build(build uint64)
}

// ReadyMonitor provides information about if the process is ready.
type ReadyMonitor interface {
	// Ready is called when the service is ready to serve requests, or when it stops being so.
	Ready(ready bool)
}

// UnlockerMonitor monitors the unlocker service.
type UnlockerMonitor interface {
}

// CheckerMonitor monitors the checker service.
type CheckerMonitor interface {
}

// SignerMonitor monitors the signer service.
type SignerMonitor interface {
	// SignCompleted is called when a siging process has completed.
	SignCompleted(started time.Time, request string, result core.Result)
}

// FetcherMonitor monitors the fetcher service.
type FetcherMonitor interface {
}

// LockerMonitor monitors the locker service.
type LockerMonitor interface {
}

// RulerMonitor monitors the ruler service.
type RulerMonitor interface {
}

// APIMonitor monitors the API service.
type APIMonitor interface {
}

// PeersMonitor monitors the dirk peers service.
type PeersMonitor interface {
}

// ProcessMonitor monitors the process service.
type ProcessMonitor interface {
}

// SenderMonitor monitors the sender service.
type SenderMonitor interface {
}

// ReceiverMonitor monitors the receiver service.
type ReceiverMonitor interface {
}

// ListerMonitor monitors the account lister service.
type ListerMonitor interface {
	// ListAccountsCompleted is called when a request for accounts has completed.
	ListAccountsCompleted(started time.Time)
}

// AccountManagerMonitor monitors the account manager service.
type AccountManagerMonitor interface {
	// AccountManagerCompleted is called when an account manager process has completed.
	AccountManagerCompleted(started time.Time, request string, result core.Result)
}

// WalletManagerMonitor monitors the wallet manager service.
type WalletManagerMonitor interface {
	// WalletManagerCompleted is called when an wallet manager process has completed.
	WalletManagerCompleted(started time.Time, request string, result core.Result)
}

// ConfidantMonitor monitors the confidant service.
type ConfidantMonitor interface {
}
