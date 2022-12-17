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

package syncmap

import (
	"context"
	"sync"

	"github.com/attestantio/dirk/services/metrics"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// Service provides a global account locker using sync.Map.
type Service struct {
	monitor      metrics.LockerMonitor
	locks        *sync.Map
	newLockMutex sync.Mutex
	mapLock      sync.Mutex
}

// module-wide log.
var log zerolog.Logger

// New creates a new in-memory fetcher.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "locker").Str("impl", "syncmap").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		monitor: parameters.monitor,
		locks:   &sync.Map{},
	}

	return s, nil
}

// PreLock must be called prior to locking one or more public keys.
// It obtains a locker-wide mutex, to ensure that only one goroutine
// can be locking or unlocking groups of public keys at a time.
func (s *Service) PreLock() {
	s.mapLock.Lock()
}

// PostLock must be called after locking one or more public keys.
// It frees the locker-wide mutex obtained by PreLock().
func (s *Service) PostLock() {
	s.mapLock.Unlock()
}

// Lock acquires a lock for a given public key.
// If more than one lock is being acquired in a batch, ensure that
// PreLock() is called beforehand and PostLock() afterwards.
func (s *Service) Lock(key [48]byte) {
	lock, exists := s.locks.Load(key)
	if !exists {
		s.newLockMutex.Lock()
		lock, exists = s.locks.Load(key)
		if !exists {
			lock = &sync.Mutex{}
			s.locks.Store(key, lock)
		}
		s.newLockMutex.Unlock()
	}
	lock.(*sync.Mutex).Lock()
}

// Unlock frees a lock for a given public key.
func (s *Service) Unlock(key [48]byte) {
	lock, exists := s.locks.Load(key)
	if !exists {
		panic("Attempt to unlock an unknown lock")
	}
	lock.(*sync.Mutex).Unlock()
}
