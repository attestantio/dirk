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
	"context"
	"errors"

	"github.com/attestantio/dirk/util/loggers"
	badger "github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"
	"github.com/opentracing/opentracing-go"
)

// Store holds key/value pairs in a badger database.
type Store struct {
	db *badger.DB
}

// NewStore creates a new badger store.
func NewStore(base string) (*Store, error) {
	opt := badger.DefaultOptions(base)
	opt.TableLoadingMode = options.LoadToRAM
	opt.ValueLogLoadingMode = options.MemoryMap
	opt.SyncWrites = true
	opt.Logger = loggers.NewBadgerLogger(log)
	db, err := badger.Open(opt)
	if err != nil {
		return nil, err
	}

	return &Store{
		db: db,
	}, nil
}

// Fetch fetches a value for a given key.
func (s *Store) Fetch(ctx context.Context, key []byte) ([]byte, error) {
	span, _ := opentracing.StartSpanFromContext(ctx, "storage.Fetch")
	defer span.Finish()

	if len(key) == 0 {
		return nil, errors.New("no key provided")
	}

	var value []byte
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			if err == badger.ErrKeyNotFound {
				return errors.New("not found")
			}
		}
		err = item.Value(func(val []byte) error {
			value = val
			return nil
		})
		if err != nil {
			return err
		}

		return err
	})
	if err != nil {
		return nil, err
	}
	return value, nil
}

// Store stores the value for a given key.
func (s *Store) Store(ctx context.Context, key []byte, value []byte) error {
	span, _ := opentracing.StartSpanFromContext(ctx, "storage.Store")
	defer span.Finish()

	if len(key) == 0 {
		return errors.New("no key provided")
	}

	if len(value) == 0 {
		return errors.New("no value provided")
	}

	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

// Close closes the store.
func (s *Store) Close(ctx context.Context) error {
	return s.db.Close()
}
