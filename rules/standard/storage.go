// Copyright © 2020, 2021 Attestant Limited.
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

	"github.com/attestantio/dirk/util/loggers"
	badger "github.com/dgraph-io/badger/v2"
	"github.com/dgraph-io/badger/v2/options"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
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

	// Garbage collect in the background on start.
	go func(db *badger.DB) {
		for {
			if err = db.RunValueLogGC(0.7); err != nil {
				// Error occurs when there is nothing left to collect.
				break
			}
		}
	}(db)

	return &Store{
		db: db,
	}, nil
}

// FetchAll fetches a map of all keys and values.
func (s *Store) FetchAll(ctx context.Context) (map[[49]byte][]byte, error) {
	items := make(map[[49]byte][]byte)
	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			err := item.Value(func(v []byte) error {
				var key [49]byte
				copy(key[:], item.Key())
				value := make([]byte, len(v))
				copy(value, v)
				items[key] = value
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return items, nil
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
			if errors.Is(err, badger.ErrKeyNotFound) {
				return errors.New("not found")
			}
		}
		err = item.Value(func(val []byte) error {
			value = make([]byte, len(val))
			copy(value, val)
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

// BatchStore stores multiple keys and values.
func (s *Store) BatchStore(ctx context.Context, keys [][]byte, values [][]byte) error {
	span, _ := opentracing.StartSpanFromContext(ctx, "storage.BatchStore")
	defer span.Finish()

	if len(keys) == 0 {
		return errors.New("no keys provided")
	}
	if len(keys) != len(values) {
		return errors.New("key/value length mismatch")
	}
	for i := range keys {
		if len(keys[i]) == 0 {
			return errors.New("empty key provided")
		}
		if len(values[i]) == 0 {
			return errors.New("empty value provided")
		}
	}

	wb := s.db.NewWriteBatch()
	defer wb.Cancel()

	for i := range keys {
		if err := wb.Set(keys[i], values[i]); err != nil {
			return errors.Wrap(err, "failed to set")
		}
	}

	return wb.Flush()
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
