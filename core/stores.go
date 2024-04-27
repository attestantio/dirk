// Copyright © 2020, 2022 Attestant Limited.
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

package core

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	filesystem "github.com/wealdtech/go-eth2-wallet-store-filesystem"
	s3 "github.com/wealdtech/go-eth2-wallet-store-s3"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
	"github.com/wealdtech/go-majordomo"
)

// Stores defines all stores.
type Stores struct {
	Stores []*Store `mapstructure:"stores"`
}

// Store defines a single store.
type Store struct {
	Name       string   `mapstructure:"name"`
	Type       string   `mapstructure:"type"`
	Location   string   `mapstructure:"location"`
	Passphrase string   `mapstructure:"passphrase"`
	S3         *S3Store `mapstructure:"s3"`
}

// S3Store defines an S3 store.
type S3Store struct {
	Region      string              `mapstructure:"region"`
	ID          string              `mapstructure:"id"`
	Bucket      string              `mapstructure:"bucket"`
	Path        string              `mapstructure:"path"`
	Endpoint    string              `mapstructure:"endpoint"`
	Credentials *S3StoreCredentials `mapstructure:"credentials"`
}

// S3StoreCredentials defines credentials for an S3 store.
type S3StoreCredentials struct {
	ID     string `mapstructure:"id"`
	Secret string `mapstructure:"secret"`
}

// InitStores initialises the stores from a configuration.
func InitStores(ctx context.Context, majordomo majordomo.Service, storeDefinitions []*Store) ([]e2wtypes.Store, error) {
	if len(storeDefinitions) == 0 {
		log.Warn().Msg("No stores configured; using default")

		return initDefaultStores(), nil
	}
	res := make([]e2wtypes.Store, 0, len(storeDefinitions))
	for i, storeDefinition := range storeDefinitions {
		if storeDefinition.Name == "" {
			return nil, fmt.Errorf("store %d has no name", i)
		}
		if storeDefinition.Type == "" {
			return nil, fmt.Errorf("store %d has no type", i)
		}

		var store e2wtypes.Store
		var err error
		switch storeDefinition.Type {
		case "filesystem":
			store, err = initFilesystemStore(ctx, majordomo, storeDefinition)
		case "s3":
			store, err = initS3Store(ctx, majordomo, storeDefinition)
		case "scratch":
			store = initScratchStore(ctx, majordomo, storeDefinition)
		default:
			return nil, fmt.Errorf("store %d has unhandled type %q", i, storeDefinition.Type)
		}
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to access store %s", storeDefinition.Name))
		}

		res = append(res, store)
	}

	return res, nil
}

func initFilesystemStore(ctx context.Context,
	majordomo majordomo.Service,
	storeDefinition *Store,
) (
	e2wtypes.Store,
	error,
) {
	log.Trace().Str("name", storeDefinition.Name).Str("location", storeDefinition.Location).Msg("Adding filesystem store")

	opts := make([]filesystem.Option, 0)
	if len(storeDefinition.Passphrase) > 0 {
		passphrase, err := majordomo.Fetch(ctx, storeDefinition.Passphrase)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain passphrase")
		}
		opts = append(opts, filesystem.WithPassphrase(passphrase))
	}
	if storeDefinition.Location != "" {
		opts = append(opts, filesystem.WithLocation(storeDefinition.Location))
	}
	store := filesystem.New(opts...)

	return store, nil
}

func initS3Store(ctx context.Context,
	majordomo majordomo.Service,
	storeDefinition *Store,
) (
	e2wtypes.Store,
	error,
) {
	log.Trace().Str("name", storeDefinition.Name).Str("location", storeDefinition.Location).Msg("Adding S3 store")

	opts := make([]s3.Option, 0)
	if len(storeDefinition.Passphrase) > 0 {
		passphrase, err := majordomo.Fetch(ctx, storeDefinition.Passphrase)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain passphrase")
		}
		opts = append(opts, s3.WithPassphrase(passphrase))
	}
	if storeDefinition.S3 != nil {
		opts = append(opts, s3.WithRegion(storeDefinition.S3.Region))
		opts = append(opts, s3.WithID([]byte(storeDefinition.S3.ID)))
		opts = append(opts, s3.WithBucket(storeDefinition.S3.Bucket))
		opts = append(opts, s3.WithPath(storeDefinition.S3.Path))
		opts = append(opts, s3.WithEndpoint(storeDefinition.S3.Endpoint))
	}
	if storeDefinition.S3 != nil && storeDefinition.S3.Credentials != nil {
		id, err := majordomo.Fetch(ctx, storeDefinition.S3.Credentials.ID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain credentials ID")
		}
		opts = append(opts, s3.WithCredentialsID(string(id)))
		secret, err := majordomo.Fetch(ctx, storeDefinition.S3.Credentials.Secret)
		if err != nil {
			return nil, errors.Wrap(err, "failed to obtain credentials secret")
		}
		opts = append(opts, s3.WithCredentialsSecret(string(secret)))
	}
	store, err := s3.New(opts...)
	if err != nil {
		return nil, err
	}

	return store, nil
}

func initScratchStore(_ context.Context,
	_ majordomo.Service,
	storeDefinition *Store,
) e2wtypes.Store {
	log.Trace().Str("name", storeDefinition.Name).Msg("Adding scratch store")

	store := scratch.New()

	return store
}

// initDefaultStores initialises the default stores.
func initDefaultStores() []e2wtypes.Store {
	res := make([]e2wtypes.Store, 1)
	res[0] = filesystem.New()

	return res
}
