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
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	scratch "github.com/wealdtech/go-eth2-wallet-store-scratch"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// func TestMain(m *testing.M) {
// 	if err := e2types.InitBLS(); err != nil {
// 		os.Exit(1)
// 	}
// 	os.Exit(m.Run())
// }

func TestWalletFromBytes(t *testing.T) {
	store := scratch.New()
	encryptor := keystorev4.New()

	walletID := uuid.New()

	tests := []struct {
		name      string
		data      []byte
		store     e2wtypes.Store
		encryptor e2wtypes.Encryptor
		err       string
	}{
		{
			name: "NoStore",
			err:  "no store provided",
		},
		{
			name:  "NoEncryptor",
			store: store,
			err:   "no encryptor provided",
		},
		{
			name:      "NoData",
			store:     store,
			encryptor: encryptor,
			err:       "no data provided",
		},
		{
			name:      "BadData",
			store:     store,
			encryptor: encryptor,
			data:      []byte("Hello, world!"),
			err:       "invalid character 'H' looking for beginning of value",
		},
		{
			name:      "UnknownType",
			store:     store,
			encryptor: encryptor,
			data:      []byte(fmt.Sprintf(`{"uuid":"%s","version":1,"name":"Test wallet","type":"notknown"}`, walletID.String())),
			err:       "unsupported wallet type \"notknown\"",
		},
		{
			name:      "Good",
			store:     store,
			encryptor: encryptor,
			data:      []byte(fmt.Sprintf(`{"uuid":"%s","version":1,"name":"Test wallet","type":"non-deterministic"}`, walletID.String())),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := walletFromBytes(context.Background(), test.data, test.store, test.encryptor)
			if test.err == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}
