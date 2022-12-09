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

package standard_test

import (
	"context"
	"os"
	"testing"

	standardrules "github.com/attestantio/dirk/rules/standard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	_, err := standardrules.NewStore("/does/not/exist")
	assert.Contains(t, err.Error(), "Error Creating Dir")

	tmpDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	_, err = standardrules.NewStore(tmpDir)
	assert.NoError(t, err)
}

func TestStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	service, err := standardrules.NewStore(tmpDir)
	require.NoError(t, err)

	tests := []struct {
		name  string
		key   []byte
		value []byte
		err   string
	}{
		{
			name: "Nil",
			err:  "no key provided",
		},
		{
			name: "Empty",
			key:  []byte{},
			err:  "no key provided",
		},
		{
			name: "NoValue",
			key:  []byte("nokey"),
			err:  "no value provided",
		},
		{
			name:  "Good",
			key:   []byte("key"),
			value: []byte("value"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := service.Store(context.Background(), test.key, test.value)
			if test.err == "" {
				require.Nil(t, err)
			} else {
				require.NotNil(t, err)
				require.EqualError(t, err, test.err)
			}
		})
	}
}

func TestBatchStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	service, err := standardrules.NewStore(tmpDir)
	require.NoError(t, err)

	tests := []struct {
		name   string
		keys   [][]byte
		values [][]byte
		err    string
	}{
		{
			name: "Nil",
			err:  "no keys provided",
		},
		{
			name: "KeyMissing",
			values: [][]byte{
				[]byte("nokey"),
			},
			err: "no keys provided",
		},
		{
			name: "KeyEmpty",
			keys: [][]byte{
				[]byte(""),
			},
			values: [][]byte{
				[]byte("nokey"),
			},
			err: "empty key provided",
		},
		{
			name: "ValueMissing",
			keys: [][]byte{
				[]byte("novalue"),
			},
			err: "key/value length mismatch",
		},
		{
			name: "ValueEmpty",
			keys: [][]byte{
				[]byte("novalue"),
			},
			values: [][]byte{
				[]byte(""),
			},
			err: "empty value provided",
		},
		{
			name: "Good",
			keys: [][]byte{
				[]byte("key1"),
				[]byte("key2"),
				[]byte("key3"),
				[]byte("key4"),
			},
			values: [][]byte{
				[]byte("value1"),
				[]byte("value2"),
				[]byte("value3"),
				[]byte("value4"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := service.BatchStore(context.Background(), test.keys, test.values)
			if test.err == "" {
				require.Nil(t, err)
				for i := range test.keys {
					val, err := service.Fetch(context.Background(), test.keys[i])
					require.Nil(t, err)
					require.Equal(t, test.values[i], val)
				}
			} else {
				require.NotNil(t, err)
				require.EqualError(t, err, test.err)
			}

		})
	}
}

func TestFetch(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	service, err := standardrules.NewStore(tmpDir)
	require.NoError(t, err)

	require.NoError(t, service.Store(context.Background(), []byte("key"), []byte("value")))

	tests := []struct {
		name string
		key  []byte
		err  string
	}{
		{
			name: "Nil",
			err:  "no key provided",
		},
		{
			name: "Empty",
			key:  []byte{},
			err:  "no key provided",
		},
		{
			name: "Missing",
			key:  []byte("nokey"),
			err:  "not found",
		},
		{
			name: "Good",
			key:  []byte("key"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Fetch(context.Background(), test.key)
			if test.err == "" {
				require.Nil(t, err)
			} else {
				require.NotNil(t, err)
				require.EqualError(t, err, test.err)
			}
		})
	}
}

func TestFetchAll(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	service, err := standardrules.NewStore(tmpDir)
	require.NoError(t, err)

	keys := [][49]byte{
		{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			0x10,
		},
		{
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
			0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
			0x20,
		},
		{
			0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
			0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
			0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
			0x30,
		},
		{
			0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
			0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
			0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
			0x40,
		},
	}
	values := [][]byte{
		[]byte("value1"),
		[]byte("value2"),
		[]byte("value3"),
		[]byte("value4"),
	}
	for i := range keys {
		require.NoError(t, service.Store(context.Background(), keys[i][:], values[i]))
	}

	fetchedValues, err := service.FetchAll(context.Background())
	require.NoError(t, err)
	require.Equal(t, len(fetchedValues), len(values))
	for i := range keys {
		require.Equal(t, values[i], fetchedValues[keys[i]])
	}
}
