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

package standard_test

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	standardrules "github.com/attestantio/dirk/rules/standard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	_, err := standardrules.NewStore("/does/not/exist")
	assert.Contains(t, err.Error(), "Error Creating Dir")

	tmpDir, err := ioutil.TempDir("", "")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	_, err = standardrules.NewStore(tmpDir)
	assert.NoError(t, err)
}

func TestStore(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
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
func TestFetch(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "")
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
