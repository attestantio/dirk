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

package mock

import (
	"context"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/checker"
)

// Service is a mock account manager service.
type Service struct{}

// New creates a new account manager service.
func New() *Service {
	return &Service{}
}

// Generate generates a new account.
func (*Service) Generate(_ context.Context,
	_ *checker.Credentials,
	_ string,
	_ []byte,
	_ uint32,
	_ uint32,
) (
	core.Result,
	[]byte,
	[]*core.Endpoint,
	error,
) {
	return core.ResultSucceeded,
		[]byte{
			0xb5, 0xdd, 0x37, 0x43, 0xf5, 0x7f, 0xcd, 0xf3, 0x9c, 0x6c, 0xf8, 0xdb, 0x4c, 0x4a, 0xbd, 0x0e,
			0xb7, 0xda, 0x8d, 0x71, 0xb0, 0x6b, 0x5b, 0xdc, 0x2b, 0x3b, 0xc4, 0x37, 0x03, 0xc0, 0x0d, 0xdb,
			0xb3, 0xef, 0xd3, 0x44, 0x86, 0x2c, 0xf9, 0x0a, 0x6b, 0xda, 0x60, 0xb2, 0x03, 0x78, 0x8e, 0x17,
		},
		[]*core.Endpoint{
			{
				ID:   1,
				Name: "server-01",
				Port: 12345,
			},
		},
		nil
}

// Unlock unlocks an account.
func (*Service) Unlock(_ context.Context,
	_ *checker.Credentials,
	_ string,
	_ []byte,
) (
	core.Result,
	error,
) {
	return core.ResultSucceeded, nil
}

// Lock locks an account.
func (*Service) Lock(_ context.Context,
	_ *checker.Credentials,
	_ string,
) (
	core.Result,
	error,
) {
	return core.ResultSucceeded, nil
}
