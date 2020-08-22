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
	"strings"

	"github.com/attestantio/dirk/services/checker"
)

// Service is a checker that returns true all clients and accounts except those that start with "Deny".
type Service struct{}

// New creates a new mock checker.
func New() (*Service, error) {
	return &Service{}, nil
}

// Check returns true unless the client or account is "Deny".
func (s *Service) Check(ctx context.Context, credentials *checker.Credentials, account string, operation string) bool {
	if credentials == nil {
		return false
	}
	return !(strings.HasPrefix(credentials.Client, "Deny") || strings.Contains(account, "/Deny"))
}
