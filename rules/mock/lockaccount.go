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

	"github.com/attestantio/dirk/rules"
)

// OnLockAccount is called when a request to lock an account needs to be approved.
func (*Service) OnLockAccount(_ context.Context, _ *rules.ReqMetadata, _ *rules.LockAccountData) rules.Result {
	return rules.APPROVED
}
