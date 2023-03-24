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
	"time"

	"github.com/attestantio/dirk/core"
)

// noopMonitor is a monitor that does nothing, used in place of nil if an
// external monitor is not supplied.
type noopMonitor struct{}

// WalletManagerCompleted is called when an wallet manager process has completed.
func (n *noopMonitor) WalletManagerCompleted(_ time.Time, _ string, _ core.Result) {}
