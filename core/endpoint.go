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

package core

import (
	"fmt"
	"net"
)

// Endpoint contains information about an endpoint.
type Endpoint struct {
	ID   uint64 `mapstructure:"id"`
	Name string `mapstructure:"name"`
	Port uint32 `mapstructure:"port"`
}

// ConnectAddress returns an address suitable for connecting to the endpoint.
func (e *Endpoint) ConnectAddress() string {
	return net.JoinHostPort(e.Name, fmt.Sprintf("%d", e.Port))
}

// String returns a human-readable representation of the endpoint.
func (e *Endpoint) String() string {
	return e.ConnectAddress()
}
