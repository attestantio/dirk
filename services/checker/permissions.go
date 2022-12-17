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

package checker

import (
	"fmt"
	"strings"
)

// Permissions contains information about the operations allowed by the client.
type Permissions struct {
	Path       string   `mapstructure:"path"`
	Operations []string `mapstructure:"operations"`
}

// DumpPermissions dumps permissions for our clients to stdout.
func DumpPermissions(perms map[string][]*Permissions) {
	for client, perms := range perms {
		if client == "" {
			fmt.Println("ERROR: client does not have a name")
			continue
		}
		fmt.Printf("Permissions for %q:\n", client)
		for _, perm := range perms {
			var pathDescriptor string
			if perm.Path == "" {
				pathDescriptor = "all accounts"
			} else {
				pathDescriptor = fmt.Sprintf("accounts matching the path %q", perm.Path)
			}

			var opDescriptor string
			if len(perm.Operations) == 1 && perm.Operations[0] == "All" {
				opDescriptor = "all operations"
			} else {
				opDescriptor = fmt.Sprintf("operations %s\n", strings.Join(perm.Operations, ", "))
			}
			fmt.Printf(" - %s can carry out %s\n", pathDescriptor, opDescriptor)
		}
	}
}
