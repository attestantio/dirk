// Copyright © 2024 Attestant Limited.
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

package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupCheckerMetrics() error {
	s.checkerPermissions = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "dirk",
		Subsystem: "checker",
		Name:      "permissions",
		Help:      "The clients with permissions configured.",
	}, []string{"client"})
	return prometheus.Register(s.checkerPermissions)
}

// PermissionsObtained is called when permissions have been obtained for clients.
func (s *Service) PermissionsObtained(permissions map[string]int) {
	for client, permissions := range permissions {
		s.checkerPermissions.WithLabelValues(client).Set(float64(permissions))
	}
}
