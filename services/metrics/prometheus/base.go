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

package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupBaseMetrics() error {
	startTime := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "dirk",
		Name:      "start_time_secs",
		Help:      "The timestamp at which dirk started.",
	})
	if err := prometheus.Register(startTime); err != nil {
		return err
	}
	startTime.SetToCurrentTime()

	s.build = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "dirk",
		Name:      "build",
		Help:      "The build number of this instance.",
	})
	return prometheus.Register(s.build)
}

// Build is called when the build number is established.
func (s *Service) Build(build uint64) {
	s.build.Set(float64(build))
}
