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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func (s *Service) setupListerMetrics() error {
	s.listerProcessTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "dirk",
		Subsystem: "lister_process",
		Name:      "duration_seconds",
		Help:      "The time dirk spends in the account list process.",
		Buckets: []float64{
			0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.10,
			0.11, 0.12, 0.13, 0.14, 0.15, 0.16, 0.17, 0.18, 0.19, 0.20,
		},
	})
	if err := prometheus.Register(s.listerProcessTimer); err != nil {
		return err
	}

	s.listerRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dirk",
		Subsystem: "lister_process",
		Name:      "requests_total",
		Help:      "The number of account list requests.",
	}, []string{"result"})
	return prometheus.Register(s.listerRequests)
}

// ListAccountsCompleted is called when an account list process has completed.
func (s *Service) ListAccountsCompleted(started time.Time) {
	s.listerProcessTimer.Observe(time.Since(started).Seconds())
	s.listerRequests.WithLabelValues("succeeded").Inc()
}
