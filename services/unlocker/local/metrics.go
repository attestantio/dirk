// Copyright © 2023 Attestant Limited.
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

package local

import (
	"context"
	"time"

	"github.com/attestantio/dirk/services/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	unlockAccounts      *prometheus.CounterVec
	unlockAccountsTimer prometheus.Histogram
)

func registerMetrics(ctx context.Context, monitor metrics.Service) error {
	if unlockAccounts != nil {
		// Already registered.
		return nil
	}
	if monitor == nil {
		// No monitor.
		return nil
	}
	if monitor.Presenter() == "prometheus" {
		return registerPrometheusMetrics(ctx)
	}
	return nil
}

func registerPrometheusMetrics(_ context.Context) error {
	unlockAccounts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dirk",
		Subsystem: "unlocker_account",
		Name:      "requests_total",
		Help:      "The requests to unlock an account",
	}, []string{"result"})
	if err := prometheus.Register(unlockAccounts); err != nil {
		return err
	}
	unlockAccounts.WithLabelValues("succeeded").Add(0)
	unlockAccounts.WithLabelValues("failed").Add(0)

	unlockAccountsTimer = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "dirk",
		Subsystem: "unlocker_account",
		Name:      "requests_duration_seconds",
		Help:      "The time dirk spends unlocking accounts.",
		Buckets: []float64{
			0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
			1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 2.0,
			2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.0,
			3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 4.0,
		},
	})
	return prometheus.Register(unlockAccountsTimer)
}

func monitorUnlockAccount(succeeded bool, duration time.Duration) {
	if unlockAccounts == nil {
		// Not yet registered.
		return
	}

	unlockAccountsTimer.Observe(duration.Seconds())
	if succeeded {
		unlockAccounts.WithLabelValues("succeeded").Add(1)
	} else {
		unlockAccounts.WithLabelValues("failed").Add(1)
	}
}
