// Copyright © 2026 Attestant Limited.
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

package main

import (
	"context"
	"testing"

	certmanager "github.com/attestantio/go-certmanager"
	certmanagermetrics "github.com/attestantio/go-certmanager/metrics"
	"github.com/attestantio/go-certmanager/client/standard"
	servercertstandard "github.com/attestantio/go-certmanager/server/standard"
	certtesting "github.com/attestantio/go-certmanager/testing"
	"github.com/attestantio/go-certmanager/testing/mock"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// stubMonitor is a test monitor exposing a configurable presenter.
type stubMonitor struct{ presenter string }

func (s stubMonitor) Presenter() string { return s.presenter }

var _ certmanagermetrics.Service = stubMonitor{}

func TestStartCertManagerWiresMonitorWithName(t *testing.T) {
	ctx := context.Background()

	majordomoSvc := mock.NewMajordomo(map[string][]byte{
		"cert.pem": []byte(certtesting.SignerTest01Crt),
		"cert.key": []byte(certtesting.SignerTest01Key),
	})

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("certificates.server-cert", "cert.pem")
	viper.Set("certificates.server-key", "cert.key")

	monitor := stubMonitor{presenter: "prometheus"}

	svc, err := startCertManager(ctx, majordomoSvc, monitor)
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestStartCertManagerMonitorWithoutNameRejected(t *testing.T) {
	// Guardrail: if the wiring ever drops WithName, go-certmanager must
	// surface ErrNoNameWithMonitor. Proves the contract we rely on.
	ctx := context.Background()

	majordomoSvc := mock.NewMajordomo(map[string][]byte{
		"cert.pem": []byte(certtesting.SignerTest01Crt),
		"cert.key": []byte(certtesting.SignerTest01Key),
	})

	_, err := servercertstandard.New(ctx,
		servercertstandard.WithMajordomo(majordomoSvc),
		servercertstandard.WithCertPEMURI("cert.pem"),
		servercertstandard.WithCertKeyURI("cert.key"),
		servercertstandard.WithMonitor(stubMonitor{presenter: "prometheus"}),
	)
	require.ErrorIs(t, err, certmanager.ErrNoNameWithMonitor)
}

func TestStartClientCertManagerWiresMonitorWithName(t *testing.T) {
	ctx := context.Background()

	majordomoSvc := mock.NewMajordomo(map[string][]byte{
		"cert.pem": []byte(certtesting.ClientTest01Crt),
		"cert.key": []byte(certtesting.ClientTest01Key),
		"ca.pem":   []byte(certtesting.CACrt),
	})

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("certificates.server-cert", "cert.pem")
	viper.Set("certificates.server-key", "cert.key")
	viper.Set("certificates.ca-cert", "ca.pem")

	monitor := stubMonitor{presenter: "prometheus"}

	svc, err := startClientCertManager(ctx, majordomoSvc, monitor)
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestStartClientCertManagerMonitorWithoutNameRejected(t *testing.T) {
	ctx := context.Background()

	majordomoSvc := mock.NewMajordomo(map[string][]byte{
		"cert.pem": []byte(certtesting.ClientTest01Crt),
		"cert.key": []byte(certtesting.ClientTest01Key),
	})

	_, err := standard.New(ctx,
		standard.WithMajordomo(majordomoSvc),
		standard.WithCertPEMURI("cert.pem"),
		standard.WithCertKeyURI("cert.key"),
		standard.WithMonitor(stubMonitor{presenter: "prometheus"}),
	)
	require.ErrorIs(t, err, certmanager.ErrNoNameWithMonitor)
}
