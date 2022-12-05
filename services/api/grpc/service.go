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

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"

	accountmanagerhandler "github.com/attestantio/dirk/services/api/grpc/handlers/accountmanager"
	listerhandler "github.com/attestantio/dirk/services/api/grpc/handlers/lister"
	receiverhandler "github.com/attestantio/dirk/services/api/grpc/handlers/receiver"
	signerhandler "github.com/attestantio/dirk/services/api/grpc/handlers/signer"
	walletmanagerhandler "github.com/attestantio/dirk/services/api/grpc/handlers/walletmanager"
	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	"github.com/attestantio/dirk/services/metrics"
	"github.com/attestantio/dirk/util/loggers"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_ctxtags "github.com/grpc-ecosystem/go-grpc-middleware/tags"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
)

// Service provides the features and functions for the GRPC daemon.
type Service struct {
	monitor    metrics.APIMonitor
	grpcServer *grpc.Server
}

// module-wide log.
var log zerolog.Logger

// New creates a new API service over GRPC.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "api").Str("impl", "grpc").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	s := &Service{
		monitor: parameters.monitor,
	}

	if err := s.createServer(parameters.name, parameters.serverCert, parameters.serverKey, parameters.caCert); err != nil {
		return nil, errors.Wrap(err, "failed to create API server")
	}

	walletManagerHandler, err := walletmanagerhandler.New(ctx,
		walletmanagerhandler.WithLogLevel(parameters.logLevel),
		walletmanagerhandler.WithWalletManager(parameters.walletManager),
		walletmanagerhandler.WithProcess(parameters.process),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create wallet manager handler")
	}
	pb.RegisterWalletManagerServer(s.grpcServer, walletManagerHandler)

	accountManagerHandler, err := accountmanagerhandler.New(ctx,
		accountmanagerhandler.WithLogLevel(parameters.logLevel),
		accountmanagerhandler.WithAccountManager(parameters.accountManager),
		accountmanagerhandler.WithProcess(parameters.process),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create account manager handler")
	}
	pb.RegisterAccountManagerServer(s.grpcServer, accountManagerHandler)

	listerHandler, err := listerhandler.New(ctx,
		listerhandler.WithLister(parameters.lister),
		listerhandler.WithLogLevel(parameters.logLevel),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create lister handler")
	}
	pb.RegisterListerServer(s.grpcServer, listerHandler)

	signerHandler, err := signerhandler.New(ctx,
		signerhandler.WithSigner(parameters.signer),
		signerhandler.WithLogLevel(parameters.logLevel),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create signer handler")
	}
	pb.RegisterSignerServer(s.grpcServer, signerHandler)

	receiverHandler, err := receiverhandler.New(ctx,
		receiverhandler.WithLogLevel(parameters.logLevel),
		receiverhandler.WithProcess(parameters.process),
		receiverhandler.WithPeers(parameters.peers),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create receiver handler")
	}
	pb.RegisterDKGServer(s.grpcServer, receiverHandler)

	err = s.serve(parameters.listenAddress)
	if err != nil {
		return nil, errors.Wrap(err, "failed to start API server")
	}

	// Cancel service on context done.
	go func() {
		<-ctx.Done()
		s.grpcServer.GracefulStop()
	}()

	return s, nil
}

// createServer creates the GRPC server.
func (s *Service) createServer(name string, certPEMBlock []byte, keyPEMBlock []byte, caPEMBlock []byte) error {
	grpclog.SetLoggerV2(loggers.NewGRPCLoggerV2(log.With().Str("service", "grpc").Logger()))

	grpcOpts := []grpc.ServerOption{
		grpc.UnaryInterceptor(
			grpc_middleware.ChainUnaryServer(
				otelgrpc.UnaryServerInterceptor(),
				grpc_ctxtags.UnaryServerInterceptor(grpc_ctxtags.WithFieldExtractor(grpc_ctxtags.CodeGenRequestFieldExtractor)),
				interceptors.RequestIDInterceptor(),
				interceptors.SourceIPInterceptor(),
				interceptors.ClientInfoInterceptor(),
			)),
	}

	if name == "" {
		return errors.New("no server name provided; cannot proceed")
	}

	serverCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return errors.Wrap(err, "failed to load server keypair")
	}

	certPool := x509.NewCertPool()
	if len(caPEMBlock) > 0 {
		// Read in the certificate authority certificate; this is required to validate client certificates on incoming connections.
		if ok := certPool.AppendCertsFromPEM(caPEMBlock); !ok {
			return errors.New("could not add CA certificate to pool")
		}
	}

	serverCreds := credentials.NewTLS(&tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
	})
	grpcOpts = append(grpcOpts, grpc.Creds(serverCreds))
	s.grpcServer = grpc.NewServer(grpcOpts...)

	return nil
}

// Serve serves the GRPC server.
func (s *Service) serve(listenAddress string) error {
	conn, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return err
	}
	log.Info().Str("address", listenAddress).Msg("Listening")

	go func() {
		if err := s.grpcServer.Serve(conn); err != nil {
			log.Error().Err(err).Msg("Could not start GRPC server")
		}
	}()
	return nil
}
