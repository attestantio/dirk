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
	"sync"

	"github.com/attestantio/dirk/core"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/jackc/puddle"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Service is used to manage the sender piece of distributed key generation operations.
type Service struct {
	name                 string
	credentials          credentials.TransportCredentials
	connectionPoolsMutex sync.Mutex
	connectionPools      map[string]*puddle.Pool
}

// module-wide log.
var log zerolog.Logger

// New creates a new GRPC-based received service.
func New(ctx context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "sender").Str("impl", "grpc").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	credentials, err := composeCredentials(ctx, parameters.serverCert, parameters.serverKey, parameters.caCert)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compose client credentials")
	}

	service := &Service{
		name:            parameters.name,
		credentials:     credentials,
		connectionPools: make(map[string]*puddle.Pool),
	}
	return service, nil
}

// Prepare sends a request to the given recipient to prepare for DKG.
func (s *Service) Prepare(ctx context.Context,
	peer *core.Endpoint,
	account string,
	passphrase []byte,
	threshold uint32,
	participants []*core.Endpoint) error {
	connResource, err := s.obtainConnection(ctx, peer.ConnectAddress())
	if err != nil {
		return errors.Wrap(err, "Failed to obtain connection for Prepare()")
	}
	defer connResource.Release()
	client := pb.NewDKGClient(connResource.Value().(*grpc.ClientConn))

	pbParticipants := make([]*pb.Endpoint, len(participants))
	for i, participant := range participants {
		pbParticipants[i] = &pb.Endpoint{
			Id:   participant.ID,
			Name: participant.Name,
			Port: participant.Port,
		}
	}
	req := &pb.PrepareRequest{
		Account:      account,
		Passphrase:   passphrase,
		Threshold:    threshold,
		Participants: pbParticipants,
	}
	if _, err := client.Prepare(ctx, req); err != nil {
		return errors.Wrap(err, "Failed to call Prepare()")
	}
	return nil
}

// Execute sends a request to the given participant to execute the given DKG.
func (s *Service) Execute(ctx context.Context, peer *core.Endpoint, account string) error {
	connResource, err := s.obtainConnection(ctx, peer.ConnectAddress())
	if err != nil {
		return errors.Wrap(err, "Failed to obtain connection for Execute()")
	}
	defer connResource.Release()
	client := pb.NewDKGClient(connResource.Value().(*grpc.ClientConn))

	req := &pb.ExecuteRequest{
		Account: account,
	}
	if _, err := client.Execute(ctx, req); err != nil {
		return errors.Wrap(err, "Failed to call Execute()")
	}
	return nil
}

// Commit sends a request to the given participant to commit the given DKG.
func (s *Service) Commit(ctx context.Context, peer *core.Endpoint, account string, confirmationData []byte) ([]byte, []byte, error) {
	connResource, err := s.obtainConnection(ctx, peer.ConnectAddress())
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to obtain connection for Commit()")
	}
	defer connResource.Release()
	client := pb.NewDKGClient(connResource.Value().(*grpc.ClientConn))

	req := &pb.CommitRequest{
		Account:          account,
		ConfirmationData: confirmationData,
	}
	res, err := client.Commit(ctx, req)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to call Commit()")
	}
	return res.PublicKey, res.ConfirmationSignature, nil
}

// Abort sends a request to the given participant to abort the given DKG.
func (s *Service) Abort(ctx context.Context, peer *core.Endpoint, account string) error {
	connResource, err := s.obtainConnection(ctx, peer.ConnectAddress())
	if err != nil {
		return errors.Wrap(err, "Failed to obtain connection for Execute()")
	}
	defer connResource.Release()
	client := pb.NewDKGClient(connResource.Value().(*grpc.ClientConn))

	req := &pb.AbortRequest{
		Account: account,
	}
	if _, err := client.Abort(ctx, req); err != nil {
		return errors.Wrap(err, "Failed to call Abort()")
	}
	return nil
}

// SendContribution sends a contribution to a recipient.
func (s *Service) SendContribution(ctx context.Context, peer *core.Endpoint, account string, distributionSecret bls.SecretKey, verificationVector []bls.PublicKey) (bls.SecretKey, []bls.PublicKey, error) {
	connResource, err := s.obtainConnection(ctx, peer.ConnectAddress())
	if err != nil {
		return bls.SecretKey{}, nil, errors.Wrap(err, "Failed to obtain connection for SendContribution()")
	}
	defer connResource.Release()
	client := pb.NewDKGClient(connResource.Value().(*grpc.ClientConn))

	vVec := make([][]byte, len(verificationVector))
	for i, key := range verificationVector {
		vVec[i] = key.Serialize()
	}
	req := &pb.ContributeRequest{
		Account:            account,
		Secret:             distributionSecret.Serialize(),
		VerificationVector: vVec,
	}
	res, err := client.Contribute(ctx, req)
	if err != nil {
		return bls.SecretKey{}, nil, errors.Wrap(err, "Failed to call Contribute()")
	}

	resSecret := bls.SecretKey{}
	if err := resSecret.Deserialize(res.Secret); err != nil {
		return bls.SecretKey{}, nil, errors.Wrap(err, "Returned invalid secret key")
	}
	resVVec := make([]bls.PublicKey, len(res.VerificationVector))
	for i, key := range res.VerificationVector {
		resVVec[i] = bls.PublicKey{}
		if err := resVVec[i].Deserialize(key); err != nil {
			return bls.SecretKey{}, nil, errors.Wrap(err, "Returned invalid verification vector")
		}
	}

	return resSecret, resVVec, nil
}

func composeCredentials(_ context.Context, certPEMBlock []byte, keyPEMBlock []byte, caPEMBlock []byte) (credentials.TransportCredentials, error) {
	clientCert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return nil, errors.Wrap(err, "failed to access client certificate/key")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		MinVersion:   tls.VersionTLS13,
	}
	if len(caPEMBlock) > 0 {
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(caPEMBlock) {
			return nil, errors.New("failed to add CA certificate")
		}
		tlsCfg.RootCAs = cp
	}

	return credentials.NewTLS(tlsCfg), nil
}

// obtainConnection obtains a connection to the required address via GRPC.
func (s *Service) obtainConnection(_ context.Context, address string) (*puddle.Resource, error) {
	s.connectionPoolsMutex.Lock()
	pool, exists := s.connectionPools[address]
	if !exists {
		constructor := func(ctx context.Context) (interface{}, error) {
			return grpc.Dial(address, []grpc.DialOption{
				grpc.WithTransportCredentials(s.credentials),
			}...)
		}
		destructor := func(val interface{}) {
			if err := val.(*grpc.ClientConn).Close(); err != nil {
				log.Warn().Err(err).Msg("Failed to close client connection")
			}
		}
		pool = puddle.NewPool(constructor, destructor, 32)
		s.connectionPools[address] = pool
	}
	s.connectionPoolsMutex.Unlock()
	res, err := pool.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	return res, nil
}
