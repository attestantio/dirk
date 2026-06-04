// Copyright © 2020 - 2026 Attestant Limited.
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

package interceptors

import (
	"context"

	"github.com/attestantio/go-certmanager/san"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ClientName is a context tag for the identity extracted from the client's certificate.
type ClientName struct{}

// ClientIdentitySource is a context tag for the source of the client identity.
type ClientIdentitySource struct{}

// ClientCertificateSANs is a context tag for all SANs from the client's certificate.
type ClientCertificateSANs struct{}

// ClientCommonName is a context tag for the Common Name field of the client's certificate.
type ClientCommonName struct{}

// ClientInfoInterceptor adds the client certificate identity to incoming requests.
//
// Identity is extracted from the client certificate using a prioritized approach
// that complies with RFC 6125 (domain name verification) by preferring Subject
// Alternative Name (SAN) fields over the deprecated Common Name (CN).
//
// The identity extraction follows this priority order:
//  1. DNS names from SAN - Most common for service-to-service authentication
//  2. Common Name (CN) - Fallback for backward compatibility with legacy certificates
func ClientInfoInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		grpcPeer, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Internal, "Failure")
		}

		newCtx := ctx
		tlsInfo, ok := grpcPeer.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing TLS auth info")
		}
		authState := tlsInfo.State
		if authState.HandshakeComplete {
			peerCerts := authState.PeerCertificates
			if len(peerCerts) > 0 {
				peerCert := peerCerts[0]

				// Extract client identity using go-certmanager SAN utilities.
				clientIdentity, identitySource := san.ExtractIdentity(peerCert)
				certificateSANs := san.ExtractAllSANs(peerCert)

				newCtx = context.WithValue(ctx, &ClientName{}, clientIdentity)
				newCtx = context.WithValue(newCtx, &ClientIdentitySource{}, identitySource)
				newCtx = context.WithValue(newCtx, &ClientCertificateSANs{}, certificateSANs)
				newCtx = context.WithValue(newCtx, &ClientCommonName{}, peerCert.Subject.CommonName)
			}
		}

		return handler(newCtx, req)
	}
}
