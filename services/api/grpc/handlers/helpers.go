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

package handlers

import (
	context "context"

	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	"github.com/attestantio/dirk/services/checker"
)

// GenerateCredentials generates checker credentials from the GRPC request information.
func GenerateCredentials(ctx context.Context) *checker.Credentials {
	res := &checker.Credentials{}

	if requestID, ok := ctx.Value(&interceptors.RequestID{}).(string); ok {
		res.RequestID = requestID
	}
	if client, ok := ctx.Value(&interceptors.ClientName{}).(string); ok {
		res.Client = client
	}
	if identitySource, ok := ctx.Value(&interceptors.ClientIdentitySource{}).(string); ok {
		res.ClientIdentitySource = identitySource
	}
	if certSANs, ok := ctx.Value(&interceptors.ClientCertificateSANs{}).(*interceptors.CertificateSANs); ok {
		// Convert from interceptors type to checker type.
		res.ClientCertificateSANs = &checker.CertificateSANs{
			DNSNames:       certSANs.DNSNames,
			IPAddresses:    certSANs.IPAddresses,
			EmailAddresses: certSANs.EmailAddresses,
		}
	}
	if ip, ok := ctx.Value(&interceptors.ExternalIP{}).(string); ok {
		res.IP = ip
	}

	return res
}
