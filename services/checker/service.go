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

package checker

import (
	"context"

	"github.com/attestantio/go-certmanager/san"
)

// Credentials are the credentials used to check.
type Credentials struct {
	// Client is the authenticated client identity (extracted from certificate).
	Client string
	// ClientIdentitySource indicates where the Client identity came from.
	// Possible values: "san-dns", "cn", or "unknown" if no identity.
	ClientIdentitySource san.IdentitySource
	// ClientCertificateSANs contains all Subject Alternative Names from the client certificate.
	ClientCertificateSANs *san.CertificateSANs
	// ClientCommonName is the Common Name field of the client certificate's
	// Subject. Retained while SAN-DNS identities co-exist with legacy CN
	// identities so the checker can warn about mismatches during migration.
	ClientCommonName string
	// RequestID is the ID of the request.
	RequestID string
	// IP is the originating IP address of the request.
	IP string
}

// Service is the interface for checking client access to accounts.
type Service interface {
	Check(ctx context.Context, credentials *Credentials, account string, operation string) bool
}
