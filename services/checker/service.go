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

package checker

import "context"

// Credentials are the credentials used to check.
type Credentials struct {
	// RequestID is the ID of the request.
	RequestID string
	// Client is the authenticated client identity (extracted from certificate).
	Client string
	// ClientIdentitySource indicates where the Client identity came from.
	// Possible values: "san-dns", "san-ip", "san-email", "cn", or "" if no identity.
	ClientIdentitySource string
	// ClientCertificateSANs contains all Subject Alternative Names from the client certificate.
	ClientCertificateSANs *CertificateSANs
	// IP is the originating IP address of the request.
	IP string
}

// CertificateSANs contains all Subject Alternative Name values from a certificate.
type CertificateSANs struct {
	// DNSNames contains all DNS names from the certificate's SAN extension.
	DNSNames []string
	// IPAddresses contains all IP addresses from the certificate's SAN extension (as strings).
	IPAddresses []string
	// EmailAddresses contains all email addresses from the certificate's SAN extension.
	EmailAddresses []string
}

// Service is the interface for checking client access to accounts.
type Service interface {
	Check(ctx context.Context, credentials *Credentials, account string, operation string) bool
}
