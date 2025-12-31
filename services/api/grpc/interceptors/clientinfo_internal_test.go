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

package interceptors

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractClientIdentity(t *testing.T) {
	tests := []struct {
		name         string
		cert         *x509.Certificate
		wantIdentity string
		wantSource   string
		description  string
	}{
		{
			name: "SAN DNS single",
			cert: &x509.Certificate{
				DNSNames: []string{"validator-01.example.com"},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "validator-01.example.com",
			wantSource:   "san-dns",
			description:  "Single DNS name in SAN should be preferred over CN",
		},
		{
			name: "SAN DNS multiple",
			cert: &x509.Certificate{
				DNSNames: []string{
					"primary.example.com",
					"secondary.example.com",
					"tertiary.example.com",
				},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "primary.example.com",
			wantSource:   "san-dns",
			description:  "First DNS name should be selected when multiple are present",
		},
		{
			name: "SAN IP single IPv4",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("192.168.1.100")},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "192.168.1.100",
			wantSource:   "san-ip",
			description:  "IPv4 address in SAN should be used when no DNS names present",
		},
		{
			name: "SAN IP single IPv6",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{net.ParseIP("2001:db8::1")},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "2001:db8::1",
			wantSource:   "san-ip",
			description:  "IPv6 address in SAN should be used when no DNS names present",
		},
		{
			name: "SAN IP multiple",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("10.0.0.2"),
					net.ParseIP("2001:db8::1"),
				},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "10.0.0.1",
			wantSource:   "san-ip",
			description:  "First IP address should be selected when multiple are present",
		},
		{
			name: "SAN Email single",
			cert: &x509.Certificate{
				EmailAddresses: []string{"validator@example.com"},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "validator@example.com",
			wantSource:   "san-email",
			description:  "Email address in SAN should be used when no DNS or IP present",
		},
		{
			name: "SAN Email multiple",
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"primary@example.com",
					"secondary@example.com",
					"tertiary@example.com",
				},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "primary@example.com",
			wantSource:   "san-email",
			description:  "First email should be selected when multiple are present",
		},
		{
			name: "CN only (legacy)",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "legacy-client.example.com",
				},
			},
			wantIdentity: "legacy-client.example.com",
			wantSource:   "cn",
			description:  "CN should be used as fallback when no SAN present",
		},
		{
			name: "SAN DNS priority over IP",
			cert: &x509.Certificate{
				DNSNames:    []string{"dns-name.example.com"},
				IPAddresses: []net.IP{net.ParseIP("192.168.1.1")},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "dns-name.example.com",
			wantSource:   "san-dns",
			description:  "DNS name should be preferred over IP address",
		},
		{
			name: "SAN DNS priority over Email",
			cert: &x509.Certificate{
				DNSNames:       []string{"dns-name.example.com"},
				EmailAddresses: []string{"email@example.com"},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "dns-name.example.com",
			wantSource:   "san-dns",
			description:  "DNS name should be preferred over email address",
		},
		{
			name: "SAN IP priority over Email",
			cert: &x509.Certificate{
				IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
				EmailAddresses: []string{"email@example.com"},
				Subject: pkix.Name{
					CommonName: "should-not-use-this",
				},
			},
			wantIdentity: "192.168.1.1",
			wantSource:   "san-ip",
			description:  "IP address should be preferred over email address",
		},
		{
			name: "All SAN types present",
			cert: &x509.Certificate{
				DNSNames:       []string{"dns.example.com"},
				IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
				EmailAddresses: []string{"email@example.com"},
				Subject: pkix.Name{
					CommonName: "cn.example.com",
				},
			},
			wantIdentity: "dns.example.com",
			wantSource:   "san-dns",
			description:  "DNS should win when all identity types are present",
		},
		{
			name: "Empty DNS name ignored",
			cert: &x509.Certificate{
				DNSNames:    []string{""},
				IPAddresses: []net.IP{net.ParseIP("192.168.1.1")},
				Subject: pkix.Name{
					CommonName: "fallback.example.com",
				},
			},
			wantIdentity: "192.168.1.1",
			wantSource:   "san-ip",
			description:  "Empty DNS name should be skipped, next priority used",
		},
		{
			name: "Empty Email ignored",
			cert: &x509.Certificate{
				EmailAddresses: []string{""},
				Subject: pkix.Name{
					CommonName: "fallback.example.com",
				},
			},
			wantIdentity: "fallback.example.com",
			wantSource:   "cn",
			description:  "Empty email address should be skipped, CN used as fallback",
		},
		{
			name: "No identity available",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "",
				},
			},
			wantIdentity: "",
			wantSource:   "",
			description:  "Empty string and source when no identity available",
		},
		{
			name: "Complex realistic scenario - modern CA",
			cert: &x509.Certificate{
				DNSNames: []string{
					"validator-prod-01.validators.example.com",
					"validator-prod-01.internal",
					"10-0-1-100.validators.example.com",
				},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.1.100"),
					net.ParseIP("192.168.50.10"),
				},
				Subject: pkix.Name{
					CommonName: "",
				},
			},
			wantIdentity: "validator-prod-01.validators.example.com",
			wantSource:   "san-dns",
			description:  "Modern CA certificate with multiple SANs and empty CN",
		},
		{
			name: "Service certificate with email",
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"service-account-validator@example.com",
					"backup-validator@example.com",
				},
				Subject: pkix.Name{
					CommonName: "Service Account Validator",
				},
			},
			wantIdentity: "service-account-validator@example.com",
			wantSource:   "san-email",
			description:  "Service certificate using email-based identity",
		},
		{
			name: "Certificate with unusual but technically valid emails",
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"test@localhost", // Local email without domain
					"user@127.0.0.1", // IP address as domain
					"valid@example.com",
				},
				Subject: pkix.Name{
					CommonName: "unusual-email-client",
				},
			},
			wantIdentity: "test@localhost",
			wantSource:   "san-email",
			description:  "Unusual but syntactically valid emails are accepted as identities",
		},
		{
			name: "Certificate with private/reserved IP addresses",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("127.0.0.1"),     // localhost
					net.ParseIP("192.168.1.100"), // private network
					net.ParseIP("10.0.0.1"),      // private network
				},
				Subject: pkix.Name{
					CommonName: "private-ip-client",
				},
			},
			wantIdentity: "127.0.0.1",
			wantSource:   "san-ip",
			description:  "Private and reserved IP addresses are accepted as valid identities",
		},
		{
			name: "Certificate with IPv6 localhost",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("::1"),         // IPv6 localhost
					net.ParseIP("2001:db8::1"), // IPv6 documentation address
				},
				Subject: pkix.Name{
					CommonName: "ipv6-client",
				},
			},
			wantIdentity: "::1",
			wantSource:   "san-ip",
			description:  "IPv6 addresses including localhost are properly handled",
		},
		{
			name: "Certificate with public IP when localhost expected",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("8.8.8.8"), // Public DNS server IP
				},
				DNSNames: []string{"localhost"}, // But claims to be localhost
				Subject: pkix.Name{
					CommonName: "localhost",
				},
			},
			wantIdentity: "localhost",
			wantSource:   "san-dns",
			description:  "DNS names take priority over IPs, even with mismatched values",
		},
		{
			name: "Certificate with wrong domain email",
			cert: &x509.Certificate{
				EmailAddresses: []string{
					"admin@wrong-domain.com", // Email for different domain
				},
				DNSNames: []string{"validator.example.com"},
				Subject: pkix.Name{
					CommonName: "validator.example.com",
				},
			},
			wantIdentity: "validator.example.com",
			wantSource:   "san-dns",
			description:  "DNS identity takes priority over email, regardless of email domain",
		},
		{
			name: "Localhost IP",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("127.0.0.1"),
				},
				Subject: pkix.Name{
					CommonName: "localhost",
				},
			},
			wantIdentity: "127.0.0.1",
			wantSource:   "san-ip",
			description:  "Localhost IP address should be handled correctly",
		},
		{
			name: "IPv6 localhost",
			cert: &x509.Certificate{
				IPAddresses: []net.IP{
					net.ParseIP("::1"),
				},
				Subject: pkix.Name{
					CommonName: "localhost",
				},
			},
			wantIdentity: "::1",
			wantSource:   "san-ip",
			description:  "IPv6 localhost should be handled correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use reflection to call the unexported function
			// In a real test, we'd either export it or test through the interceptor
			identity, source := extractClientIdentity(tt.cert)

			assert.Equal(t, tt.wantIdentity, identity,
				"Identity mismatch: %s", tt.description)
			assert.Equal(t, tt.wantSource, source,
				"Source mismatch: %s", tt.description)
		})
	}
}

func TestExtractCertificateSANs(t *testing.T) {
	tests := []struct {
		name     string
		cert     *x509.Certificate
		wantSANs *CertificateSANs
	}{
		{
			name: "All SAN types populated",
			cert: &x509.Certificate{
				DNSNames: []string{
					"dns1.example.com",
					"dns2.example.com",
				},
				IPAddresses: []net.IP{
					net.ParseIP("192.168.1.1"),
					net.ParseIP("2001:db8::1"),
				},
				EmailAddresses: []string{
					"email1@example.com",
					"email2@example.com",
				},
			},
			wantSANs: &CertificateSANs{
				DNSNames: []string{
					"dns1.example.com",
					"dns2.example.com",
				},
				IPAddresses: []string{
					"192.168.1.1",
					"2001:db8::1",
				},
				EmailAddresses: []string{
					"email1@example.com",
					"email2@example.com",
				},
			},
		},
		{
			name: "Empty certificate",
			cert: &x509.Certificate{},
			wantSANs: &CertificateSANs{
				DNSNames:       []string{},
				IPAddresses:    []string{},
				EmailAddresses: []string{},
			},
		},
		{
			name: "Only DNS names",
			cert: &x509.Certificate{
				DNSNames: []string{"example.com"},
			},
			wantSANs: &CertificateSANs{
				DNSNames:       []string{"example.com"},
				IPAddresses:    []string{},
				EmailAddresses: []string{},
			},
		},
		{
			name: "Many SANs",
			cert: &x509.Certificate{
				DNSNames: []string{
					"host1.example.com",
					"host2.example.com",
					"host3.example.com",
					"host4.example.com",
					"host5.example.com",
				},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("10.0.0.2"),
					net.ParseIP("10.0.0.3"),
				},
				EmailAddresses: []string{
					"admin@example.com",
				},
			},
			wantSANs: &CertificateSANs{
				DNSNames: []string{
					"host1.example.com",
					"host2.example.com",
					"host3.example.com",
					"host4.example.com",
					"host5.example.com",
				},
				IPAddresses: []string{
					"10.0.0.1",
					"10.0.0.2",
					"10.0.0.3",
				},
				EmailAddresses: []string{
					"admin@example.com",
				},
			},
		},
		{
			name: "Unusual but valid SAN values",
			cert: &x509.Certificate{
				DNSNames: []string{
					"localhost",
					"my-server.internal",
				},
				IPAddresses: []net.IP{
					net.ParseIP("127.0.0.1"),
					net.ParseIP("::1"),
					net.ParseIP("192.168.1.1"),
				},
				EmailAddresses: []string{
					"root@localhost",
					"user@192.168.1.100",
					"service@company.internal",
				},
			},
			wantSANs: &CertificateSANs{
				DNSNames: []string{
					"localhost",
					"my-server.internal",
				},
				IPAddresses: []string{
					"127.0.0.1",
					"::1",
					"192.168.1.1",
				},
				EmailAddresses: []string{
					"root@localhost",
					"user@192.168.1.100",
					"service@company.internal",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sans := extractCertificateSANs(tt.cert)

			require.NotNil(t, sans)
			assert.Equal(t, tt.wantSANs.DNSNames, sans.DNSNames, "DNS names mismatch")
			assert.Equal(t, tt.wantSANs.IPAddresses, sans.IPAddresses, "IP addresses mismatch")
			assert.Equal(t, tt.wantSANs.EmailAddresses, sans.EmailAddresses, "Email addresses mismatch")
		})
	}
}
