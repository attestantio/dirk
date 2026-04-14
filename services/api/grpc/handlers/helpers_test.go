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

package handlers_test

import (
	"context"
	"testing"

	"github.com/attestantio/dirk/services/api/grpc/handlers"
	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	"github.com/attestantio/dirk/services/checker"
	"github.com/attestantio/go-certmanager/san"
	"github.com/stretchr/testify/assert"
)

func TestGenerateCredentials(t *testing.T) {
	tests := []struct {
		name     string
		setupCtx func() context.Context
		expected *checker.Credentials
	}{
		{
			name:     "EmptyContext",
			setupCtx: func() context.Context { return context.Background() },
			expected: &checker.Credentials{},
		},
		{
			name: "RequestIDOnly",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), &interceptors.RequestID{}, "test-request-123")
			},
			expected: &checker.Credentials{
				RequestID: "test-request-123",
			},
		},
		{
			name: "ClientNameOnly",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), &interceptors.ClientName{}, "test-client")
			},
			expected: &checker.Credentials{
				Client: "test-client",
			},
		},
		{
			name: "ClientIdentitySourceOnly",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), &interceptors.ClientIdentitySource{}, san.IdentitySourceSANDNS)
			},
			expected: &checker.Credentials{
				ClientIdentitySource: san.IdentitySourceSANDNS,
			},
		},
		{
			name: "ClientCertificateSANsOnly",
			setupCtx: func() context.Context {
				sans := &san.CertificateSANs{
					DNSNames: []string{"example.com", "backup.example.com"},
				}
				return context.WithValue(context.Background(), &interceptors.ClientCertificateSANs{}, sans)
			},
			expected: &checker.Credentials{
				ClientCertificateSANs: &san.CertificateSANs{
					DNSNames: []string{"example.com", "backup.example.com"},
				},
			},
		},
		{
			name: "ExternalIPOnly",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), &interceptors.ExternalIP{}, "10.0.0.1")
			},
			expected: &checker.Credentials{
				IP: "10.0.0.1",
			},
		},
		{
			name: "AllFields",
			setupCtx: func() context.Context {
				ctx := context.Background()
				ctx = context.WithValue(ctx, &interceptors.RequestID{}, "req-456")
				ctx = context.WithValue(ctx, &interceptors.ClientName{}, "validator.example.com")
				ctx = context.WithValue(ctx, &interceptors.ClientIdentitySource{}, san.IdentitySourceSANDNS)
				ctx = context.WithValue(ctx, &interceptors.ClientCertificateSANs{}, &san.CertificateSANs{
					DNSNames: []string{"validator.example.com"},
				})
				ctx = context.WithValue(ctx, &interceptors.ExternalIP{}, "203.0.113.1")
				return ctx
			},
			expected: &checker.Credentials{
				RequestID:            "req-456",
				Client:               "validator.example.com",
				ClientIdentitySource: san.IdentitySourceSANDNS,
				ClientCertificateSANs: &san.CertificateSANs{
					DNSNames: []string{"validator.example.com"},
				},
				IP: "203.0.113.1",
			},
		},
		{
			name: "PartialSANs",
			setupCtx: func() context.Context {
				sans := &san.CertificateSANs{
					DNSNames: []string{"dns.example.com"},
				}
				return context.WithValue(context.Background(), &interceptors.ClientCertificateSANs{}, sans)
			},
			expected: &checker.Credentials{
				ClientCertificateSANs: &san.CertificateSANs{
					DNSNames: []string{"dns.example.com"},
				},
			},
		},
		{
			name: "NilSANs",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), &interceptors.ClientCertificateSANs{}, (*san.CertificateSANs)(nil))
			},
			expected: &checker.Credentials{},
		},
		{
			name: "WrongTypeSANs",
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), &interceptors.ClientCertificateSANs{}, "not-a-sans-struct")
			},
			expected: &checker.Credentials{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := test.setupCtx()
			result := handlers.GenerateCredentials(ctx)

			// Use assert.Equal for deep comparison of structs
			assert.Equal(t, test.expected, result)
		})
	}
}

// TestGenerateCredentials_TypeSafety tests that the function handles type mismatches gracefully
func TestGenerateCredentials_TypeSafety(t *testing.T) {
	// Test with wrong types in context - these should be ignored
	ctx := context.Background()
	ctx = context.WithValue(ctx, &interceptors.RequestID{}, 12345)                    // int instead of string
	ctx = context.WithValue(ctx, &interceptors.ClientName{}, []byte("bytes"))         // []byte instead of string
	ctx = context.WithValue(ctx, &interceptors.ClientIdentitySource{}, "not-an-enum") // string instead of IdentitySource
	ctx = context.WithValue(ctx, &interceptors.ClientCertificateSANs{}, "not-sans")   // string instead of *CertificateSANs
	ctx = context.WithValue(ctx, &interceptors.ExternalIP{}, 67890)                   // int instead of string

	result := handlers.GenerateCredentials(ctx)

	// Should return empty credentials when types don't match
	expected := &checker.Credentials{}
	assert.Equal(t, expected, result)
}

func TestGenerateCredentials_CheckerCompatibility(t *testing.T) {
	// This test verifies that GenerateCredentials produces credentials that are
	// fully compatible with the checker service interface and type expectations.
	ctx := context.Background()

	// Set up context with certificate information (using DNS as identity source)
	ctx = context.WithValue(ctx, &interceptors.ClientName{}, "validator.example.com")
	ctx = context.WithValue(ctx, &interceptors.ClientIdentitySource{}, san.IdentitySourceSANDNS)
	ctx = context.WithValue(ctx, &interceptors.ClientCertificateSANs{}, &san.CertificateSANs{
		DNSNames: []string{"validator.example.com"},
	})

	credentials := handlers.GenerateCredentials(ctx)

	// Verify the credentials struct has all expected fields and types
	assert.Equal(t, "validator.example.com", credentials.Client)
	assert.Equal(t, san.IdentitySourceSANDNS, credentials.ClientIdentitySource)
	assert.NotNil(t, credentials.ClientCertificateSANs)
	assert.Equal(t, []string{"validator.example.com"}, credentials.ClientCertificateSANs.DNSNames)

	// Verify this works with checker.Credentials type expectations
	// The credentials should be usable by the checker service without type errors
	var checkerCreds *checker.Credentials = credentials
	assert.NotNil(t, checkerCreds)
	assert.Equal(t, "validator.example.com", checkerCreds.Client)
}
