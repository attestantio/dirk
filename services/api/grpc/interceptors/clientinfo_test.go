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

package interceptors_test

import (
	"context"
	"testing"

	"github.com/attestantio/dirk/services/api/grpc/interceptors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// nonTLSAuthInfo is a credentials.AuthInfo that is not credentials.TLSInfo,
// used to confirm the interceptor handles unexpected concrete types without
// panicking.
type nonTLSAuthInfo struct{}

func (nonTLSAuthInfo) AuthType() string { return "non-tls" }

func TestClientInfoInterceptor_NonTLSAuthInfo_ReturnsUnauthenticated(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: nonTLSAuthInfo{}})

	called := false
	handler := func(context.Context, any) (any, error) {
		called = true
		return nil, nil //nolint:nilnil // handler shape required by grpc
	}

	interceptor := interceptors.ClientInfoInterceptor()
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected gRPC status error")
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.False(t, called, "handler must not be invoked when auth info is unusable")
}

func TestClientInfoInterceptor_NilAuthInfo_ReturnsUnauthenticated(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: nil})

	handler := func(context.Context, any) (any, error) { return nil, nil } //nolint:nilnil

	interceptor := interceptors.ClientInfoInterceptor()
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}
