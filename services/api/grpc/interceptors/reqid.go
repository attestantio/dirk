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
	"context"
	"fmt"
	"math/rand"
	"time"

	"google.golang.org/grpc"
)

// RequestID is a context tag for the request ID.
type RequestID struct{}

// RequestIDInterceptor adds a request ID to incoming requests.
func RequestIDInterceptor() grpc.UnaryServerInterceptor {
	rand.Seed(time.Now().UnixNano())
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// #nosec G404
		newCtx := context.WithValue(ctx, &RequestID{}, fmt.Sprintf("%02x", rand.Int31()))
		return handler(newCtx, req)
	}
}
