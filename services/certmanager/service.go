// Copyright © 2025 Attestant Limited.
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

package certmanager

import "crypto/tls"

// Service is the tls certificate manager service.
type Service interface {
	// Gets the certificate, reloading it if configured to do so
	// and necessary.
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}
