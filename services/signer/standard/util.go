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

package standard

import (
	context "context"
	"errors"

	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// generateSigningRoot generates a signing root from a data root and domain.
func generateSigningRoot(_ context.Context, root []byte, domain []byte) ([32]byte, error) {
	signingData := &SigningRoot{
		DataRoot: root,
		Domain:   domain,
	}
	return signingData.HashTreeRoot()
}

func signRoot(ctx context.Context, account e2wtypes.Account, root []byte) ([]byte, error) {
	signer, isSigner := account.(e2wtypes.AccountSigner)
	if !isSigner {
		return nil, errors.New("not a signer")
	}
	signature, err := signer.Sign(ctx, root)
	if err != nil {
		return nil, err
	}
	return signature.Marshal(), nil
}
