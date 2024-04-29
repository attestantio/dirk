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

package lister

import (
	context "context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/attestantio/dirk/core"
	"github.com/attestantio/dirk/services/api/grpc/handlers"
	pb "github.com/wealdtech/eth2-signer-api/pb/v1"
	e2wtypes "github.com/wealdtech/go-eth2-wallet-types/v2"
)

// ListAccounts lists accounts.
func (h *Handler) ListAccounts(ctx context.Context, req *pb.ListAccountsRequest) (*pb.ListAccountsResponse, error) {
	if req == nil {
		log.Warn().Str("result", "denied").Msg("Request not specified")
		return nil, errors.New("no request specified")
	}

	log.Trace().Strs("paths", req.GetPaths()).Msg("List accounts request received")
	res := &pb.ListAccountsResponse{}
	res.Accounts = make([]*pb.Account, 0)
	res.DistributedAccounts = make([]*pb.DistributedAccount, 0)

	result, accounts := h.lister.ListAccounts(ctx, handlers.GenerateCredentials(ctx), req.GetPaths())
	switch result {
	case core.ResultDenied:
		res.State = pb.ResponseState_DENIED
		return res, nil
	case core.ResultUnknown, core.ResultFailed:
		res.State = pb.ResponseState_FAILED
		return res, nil
	case core.ResultSucceeded:
		for _, account := range accounts {
			uuid, err := account.ID().MarshalBinary()
			if err != nil {
				log.Error().Str("uuid", account.ID().String()).Err(err).Msg("Failed to marshal UUID")
				continue
			}
			var name string
			if walletProvider, isWalletProvider := account.(e2wtypes.AccountWalletProvider); isWalletProvider {
				name = fmt.Sprintf("%s/%s", walletProvider.Wallet().Name(), account.Name())
			} else {
				name = account.Name()
			}
			pubKeyProvider, isProvider := account.(e2wtypes.AccountPublicKeyProvider)
			if !isProvider {
				log.Error().Msg("Account does not provide public keys")
				continue
			}
			if distributedAccount, isDistributedAccount := account.(e2wtypes.DistributedAccount); isDistributedAccount {
				pbAccount := &pb.DistributedAccount{
					Uuid:               uuid,
					Name:               name,
					PublicKey:          pubKeyProvider.PublicKey().Marshal(),
					CompositePublicKey: distributedAccount.CompositePublicKey().Marshal(),
				}
				pbAccount.Uuid = uuid
				pbAccount.SigningThreshold = distributedAccount.SigningThreshold()
				pbAccount.Participants = make([]*pb.Endpoint, 0)
				for k, v := range distributedAccount.Participants() {
					parts := strings.Split(v, ":")
					if len(parts) != 2 {
						log.Warn().Str("participant", v).Msg("Invalid format for participant")
						continue
					}
					port, err := strconv.ParseUint(parts[1], 10, 32)
					if err != nil {
						log.Warn().Str("participant", v).Err(err).Msg("Invalid port for participant")
						continue
					}
					pbAccount.Participants = append(pbAccount.GetParticipants(), &pb.Endpoint{
						Id:   k,
						Name: parts[0],
						Port: uint32(port),
					})
				}
				res.DistributedAccounts = append(res.GetDistributedAccounts(), pbAccount)
			} else {
				pbAccount := &pb.Account{
					Uuid:      uuid,
					Name:      name,
					PublicKey: pubKeyProvider.PublicKey().Marshal(),
				}
				res.Accounts = append(res.GetAccounts(), pbAccount)
			}
		}
	}

	res.State = pb.ResponseState_SUCCEEDED
	log.Trace().Int("accounts", len(res.GetAccounts())).Int("distributedAccounts", len(res.GetDistributedAccounts())).Msg("Success")

	return res, nil
}
