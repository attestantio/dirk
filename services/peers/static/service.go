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

package static

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/attestantio/dirk/core"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	zerologger "github.com/rs/zerolog/log"
)

// ErrNotFound is returned when a peer is not found.
var ErrNotFound = errors.New("not found")

// Service provides a static list of peers.
type Service struct {
	peers map[uint64]*core.Endpoint
}

// module-wide log.
var log zerolog.Logger

// New creates a new peers provider.
func New(_ context.Context, params ...Parameter) (*Service, error) {
	parameters, err := parseAndCheckParameters(params...)
	if err != nil {
		return nil, errors.Wrap(err, "problem with parameters")
	}

	// Set logging.
	log = zerologger.With().Str("service", "peers").Str("impl", "static").Logger()
	if parameters.logLevel != log.GetLevel() {
		log = log.Level(parameters.logLevel)
	}

	peerNames := make(map[string]bool)
	servicePeers := make(map[uint64]*core.Endpoint, len(parameters.peers))
	if parameters.peers != nil {
		for id, v := range parameters.peers {
			peerInfo := strings.Split(v, ":")
			if len(peerInfo) != 2 {
				return nil, fmt.Errorf("malformed peer %s", v)
			}
			if _, exists := peerNames[peerInfo[0]]; exists {
				return nil, fmt.Errorf("duplicate peer name %s", peerInfo[0])
			}
			peerNames[peerInfo[0]] = true
			port, err := strconv.ParseUint(peerInfo[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("malformed peer port for %s", v)
			}
			if port == 0 {
				return nil, fmt.Errorf("invalid peer port for %s", v)
			}
			servicePeers[id] = &core.Endpoint{
				ID:   id,
				Name: peerInfo[0],
				Port: uint32(port),
			}
		}
	}

	s := &Service{
		peers: servicePeers,
	}

	return s, nil
}

// Peer returns the peer with the given ID.
func (s *Service) Peer(id uint64) (*core.Endpoint, error) {
	peer, exists := s.peers[id]
	if !exists {
		return nil, ErrNotFound
	}

	return &core.Endpoint{
		ID:   peer.ID,
		Name: peer.Name,
		Port: peer.Port,
	}, nil
}

// All returns all peers.
func (s *Service) All() map[uint64]*core.Endpoint {
	res := make(map[uint64]*core.Endpoint, len(s.peers))
	for id, peer := range s.peers {
		res[id] = &core.Endpoint{
			ID:   peer.ID,
			Name: peer.Name,
			Port: peer.Port,
		}
	}

	return res
}

// Suitable returns peers that are suitable given the supplied requirements.
// At current any peer that is present is considered suitable.
func (s *Service) Suitable(threshold uint32) ([]*core.Endpoint, error) {
	suitable := uint32(0)
	res := make([]*core.Endpoint, threshold)
	for _, peer := range s.peers {
		res[suitable] = &core.Endpoint{
			ID:   peer.ID,
			Name: peer.Name,
			Port: peer.Port,
		}
		suitable++
		if suitable == threshold {
			break
		}
	}
	if suitable < threshold {
		return nil, errors.New("not enough suitable peers")
	}

	return res, nil
}
