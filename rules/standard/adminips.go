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

package standard

import (
	"net"
	"strings"

	"github.com/rs/zerolog"
)

// parseAdminIPs turns the configured admin IP entries in to IP networks that can be
// checked against an incoming request IP address.  Each entry may be a single IP
// address, e.g. "1.2.3.4", or a CIDR range, e.g. "10.0.0.0/8"; a single IP address is
// treated as a CIDR range covering that address alone.
//
// Invalid entries are logged and skipped rather than treated as a fatal error: a
// misconfigured entry only narrows the set of addresses trusted for voluntary exits,
// never widens it, so it is not worth failing Dirk's startup over.
func parseAdminIPs(entries []string, log zerolog.Logger) []*net.IPNet {
	ipNets := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			ip, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				log.Warn().Str("entry", entry).Err(err).Msg("Invalid admin IP CIDR range; ignoring entry")

				continue
			}
			if !ip.Equal(ipNet.IP) {
				// The entry has non-zero host bits, e.g. "10.1.2.3/24" rather than
				// "10.1.2.0/24".  Treat this as a misconfiguration rather than silently
				// widening the range to the whole network the operator may not have intended.
				log.Warn().Str("entry", entry).Str("network", ipNet.String()).
					Msg("Admin IP CIDR range has non-zero host bits; ignoring entry")

				continue
			}
			ipNets = append(ipNets, ipNet)

			continue
		}

		ip := net.ParseIP(entry)
		if ip == nil {
			log.Warn().Str("entry", entry).Msg("Invalid admin IP address; ignoring entry")

			continue
		}
		if ip4 := ip.To4(); ip4 != nil {
			ipNets = append(ipNets, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
		} else {
			ipNets = append(ipNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
		}
	}

	return ipNets
}

// adminIPAllowed returns true if the given request IP address falls within any of the
// configured admin IP networks.
func adminIPAllowed(adminIPNets []*net.IPNet, requestIP string) bool {
	ip := net.ParseIP(requestIP)
	if ip == nil {
		return false
	}

	for _, ipNet := range adminIPNets {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}
