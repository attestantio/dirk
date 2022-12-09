// Copyright © 2020, 2022 Attestant Limited.
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

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/attestantio/dirk/rules"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// SlashingProtection is the top-level structure for slashing protection data.
type SlashingProtection struct {
	Metadata *SlashingProtectionMetadata `json:"metadata"`
	Data     []*SlashingProtectionData   `json:"data"`
}

// SlashingProtectionMetadata is the structure for slashing protection metadata.
type SlashingProtectionMetadata struct {
	InterchangeFormatVersion string `json:"interchange_format_version"`
	GenesisValidatorsRoot    string `json:"genesis_validators_root"`
}

// SlashingProtectionData is the struture for slashing protection data.
type SlashingProtectionData struct {
	PublicKey          string                           `json:"pubkey"`
	SignedBlocks       []*SlashingProtectionProposal    `json:"signed_blocks,omitempty"`
	SignedAttestations []*SlashingProtectionAttestation `json:"signed_attestations,omitempty"`
}

// SlashingProtectionProposal is the structure for slashing protection proposal information.
type SlashingProtectionProposal struct {
	Slot string `json:"slot"`
}

// SlashingProtectionAttestation is the structure for slashing protection attestation information.
type SlashingProtectionAttestation struct {
	SourceEpoch string `json:"source_epoch"`
	TargetEpoch string `json:"target_epoch"`
}

// exportSlashingProtection is a command to export the slashing protection database.
func exportSlashingProtection(ctx context.Context) int {
	protection, err := fetchSlashingProtection(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to obtain slashing protection information: %v\n", err)
		return 1
	}

	data, err := json.Marshal(protection)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate output: %v\n", err)
		return 1
	}

	if viper.GetString("slashing-protection-file") != "" {
		if err := os.WriteFile(viper.GetString("slashing-protection-file"), data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write output: %v\n", err)
			return 1
		}
	} else {
		fmt.Println(string(data))
	}
	return 0
}

// fetchSlashingProtection obtains the slashing protection database.
func fetchSlashingProtection(ctx context.Context) (*SlashingProtection, error) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	if viper.GetString("genesis-validators-root") == "" {
		return nil, errors.New("genesis-validators-root is required for export")
	}
	// Confirm that the genesis validators root is of the appropriate format.
	genesisValidatorsRoot, err := hex.DecodeString(strings.TrimPrefix(viper.GetString("genesis-validators-root"), "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "genesis-validators-root is invalid")
	}
	if len(genesisValidatorsRoot) != 32 {
		return nil, errors.New("genesis-validators-root must be 32 bytes")
	}

	rules, err := initRules(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to set up rules")
	}
	protection, err := rules.ExportSlashingProtection(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to obtain slashing protection")
	}
	res := &SlashingProtection{
		Metadata: &SlashingProtectionMetadata{
			InterchangeFormatVersion: "5",
			GenesisValidatorsRoot:    fmt.Sprintf("%#x", genesisValidatorsRoot),
		},
		Data: make([]*SlashingProtectionData, 0),
	}
	for _, v := range protection {
		data := &SlashingProtectionData{
			PublicKey: fmt.Sprintf("%#x", v.PubKey),
		}
		if v.HighestProposedSlot != -1 {
			data.SignedBlocks = []*SlashingProtectionProposal{
				{
					Slot: fmt.Sprintf("%d", v.HighestProposedSlot),
				},
			}
		}
		if v.HighestAttestedSourceEpoch != -1 {
			data.SignedAttestations = []*SlashingProtectionAttestation{
				{
					SourceEpoch: fmt.Sprintf("%d", v.HighestAttestedSourceEpoch),
					TargetEpoch: fmt.Sprintf("%d", v.HighestAttestedTargetEpoch),
				},
			}
		}
		res.Data = append(res.Data, data)
	}

	return res, nil
}

// importSlashingProtection is a command to import a slashing protection database.
func importSlashingProtection(ctx context.Context) int {
	if viper.GetString("slashing-protection-file") == "" {
		fmt.Fprintf(os.Stderr, "Slashing protection file required for import\n")
		return 1
	}
	data, err := os.ReadFile(viper.GetString("slashing-protection-file"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read slashing protection file: %v\n", err)
		return 1
	}

	var protection SlashingProtection
	if err := json.Unmarshal(data, &protection); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse slashing protection file: %v\n", err)
		return 1
	}
	if err := storeSlashingProtection(ctx, &protection); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to store slashing protection: %v\n", err)
		return 1
	}

	return 0
}

// storeSlashingProtection updates the slashing protection database.
func storeSlashingProtection(ctx context.Context, protection *SlashingProtection) error {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	// Confirm format and metadata.
	if protection == nil {
		return errors.New("slashing protection missing")
	}
	if protection.Metadata == nil {
		return errors.New("no metadata in file")
	}
	if protection.Metadata.InterchangeFormatVersion != "5" {
		return fmt.Errorf("interchange format incorrect; expected 5, found %s", protection.Metadata.InterchangeFormatVersion)
	}
	if viper.GetString("genesis-validators-root") == "" {
		return errors.New("genesis-validators-root is required for import")
	}
	genesisValidatorsRoot, err := hex.DecodeString(strings.TrimPrefix(viper.GetString("genesis-validators-root"), "0x"))
	if err != nil {
		return errors.Wrap(err, "genesis-validators-root is invalid")
	}
	if len(genesisValidatorsRoot) != 32 {
		return errors.New("genesis-validators-root must be 32 bytes")
	}
	if viper.GetString("genesis-validators-root") != protection.Metadata.GenesisValidatorsRoot {
		return fmt.Errorf("genesis validators root incorrect; expected %s, found %s", viper.GetString("genesis-validators-root"), protection.Metadata.GenesisValidatorsRoot)
	}

	rulesSvc, err := initRules(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to set up rules")
	}

	existingProtection, err := rulesSvc.ExportSlashingProtection(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to obtain existing protection")
	}

	protectionMap := make(map[[48]byte]*rules.SlashingProtection)
	for i := range protection.Data {
		bytes, err := hex.DecodeString(strings.TrimPrefix(protection.Data[i].PublicKey, "0x"))
		if err != nil {
			return errors.Wrap(err, "failed to decode public key")
		}
		var key [48]byte
		copy(key[:], bytes)
		keyProtection := &rules.SlashingProtection{
			HighestAttestedSourceEpoch: -1,
			HighestAttestedTargetEpoch: -1,
			HighestProposedSlot:        -1,
		}
		// We take the absolute highest source epoch and target epoch across all provided attestations.
		for _, attestation := range protection.Data[i].SignedAttestations {
			sourceEpoch, err := strconv.ParseInt(attestation.SourceEpoch, 10, 64)
			if err != nil {
				return errors.Wrap(err, "invalid attestation source epoch")
			}
			if sourceEpoch > keyProtection.HighestAttestedSourceEpoch {
				keyProtection.HighestAttestedSourceEpoch = sourceEpoch
			}
			targetEpoch, err := strconv.ParseInt(attestation.TargetEpoch, 10, 64)
			if err != nil {
				return errors.Wrap(err, "invalid attestation target epoch")
			}
			if targetEpoch > keyProtection.HighestAttestedTargetEpoch {
				keyProtection.HighestAttestedTargetEpoch = targetEpoch
			}
		}
		// We take the absolute highest slot across all provided proposals.
		for _, proposal := range protection.Data[i].SignedBlocks {
			slot, err := strconv.ParseInt(proposal.Slot, 10, 64)
			if err != nil {
				return errors.Wrap(err, "invalid proposal slot")
			}
			if slot > keyProtection.HighestProposedSlot {
				keyProtection.HighestProposedSlot = slot
			}
		}

		existingKeyProtection, exists := existingProtection[key]
		if exists {
			// We already have an entry; only add this if it contains newer data.
			if existingKeyProtection.HighestAttestedSourceEpoch <= keyProtection.HighestAttestedSourceEpoch &&
				existingKeyProtection.HighestAttestedTargetEpoch <= keyProtection.HighestAttestedTargetEpoch &&
				existingKeyProtection.HighestProposedSlot <= keyProtection.HighestProposedSlot {
				protectionMap[key] = keyProtection
			} else {
				fmt.Printf("Existing entry for public key %#x contains newer data; not importing\n", key)
			}
		} else {
			protectionMap[key] = keyProtection
		}
	}
	if err := rulesSvc.ImportSlashingProtection(ctx, protectionMap); err != nil {
		return errors.Wrap(err, "failed to obtain slashing protection")
	}

	return nil
}
