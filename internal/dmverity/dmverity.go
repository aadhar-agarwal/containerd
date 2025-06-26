/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

// Package dmverity provides functions for working with dm-verity for integrity verification
package dmverity

import (
	"bufio"
	"strconv"
	"strings"
)

// VeritySetupCommand represents the type of veritysetup command to execute
type VeritySetupCommand string

const (
	// FormatCommand corresponds to "veritysetup format"
	FormatCommand VeritySetupCommand = "format"
	// OpenCommand corresponds to "veritysetup open"
	OpenCommand VeritySetupCommand = "open"
	// CloseCommand corresponds to "veritysetup close"
	CloseCommand VeritySetupCommand = "close"
	// StatusCommand corresponds to "veritysetup status"
	StatusCommand VeritySetupCommand = "status"
)

// DmverityOptions contains configuration options for dm-verity operations
type DmverityOptions struct {
	// Salt for hashing, represented as a hex string
	Salt string
	// Hash algorithm to use (default: sha256)
	HashAlgorithm string
	// Size of data blocks in bytes (default: 4096)
	DataBlockSize uint64
	// Size of hash blocks in bytes (default: 4096)
	HashBlockSize uint64
	// Number of data blocks
	DataBlocks uint64
	// Offset of hash area in bytes
	HashOffset uint64
	// Hash type (default: 1)
	HashType uint64
	// Superblock usage flag (false meaning --no-superblock)
	UseSuperblock bool
	// Debug flag
	Debug bool
	// UUID for device to use
	UUID string
}

// DefaultDmverityOptions returns a DmverityOptions struct with default values
func DefaultDmverityOptions() DmverityOptions {
	return DmverityOptions{
		HashAlgorithm: "sha256",
		DataBlockSize: 512,
		HashBlockSize: 512,
		HashType:      1,
		UseSuperblock: true,
		Salt:          "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

// FormatOutputInfo represents the parsed information from veritysetup format command output
type FormatOutputInfo struct {
	// Basic dm-verity options, reused from DmverityOptions
	DmverityOptions
	// Number of hash blocks in the hash area
	HashBlocks int64
	// Root hash value for verification
	RootHash string
}

// ParseFormatOutput parses the output from veritysetup format command
// and returns a structured representation of the information
func ParseFormatOutput(output string) (*FormatOutputInfo, error) {
	info := &FormatOutputInfo{}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		// Skip the header line and command echo line
		if strings.HasPrefix(line, "VERITY header") || strings.HasPrefix(line, "# veritysetup") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "UUID":
			info.UUID = value
		case "Hash type":
			hashType, err := strconv.Atoi(value)
			if err == nil {
				info.HashType = uint64(hashType)
			}
		case "Data blocks":
			dataBlocks, err := strconv.ParseInt(value, 10, 64)
			if err == nil {
				info.DataBlocks = uint64(dataBlocks)
			}
		case "Data block size":
			dataBlockSize, err := strconv.ParseInt(value, 10, 64)
			if err == nil {
				info.DataBlockSize = uint64(dataBlockSize)
			}
		case "Hash blocks":
			hashBlocks, err := strconv.ParseInt(value, 10, 64)
			if err == nil {
				info.HashBlocks = hashBlocks
			}
		case "Hash block size":
			hashBlockSize, err := strconv.ParseInt(value, 10, 64)
			if err == nil {
				info.HashBlockSize = uint64(hashBlockSize)
			}
		case "Hash algorithm":
			info.HashAlgorithm = value
		case "Salt":
			info.Salt = value
		case "Root hash":
			info.RootHash = value
		}
	}

	return info, scanner.Err()
}

// StatusInfo represents the parsed information from veritysetup status command output
type StatusInfo struct {
	// Device path
	Device string
	// Whether the device is active
	IsActive bool
	// Whether the device is in use
	InUse bool
	// Type of the device (e.g., "VERITY")
	Type string
	// Status of verification (e.g., "verified")
	Status string
}

// ParseStatusOutput parses the output from veritysetup status command
// and returns a structured representation of the information
func ParseStatusOutput(output string) (*StatusInfo, error) {
	info := &StatusInfo{}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and command echo lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse the first line: "/dev/mapper/containerd-erofs-1 is active and is in use."
		if strings.Contains(line, " is ") {
			info.Device = strings.Fields(line)[0]
			info.IsActive = strings.Contains(line, "active")
			info.InUse = strings.Contains(line, "in use")
			continue
		}

		// Parse key-value pairs
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "type":
			info.Type = value
		case "status":
			info.Status = value
		}
	}

	return info, scanner.Err()
}

// IsVerified checks if the dm-verity device status is "verified"
func (s *StatusInfo) IsVerified() bool {
	return s.Status == "verified"
}

func (s *StatusInfo) IsInUse() bool {
	return s.IsActive && s.InUse
}
