package analyzers

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

func init() { module.Register(&secureSDSParser{}) }

type secureSDSParser struct{}

func (c *secureSDSParser) Name() string     { return "secure_sds_parser" }
func (c *secureSDSParser) Category() string { return "ntfs" }
func (c *secureSDSParser) Mode() string     { return module.ModeAnalyzer }
func (c *secureSDSParser) Description() string {
	return "Parse Secure SDS"
}

func (c *secureSDSParser) Collect(ctx context.Context, outputDir string) ([]module.FileInfo, error) {
	outDir := module.ModuleDir(outputDir, c)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("create secure_sds parser output dir: %w", err)
	}

	data, _, err := readSecureSDSSource(ctx, outputDir)
	if err != nil {
		return nil, err
	}

	rows, parsedCount, skippedCount, err := parseSecureSDSRows(data)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no SDS entries parsed")
	}

	entriesCSV := filepath.Join(outDir, "secure_sds_entries.csv")
	if err := writeCSVFile(entriesCSV, []string{
		"StreamOffset",
		"HeaderOffsetValue",
		"EntryLength",
		"SecurityId",
		"Hash",
		"DescriptorBytes",
		"ControlFlags",
		"OwnerSID",
		"GroupSID",
		"DACLPresent",
		"DACLSize",
		"DACLEntryCount",
		"SACLPresent",
		"SACLSize",
		"SACLEntryCount",
	}, rows); err != nil {
		return nil, err
	}

	entriesInfo, err := utils.FileInfoFromPath(entriesCSV)
	if err != nil {
		return nil, err
	}
	_ = parsedCount
	_ = skippedCount
	return []module.FileInfo{entriesInfo}, nil
}

func readSecureSDSSource(ctx context.Context, outputDir string) ([]byte, string, error) {
	if dir, ok := existingModuleDir(outputDir, "secure_sds"); ok {
		path := filepath.Join(dir, "$Secure_SDS")
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, "", fmt.Errorf("read collected $Secure:$SDS: %w", err)
			}
			return data, path, nil
		}
	}

	vol, err := acquisition.OpenRawVolume("C")
	if err != nil {
		return nil, "", fmt.Errorf("open raw volume for live SDS parse: %w", err)
	}
	defer vol.Close()

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		return nil, "", fmt.Errorf("get NTFS volume data for live SDS parse: %w", err)
	}

	data, err := acquisition.ReadNamedDataStreamFromMFTRecord(vol, volData, 9, "$SDS")
	if err != nil {
		return nil, "", fmt.Errorf("read live $Secure:$SDS: %w", err)
	}
	return data, `\\.\C: ($Secure:$SDS live parse)`, nil
}

func parseSecureSDSRows(data []byte) ([][]string, int, int, error) {
	rows := make([][]string, 0, 1024)
	offset := 0
	parsedCount := 0
	skippedCount := 0

	for offset+20 <= len(data) {
		chunkEnd := offset + 16
		if chunkEnd > len(data) {
			chunkEnd = len(data)
		}
		if allZero(data[offset:chunkEnd]) {
			offset += 16
			continue
		}

		hash := binary.LittleEndian.Uint32(data[offset : offset+4])
		securityID := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		headerOffset := binary.LittleEndian.Uint64(data[offset+8 : offset+16])
		entryLength := int(binary.LittleEndian.Uint32(data[offset+16 : offset+20]))

		if entryLength < 20 || offset+entryLength > len(data) {
			skippedCount++
			offset += 16
			continue
		}

		descriptor := data[offset+20 : offset+entryLength]
		info, ok := parseSecurityDescriptorInfo(descriptor)
		if !ok {
			skippedCount++
			offset += align16(entryLength)
			continue
		}

		rows = append(rows, []string{
			fmt.Sprintf("%d", offset),
			fmt.Sprintf("%d", headerOffset),
			fmt.Sprintf("%d", entryLength),
			fmt.Sprintf("%d", securityID),
			fmt.Sprintf("0x%08X", hash),
			fmt.Sprintf("%d", len(descriptor)),
			info.controlFlags,
			info.ownerSID,
			info.groupSID,
			fmt.Sprintf("%t", info.daclPresent),
			fmt.Sprintf("%d", info.daclSize),
			fmt.Sprintf("%d", info.daclAceCount),
			fmt.Sprintf("%t", info.saclPresent),
			fmt.Sprintf("%d", info.saclSize),
			fmt.Sprintf("%d", info.saclAceCount),
		})
		parsedCount++
		offset += align16(entryLength)
	}

	return rows, parsedCount, skippedCount, nil
}

type securityDescriptorInfo struct {
	controlFlags string
	ownerSID     string
	groupSID     string
	daclPresent  bool
	daclSize     int
	daclAceCount int
	saclPresent  bool
	saclSize     int
	saclAceCount int
}

func parseSecurityDescriptorInfo(data []byte) (securityDescriptorInfo, bool) {
	if len(data) < 20 {
		return securityDescriptorInfo{}, false
	}

	control := binary.LittleEndian.Uint16(data[2:4])
	ownerOff := binary.LittleEndian.Uint32(data[4:8])
	groupOff := binary.LittleEndian.Uint32(data[8:12])
	saclOff := binary.LittleEndian.Uint32(data[12:16])
	daclOff := binary.LittleEndian.Uint32(data[16:20])

	info := securityDescriptorInfo{
		controlFlags: securityDescriptorControlString(control),
		ownerSID:     sidFromOffset(data, ownerOff),
		groupSID:     sidFromOffset(data, groupOff),
		daclPresent:  control&0x0004 != 0 && daclOff != 0,
		saclPresent:  control&0x0010 != 0 && saclOff != 0,
	}

	if info.daclPresent {
		size, aceCount, ok := parseACLInfo(data, daclOff)
		if ok {
			info.daclSize = size
			info.daclAceCount = aceCount
		}
	}
	if info.saclPresent {
		size, aceCount, ok := parseACLInfo(data, saclOff)
		if ok {
			info.saclSize = size
			info.saclAceCount = aceCount
		}
	}
	return info, true
}

func securityDescriptorControlString(control uint16) string {
	flags := []struct {
		value uint16
		name  string
	}{
		{0x0001, "OWNER_DEFAULTED"},
		{0x0002, "GROUP_DEFAULTED"},
		{0x0004, "DACL_PRESENT"},
		{0x0008, "DACL_DEFAULTED"},
		{0x0010, "SACL_PRESENT"},
		{0x0020, "SACL_DEFAULTED"},
		{0x0100, "DACL_AUTO_INHERIT_REQ"},
		{0x0200, "SACL_AUTO_INHERIT_REQ"},
		{0x0400, "DACL_AUTO_INHERITED"},
		{0x0800, "SACL_AUTO_INHERITED"},
		{0x1000, "DACL_PROTECTED"},
		{0x2000, "SACL_PROTECTED"},
		{0x4000, "RM_CONTROL_VALID"},
		{0x8000, "SELF_RELATIVE"},
	}

	var names []string
	for _, flag := range flags {
		if control&flag.value != 0 {
			names = append(names, flag.name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, "|")
}

func sidFromOffset(data []byte, offset uint32) string {
	if offset == 0 || int(offset) >= len(data) {
		return ""
	}
	sid, ok := parseSID(data[offset:])
	if !ok {
		return ""
	}
	return sid
}

func parseSID(data []byte) (string, bool) {
	if len(data) < 8 {
		return "", false
	}

	revision := data[0]
	subAuthorityCount := int(data[1])
	expectedLen := 8 + subAuthorityCount*4
	if expectedLen > len(data) {
		return "", false
	}

	identifierAuthority := uint64(0)
	for _, value := range data[2:8] {
		identifierAuthority = (identifierAuthority << 8) | uint64(value)
	}

	parts := []string{fmt.Sprintf("S-%d-%d", revision, identifierAuthority)}
	for i := 0; i < subAuthorityCount; i++ {
		start := 8 + i*4
		subAuthority := binary.LittleEndian.Uint32(data[start : start+4])
		parts = append(parts, fmt.Sprintf("%d", subAuthority))
	}
	return strings.Join(parts, "-"), true
}

func parseACLInfo(data []byte, offset uint32) (int, int, bool) {
	if offset == 0 || int(offset)+8 > len(data) {
		return 0, 0, false
	}
	acl := data[offset:]
	size := int(binary.LittleEndian.Uint16(acl[2:4]))
	aceCount := int(binary.LittleEndian.Uint16(acl[4:6]))
	if size <= 0 || int(offset)+size > len(data) {
		return 0, 0, false
	}
	return size, aceCount, true
}

func align16(value int) int {
	if value%16 == 0 {
		return value
	}
	return value + (16 - value%16)
}
