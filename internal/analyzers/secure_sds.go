package analyzers

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Liuchijang/FIR/internal/acquisition"
	"github.com/Liuchijang/FIR/internal/module"
	"github.com/Liuchijang/FIR/internal/utils"
)

func init() { module.RegisterAnalyzer(&secureSDSParser{}) }

type secureSDSParser struct{}

func (c *secureSDSParser) Name() string     { return "secure_sds_parser" }
func (c *secureSDSParser) Category() string { return "ntfs" }
func (c *secureSDSParser) Description() string {
	return "Parse Secure SDS"
}

func (c *secureSDSParser) Analyze(ctx context.Context, req module.AnalyzeRequest) module.AnalyzeResult {
	outDir, err := req.EnsureOutputDir(c.Name())
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Errorf("create secure_sds parser output dir: %w", err).Error()}
	}

	sources, sourceErrs := readSecureSDSSources(req.OutputDir)

	var rows [][]string
	var parseErrs []string
	for _, src := range sources {
		select {
		case <-ctx.Done():
			return module.AnalyzeResult{OutputPath: outDir, Error: ctx.Err().Error()}
		default:
		}

		driveRows, _, _, err := parseSecureSDSRows(src.data)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Sprintf("%s: %v", src.drive, err))
			continue
		}
		for _, row := range driveRows {
			rows = append(rows, append([]string{src.drive}, row...))
		}
	}
	if len(rows) == 0 {
		return module.AnalyzeResult{OutputPath: outDir, Error: fmt.Sprintf("no SDS entries parsed: %s", strings.Join(append(sourceErrs, parseErrs...), "; "))}
	}

	entriesCSV := filepath.Join(outDir, "secure_sds_entries.csv")
	if err := writeCSVFile(entriesCSV, []string{
		"Drive",
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
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}

	entriesInfo, err := utils.FileInfoFromPath(entriesCSV)
	if err != nil {
		return module.AnalyzeResult{OutputPath: outDir, Error: err.Error()}
	}
	return module.AnalyzeResult{Files: []module.FileInfo{entriesInfo}, OutputPath: outDir}
}

type secureSDSSource struct {
	drive string
	data  []byte
}

// readSecureSDSSources loads $Secure:$SDS for every drive it can, preferring
// already-collected $Secure_SDS_<drive> files, falling back to the legacy
// single-drive filename, and finally to a live read across every fixed drive.
func readSecureSDSSources(outputDir string) ([]secureSDSSource, []string) {
	var sources []secureSDSSource
	var errs []string

	if dir, ok := existingModuleDir(outputDir, "secure_sds"); ok {
		for _, drive := range collectedSecureSDSDrives(dir) {
			path := filepath.Join(dir, "$Secure_SDS_"+drive)
			data, err := os.ReadFile(path)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", drive, err))
				continue
			}
			sources = append(sources, secureSDSSource{drive: drive, data: data})
		}
		if len(sources) == 0 {
			if legacyPath := filepath.Join(dir, "$Secure_SDS"); fileExists(legacyPath) {
				data, err := os.ReadFile(legacyPath)
				if err != nil {
					errs = append(errs, fmt.Sprintf("C: %v", err))
				} else {
					sources = append(sources, secureSDSSource{drive: "C", data: data})
				}
			}
		}
	}

	if len(sources) == 0 {
		drives, err := acquisition.ListFixedDrives()
		if err != nil || len(drives) == 0 {
			drives = []string{"C"}
		}
		for _, drive := range drives {
			data, err := readLiveSecureSDS(drive)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", drive, err))
				continue
			}
			sources = append(sources, secureSDSSource{drive: drive, data: data})
		}
	}

	return sources, errs
}

// collectedSecureSDSDrives lists the drive letters for which a per-drive
// $Secure_SDS_<drive> file was collected into dir, sorted for determinism.
func collectedSecureSDSDrives(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var drives []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if drive, ok := strings.CutPrefix(entry.Name(), "$Secure_SDS_"); ok && drive != "" {
			drives = append(drives, drive)
		}
	}
	sort.Strings(drives)
	return drives
}

func readLiveSecureSDS(drive string) ([]byte, error) {
	vol, err := acquisition.OpenRawVolume(drive)
	if err != nil {
		return nil, fmt.Errorf("open raw volume for live SDS parse: %w", err)
	}
	defer vol.Close()

	volData, err := vol.GetNTFSVolumeData()
	if err != nil {
		return nil, fmt.Errorf("get NTFS volume data for live SDS parse: %w", err)
	}

	data, err := acquisition.ReadNamedDataStreamFromMFTRecord(vol, volData, 9, "$SDS")
	if err != nil {
		return nil, fmt.Errorf("read live $Secure:$SDS: %w", err)
	}
	return data, nil
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
