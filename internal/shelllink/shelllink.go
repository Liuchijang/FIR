// Package shelllink parses a Windows shell link — a LNK file.
//
// It exists for the jump lists: both kinds are a wrapper around LNK bodies, and
// until those are read a jump list says what was opened but not where the target
// lived, how big it was, what its own timestamps said or which volume it sat on.
// The same parser serves a .lnk on disk, so the Recent folder itself becomes
// readable with no new format work.
//
// stdlib only, like internal/olecf and internal/jumplist. These bytes come off a
// subject machine and are attacker-reachable — a LNK is a documented delivery
// vector — so every structure is read with its own length checked against what
// is actually there, and no declared size is trusted.
package shelllink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"

	"github.com/Liuchijang/Tyto/internal/winguid"
)

// GUID is internal/winguid's: a shell link's tracker block carries the same
// droid identifiers a jump list entry does, and the arithmetic that turns one
// into a MAC address and a timestamp lives in one place.
type GUID = winguid.GUID

func guidAt(record []byte, offset int) GUID { return winguid.At(record, offset) }

// headerSize is fixed by the format at 0x4C, and the value is also how a LNK is
// recognised: it is the first four bytes of every one.
const headerSize = 0x4C

// linkCLSID follows the header size in every shell link.
var linkCLSID = [16]byte{
	0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// LinkFlags bits, in the order MS-SHLLINK defines them. Only the ones that
// change how the rest of the file is laid out are named.
const (
	flagHasLinkTargetIDList = 1 << 0
	flagHasLinkInfo         = 1 << 1
	flagHasName             = 1 << 2
	flagHasRelativePath     = 1 << 3
	flagHasWorkingDir       = 1 << 4
	flagHasArguments        = 1 << 5
	flagHasIconLocation     = 1 << 6
	flagIsUnicode           = 1 << 7
	flagForceNoLinkInfo     = 1 << 8
)

// flagNames is for the HeaderFlags column: the set a link declares is worth
// reporting because it says what the link was built to do.
var flagNames = []struct {
	bit  uint32
	name string
}{
	{flagHasLinkTargetIDList, "HasTargetIDList"},
	{flagHasLinkInfo, "HasLinkInfo"},
	{flagHasName, "HasName"},
	{flagHasRelativePath, "HasRelativePath"},
	{flagHasWorkingDir, "HasWorkingDir"},
	{flagHasArguments, "HasArguments"},
	{flagHasIconLocation, "HasIconLocation"},
	{flagIsUnicode, "IsUnicode"},
	{flagForceNoLinkInfo, "ForceNoLinkInfo"},
	{1 << 9, "HasExpString"},
	{1 << 10, "RunInSeparateProcess"},
	{1 << 12, "HasDarwinID"},
	{1 << 13, "RunAsUser"},
	{1 << 14, "HasExpIcon"},
	{1 << 15, "NoPidlAlias"},
	{1 << 17, "RunWithShimLayer"},
	{1 << 18, "ForceNoLinkTrack"},
	{1 << 19, "EnableTargetMetadata"},
	{1 << 20, "DisableLinkPathTracking"},
	{1 << 21, "DisableKnownFolderTracking"},
	{1 << 22, "DisableKnownFolderAlias"},
	{1 << 23, "AllowLinkToLink"},
	{1 << 24, "UnaliasOnSave"},
	{1 << 25, "PreferEnvironmentPath"},
	{1 << 26, "KeepLocalIDListForUNCTarget"},
}

// File attribute bits, named as the CSV reports them.
var attributeNames = []struct {
	bit  uint32
	name string
}{
	{0x0001, "ReadOnly"},
	{0x0002, "Hidden"},
	{0x0004, "System"},
	{0x0010, "Directory"},
	{0x0020, "Archive"},
	{0x0040, "Device"},
	{0x0080, "Normal"},
	{0x0100, "Temporary"},
	{0x0200, "SparseFile"},
	{0x0400, "ReparsePoint"},
	{0x0800, "Compressed"},
	{0x1000, "Offline"},
	{0x2000, "NotContentIndexed"},
	{0x4000, "Encrypted"},
}

// Drive types as GetDriveType returns them, which is what a VolumeID records.
var driveTypeNames = map[uint32]string{
	0: "Unknown",
	1: "NoRootDirectory",
	2: "Removable",
	3: "Fixed",
	4: "Remote",
	5: "CDROM",
	6: "RAMDisk",
}

// ErrNotShellLink reports bytes that are not a LNK.
var ErrNotShellLink = errors.New("not a shell link")

// File is a parsed shell link.
type File struct {
	Flags          uint32
	FileAttributes uint32

	// The target's own timestamps, as FILETIME. They describe the file the link
	// points at, recorded when the link was last written — not the link.
	TargetCreated  uint64
	TargetAccessed uint64
	TargetWritten  uint64

	TargetSize uint32
	IconIndex  int32

	// From the LinkInfo structure: where the target lived.
	LocalBasePath    string
	CommonPathSuffix string
	DriveType        uint32
	HasVolumeID      bool
	DriveSerial      uint32
	VolumeLabel      string
	NetworkShare     string
	NetworkDevice    string

	// From StringData.
	Name         string
	RelativePath string
	WorkingDir   string
	Arguments    string
	IconLocation string

	// From the target ID list.
	TargetPath        string
	MFTEntryNumber    uint64
	MFTSequenceNumber uint16
	HasMFTReference   bool

	// From the TrackerDataBlock: the machine the link was created on. The
	// identifier survives the link being copied elsewhere, which is what makes it
	// worth reporting.
	MachineID        string
	DroidVolume      GUID
	DroidFile        GUID
	DroidBirthVolume GUID
	DroidBirthFile   GUID

	// Title is PKEY_Title out of a property store, when there is one. It is the
	// label a custom destinations entry shows in the jump list menu.
	Title string

	// ExtraBlocks names the extra data blocks the link carries, in order.
	ExtraBlocks []string

	Warnings []string
}

// Open reads and parses a LNK from disk.
func Open(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse reads a LNK already in memory.
//
// Trailing bytes are tolerated: a LNK carved out of a custom destinations file
// runs to the start of the next one, so what is handed in is usually longer than
// the link.
func Parse(data []byte) (*File, error) {
	if len(data) < headerSize {
		return nil, ErrNotShellLink
	}
	if binary.LittleEndian.Uint32(data) != headerSize || [16]byte(data[4:20]) != linkCLSID {
		return nil, ErrNotShellLink
	}

	f := &File{
		Flags:          binary.LittleEndian.Uint32(data[0x14:]),
		FileAttributes: binary.LittleEndian.Uint32(data[0x18:]),
		TargetCreated:  binary.LittleEndian.Uint64(data[0x1C:]),
		TargetAccessed: binary.LittleEndian.Uint64(data[0x24:]),
		TargetWritten:  binary.LittleEndian.Uint64(data[0x2C:]),
		TargetSize:     binary.LittleEndian.Uint32(data[0x34:]),
		IconIndex:      int32(binary.LittleEndian.Uint32(data[0x38:])),
	}

	at := headerSize
	if f.Flags&flagHasLinkTargetIDList != 0 {
		next, err := f.readTargetIDList(data, at)
		if err != nil {
			f.Warnings = append(f.Warnings, err.Error())
			return f, nil
		}
		at = next
	}
	if f.Flags&flagHasLinkInfo != 0 && f.Flags&flagForceNoLinkInfo == 0 {
		next, err := f.readLinkInfo(data, at)
		if err != nil {
			f.Warnings = append(f.Warnings, err.Error())
			return f, nil
		}
		at = next
	}

	next, err := f.readStringData(data, at)
	if err != nil {
		f.Warnings = append(f.Warnings, err.Error())
		return f, nil
	}
	at = next

	f.readExtraData(data, at)
	return f, nil
}

// FlagNames renders the header flags a link declares.
func (f *File) FlagNames() []string {
	return namesOf(f.Flags, flagNames)
}

// AttributeNames renders the target's file attributes.
func (f *File) AttributeNames() []string {
	return namesOf(f.FileAttributes, attributeNames)
}

// DriveTypeName is the volume's drive type, or "" when the link records no
// volume at all.
func (f *File) DriveTypeName() string {
	if !f.HasVolumeID {
		return ""
	}
	if name, ok := driveTypeNames[f.DriveType]; ok {
		return name
	}
	return fmt.Sprintf("Unrecognized(%d)", f.DriveType)
}

// LocalPath is the target path the LinkInfo records: the base path with the
// common suffix appended, which is how the two halves are meant to be joined.
//
// A target on a share has no local base path — LinkInfo describes it as the share
// name plus the same suffix — so the two are joined here rather than left in
// separate columns for a reader to notice and assemble. Measured against JLECmd,
// this was 20 rows of one run where it produced
// "\WSL.LOCALHOST\KALI-LINUX\home\saturday\poc.py" and this produced nothing.
func (f *File) LocalPath() string {
	base := f.LocalBasePath
	if base == "" && f.NetworkShare != "" {
		base = strings.TrimRight(f.NetworkShare, `\`) + `\`
	}
	if base == "" {
		return ""
	}
	if f.CommonPathSuffix == "" {
		return base
	}
	return base + f.CommonPathSuffix
}

func namesOf(value uint32, table []struct {
	bit  uint32
	name string
}) []string {
	var out []string
	for _, entry := range table {
		if value&entry.bit != 0 {
			out = append(out, entry.name)
		}
	}
	return out
}

// readLinkInfo reads where the target lived: the local path, the volume it was
// on, or the network share it came from.
func (f *File) readLinkInfo(data []byte, at int) (int, error) {
	if at+8 > len(data) {
		return at, errors.New("LinkInfo runs past the end of the link")
	}
	size := int(binary.LittleEndian.Uint32(data[at:]))
	if size < 0x1C || at+size > len(data) {
		return at, fmt.Errorf("LinkInfo declares %d bytes, %d remain", size, len(data)-at)
	}
	info := data[at : at+size]

	headerLen := int(binary.LittleEndian.Uint32(info[4:]))
	flags := binary.LittleEndian.Uint32(info[8:])
	volumeOffset := int(binary.LittleEndian.Uint32(info[0x0C:]))
	basePathOffset := int(binary.LittleEndian.Uint32(info[0x10:]))
	networkOffset := int(binary.LittleEndian.Uint32(info[0x14:]))
	suffixOffset := int(binary.LittleEndian.Uint32(info[0x18:]))

	// A header of 0x24 or more carries Unicode offsets for the same two strings.
	// They are preferred where present: the ANSI pair is a lossy rendering of the
	// same path, and on a non-Latin profile name it is the wrong path.
	basePathUnicode, suffixUnicode := 0, 0
	if headerLen >= 0x24 && len(info) >= 0x24 {
		basePathUnicode = int(binary.LittleEndian.Uint32(info[0x1C:]))
		suffixUnicode = int(binary.LittleEndian.Uint32(info[0x20:]))
	}

	if flags&0x01 != 0 {
		if basePathUnicode > 0 {
			f.LocalBasePath = utf16StringAt(info, basePathUnicode)
		} else {
			f.LocalBasePath = ansiStringAt(info, basePathOffset)
			if hasHighBytes(info, basePathOffset) {
				// Saying so matters more than the characters do: the shell items
				// carry the same name in UTF-16 and are the column to trust.
				f.Warnings = append(f.Warnings,
					"LinkInfo carries only a single-byte path; its code page is not recorded, so characters outside ASCII are approximate")
			}
		}
		f.readVolumeID(info, volumeOffset)
	}
	if flags&0x02 != 0 {
		f.readNetworkLink(info, networkOffset)
	}
	if suffixUnicode > 0 {
		f.CommonPathSuffix = utf16StringAt(info, suffixUnicode)
	} else {
		f.CommonPathSuffix = ansiStringAt(info, suffixOffset)
	}

	return at + size, nil
}

func (f *File) readVolumeID(info []byte, offset int) {
	if offset <= 0 || offset+16 > len(info) {
		return
	}
	size := int(binary.LittleEndian.Uint32(info[offset:]))
	if size < 16 || offset+size > len(info) {
		return
	}
	volume := info[offset : offset+size]

	f.HasVolumeID = true
	f.DriveType = binary.LittleEndian.Uint32(volume[4:])
	f.DriveSerial = binary.LittleEndian.Uint32(volume[8:])

	labelOffset := int(binary.LittleEndian.Uint32(volume[12:]))
	// The sentinel 0x14 means the label is Unicode and its offset follows.
	if labelOffset == 0x14 && len(volume) >= 20 {
		f.VolumeLabel = utf16StringAt(volume, int(binary.LittleEndian.Uint32(volume[16:])))
		return
	}
	f.VolumeLabel = ansiStringAt(volume, labelOffset)
}

func (f *File) readNetworkLink(info []byte, offset int) {
	if offset <= 0 || offset+20 > len(info) {
		return
	}
	size := int(binary.LittleEndian.Uint32(info[offset:]))
	if size < 20 || offset+size > len(info) {
		return
	}
	network := info[offset : offset+size]

	flags := binary.LittleEndian.Uint32(network[4:])
	nameOffset := int(binary.LittleEndian.Uint32(network[8:]))
	deviceOffset := int(binary.LittleEndian.Uint32(network[12:]))

	// Offsets beyond 0x14 mean the Unicode pair is present after them.
	if nameOffset > 0x14 && len(network) >= 0x1C {
		f.NetworkShare = utf16StringAt(network, int(binary.LittleEndian.Uint32(network[0x14:])))
		if flags&0x01 != 0 {
			f.NetworkDevice = utf16StringAt(network, int(binary.LittleEndian.Uint32(network[0x18:])))
		}
		return
	}
	f.NetworkShare = ansiStringAt(network, nameOffset)
	if flags&0x01 != 0 {
		f.NetworkDevice = ansiStringAt(network, deviceOffset)
	}
}

// readStringData reads the five optional strings, which appear in a fixed order
// and only when their flag is set.
func (f *File) readStringData(data []byte, at int) (int, error) {
	unicode := f.Flags&flagIsUnicode != 0
	for _, field := range []struct {
		flag uint32
		dst  *string
	}{
		{flagHasName, &f.Name},
		{flagHasRelativePath, &f.RelativePath},
		{flagHasWorkingDir, &f.WorkingDir},
		{flagHasArguments, &f.Arguments},
		{flagHasIconLocation, &f.IconLocation},
	} {
		if f.Flags&field.flag == 0 {
			continue
		}
		if at+2 > len(data) {
			return at, errors.New("string data runs past the end of the link")
		}
		count := int(binary.LittleEndian.Uint16(data[at:]))
		at += 2

		width := 1
		if unicode {
			width = 2
		}
		end := at + count*width
		if end > len(data) {
			return at, fmt.Errorf("a string declares %d characters, %d bytes remain", count, len(data)-at)
		}
		if unicode {
			*field.dst = decodeUTF16(data[at:end])
		} else {
			*field.dst = trimNUL(string(data[at:end]))
		}
		at = end
	}
	return at, nil
}

// readExtraData walks the trailing blocks. The run ends at a block header
// smaller than four bytes, which is how the format terminates it.
func (f *File) readExtraData(data []byte, at int) {
	for at+8 <= len(data) {
		size := int(binary.LittleEndian.Uint32(data[at:]))
		if size < 4 {
			return
		}
		if at+size > len(data) {
			f.Warnings = append(f.Warnings, fmt.Sprintf("extra data block declares %d bytes, %d remain", size, len(data)-at))
			return
		}
		signature := binary.LittleEndian.Uint32(data[at+4:])
		block := data[at : at+size]

		f.ExtraBlocks = append(f.ExtraBlocks, extraBlockName(signature))
		switch signature {
		case 0xA0000003:
			f.readTrackerBlock(block)
		case 0xA0000009:
			f.readPropertyStoreBlock(block)
		}
		at += size
	}
}

var extraBlockNames = map[uint32]string{
	0xA0000001: "EnvironmentVariable",
	0xA0000002: "Console",
	0xA0000003: "Tracker",
	0xA0000004: "ConsoleFE",
	0xA0000005: "SpecialFolder",
	0xA0000006: "Darwin",
	0xA0000007: "IconEnvironment",
	0xA0000008: "Shim",
	0xA0000009: "PropertyStore",
	0xA000000B: "KnownFolder",
	0xA000000C: "VistaAndAboveIDList",
}

func extraBlockName(signature uint32) string {
	if name, ok := extraBlockNames[signature]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%08X)", signature)
}

// readTrackerBlock reads the machine name and the two droid pairs the link
// tracking service wrote.
func (f *File) readTrackerBlock(block []byte) {
	// 0x60 total: header 0x10, then a 16-byte machine name and two 32-byte droid
	// pairs.
	if len(block) < 0x60 {
		f.Warnings = append(f.Warnings, fmt.Sprintf("tracker block is %d bytes, %d expected", len(block), 0x60))
		return
	}
	f.MachineID = trimNUL(string(block[0x10:0x20]))
	f.DroidVolume = guidAt(block, 0x20)
	f.DroidFile = guidAt(block, 0x30)
	f.DroidBirthVolume = guidAt(block, 0x40)
	f.DroidBirthFile = guidAt(block, 0x50)
}

func trimNUL(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return s[:i]
		}
	}
	return s
}

// ansiStringAt reads a NUL-terminated single-byte string at an offset inside a
// structure.
//
// The code page it was written in is not recorded anywhere in the link, and it is
// the subject's rather than the analyst's, so there is nothing to decode it with.
// Each byte becomes the code point of the same value: lossless, reversible, and
// right for every byte the common Windows code pages share with Latin-1.
//
// The alternative was what this used to do — hand the bytes to Go as if they were
// UTF-8 — and it did not merely mis-render them, it dropped them: a path recorded
// as "Dùng GitHub Làm Kênh C2.pdf" reached the CSV as "Dng GitHub Lm Knh C2.pdf",
// a path that looks correct, resolves to nothing, and says nothing about having
// lost anything. hasHighBytes is what lets the caller say so.
func ansiStringAt(buf []byte, offset int) string {
	if offset <= 0 || offset >= len(buf) {
		return ""
	}
	var runes []rune
	for _, b := range buf[offset:] {
		if b == 0 {
			break
		}
		runes = append(runes, rune(b))
	}
	return string(runes)
}

// hasHighBytes reports a single-byte string that carried something outside ASCII,
// which is the case where the unknown code page matters.
func hasHighBytes(buf []byte, offset int) bool {
	if offset <= 0 || offset >= len(buf) {
		return false
	}
	for _, b := range buf[offset:] {
		if b == 0 {
			return false
		}
		if b >= 0x80 {
			return true
		}
	}
	return false
}

// utf16StringAt reads a NUL-terminated UTF-16 string at an offset inside a
// structure.
func utf16StringAt(buf []byte, offset int) string {
	if offset <= 0 || offset >= len(buf) {
		return ""
	}
	return decodeUTF16(buf[offset:])
}

// decodeUTF16 decodes little-endian UTF-16, stopping at the first NUL.
func decodeUTF16(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	return string(utf16.Decode(units))
}
