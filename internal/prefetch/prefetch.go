// Package prefetch parses a Windows Prefetch (.pf) record into its contents.
//
// The point of the package is that the interesting evidence is *inside* the file.
// Tyto's analyzer used to report only the container's first few fields and the .pf
// file's own MAC timestamps, which meant two things went wrong at once: on Windows
// 10 the file is compressed, so those fields were the compression container's magic
// read as a version number; and the MAC timestamps describe whatever copy of the
// file the analyzer happened to open, so a collected artifact reported the moment
// Tyto copied it rather than anything about the subject.
//
// A parsed record carries up to eight execution timestamps, a run count, the volumes
// the executable touched with their serials and creation times, and the full list of
// files and directories loaded during the traced runs. All of it lives in the file's
// bytes, so all of it survives being copied — which is what makes offline analysis
// of a collected Prefetch directory worth anything.
//
// Versions 17 (XP/2003), 23 (Vista/7), 26 (8.1), 30 (10) and 31 (11) are supported.
// **Only version 30 has been verified against real artifacts** — 250 files from a
// Windows 10 host — because that is the only version available to test against. The
// others are implemented from the published layouts and covered by synthetic
// fixtures, which is a weaker guarantee and is why every layout is *validated* at
// parse time rather than trusted: see chooseLayout.
package prefetch

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

// File is one parsed .pf record.
type File struct {
	Version    uint32
	Compressed bool
	// LayoutName is the variant that validated, e.g. "30" or "30v2". Recorded
	// because version 30 has two field layouts in the wild and an analyst comparing
	// output against another tool needs to know which one was read.
	LayoutName string

	ExecutableName string
	// Hash is the prefetch hash from the record. The filename carries the same value,
	// and HashMatchesName reports whether they agree — a disagreement means the file
	// was renamed, which is worth seeing.
	Hash            uint32
	HashMatchesName bool

	DeclaredSize uint32
	ActualSize   int

	RunCount uint32
	// RunTimes are the execution timestamps the record holds, most recent first.
	// Versions 17 and 23 carry one; 26 and later carry up to eight.
	RunTimes []time.Time

	Volumes []Volume
	// LoadedFiles are the full paths the traced runs touched, in record order.
	LoadedFiles []string
}

// Volume is one entry from a record's volume information block.
type Volume struct {
	DevicePath   string
	SerialHex    string
	Created      time.Time
	Directories  []string
	FileRefCount int
}

// layout is where a version keeps the fields that move.
//
// The first nine dwords of the file information block are identical in every
// version and are read directly; only the timestamps and the run count shift.
type layout struct {
	name string
	// lastRunOffset is relative to the start of the file information block.
	lastRunOffset  int
	lastRunSlots   int
	runCountOffset int
	volumeStride   int
}

// layouts lists the candidates per version, **ordered by ascending lastRunOffset**.
//
// Versions 30 and 31 have two entries because both shapes exist in the wild and the
// version number does not distinguish them: the Windows 10 host this was developed
// against keeps its timestamps eight bytes further in than the published
// version-26-style layout, with the run count in the same place.
//
// The order is load-bearing. Trying the later offset first looked fine against real
// files and was wrong: in a record using the *earlier* layout, offset 0x2C lands on
// the second timestamp of the array, which is a perfectly plausible instant — so the
// later candidate validated and every run time came out shifted by one slot. Reading
// the earlier offset first inverts that safely, because in the later layout 0x24
// holds two small unknown dwords (14 and 2 on every one of 250 real files) which
// cannot be mistaken for a FILETIME.
var layouts = map[uint32][]layout{
	17: {{name: "17", lastRunOffset: 0x24, lastRunSlots: 1, runCountOffset: 0x3C, volumeStride: 40}},
	23: {{name: "23", lastRunOffset: 0x24, lastRunSlots: 1, runCountOffset: 0x3C, volumeStride: 96}},
	26: {{name: "26", lastRunOffset: 0x24, lastRunSlots: 8, runCountOffset: 0x74, volumeStride: 96}},
	30: {
		{name: "30", lastRunOffset: 0x24, lastRunSlots: 8, runCountOffset: 0x74, volumeStride: 96},
		{name: "30v2", lastRunOffset: 0x2C, lastRunSlots: 8, runCountOffset: 0x74, volumeStride: 96},
	},
	31: {
		{name: "31", lastRunOffset: 0x24, lastRunSlots: 8, runCountOffset: 0x74, volumeStride: 96},
		{name: "31v2", lastRunOffset: 0x2C, lastRunSlots: 8, runCountOffset: 0x74, volumeStride: 96},
	},
}

const (
	// headerSize is the fixed part every version shares: version, signature, an
	// unknown dword, the declared file size, the executable name, the hash and a
	// flags dword.
	headerSize = 0x54
	// fileInfoOffset is where the version-dependent block begins.
	fileInfoOffset = headerSize

	nameOffset   = 0x10
	nameMaxBytes = 60
	hashOffset   = 0x4C

	signature = "SCCA"

	// filetimeEpochOffset is 1601-01-01 in 100ns ticks before the Unix epoch.
	filetimeEpochOffset = 116444736000000000
)

// filetimeMin/filetimeMax bound what counts as a run timestamp.
//
// Prefetch was introduced with Windows XP, so nothing legitimate predates 2001, and
// a value beyond the next century is a misread field rather than a scheduled run.
// The bounds are what makes layout validation possible: a candidate whose first slot
// is not a plausible instant is the wrong candidate.
const (
	filetimeMin = 126000000000000000 // 2000-ish
	filetimeMax = 159000000000000000 // 2105-ish
)

// Parse reads and parses one .pf file.
func Parse(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseBytes(raw)
}

// ParseBytes parses a .pf record that is already in memory, compressed or not.
func ParseBytes(raw []byte) (*File, error) {
	compressed := isCompressed(raw)
	body, err := decompress(raw)
	if err != nil {
		return nil, err
	}

	if len(body) < headerSize {
		return nil, fmt.Errorf("prefetch record is %d bytes, shorter than its %d-byte header", len(body), headerSize)
	}
	if got := string(body[4:8]); got != signature {
		return nil, fmt.Errorf("prefetch signature is %q, want %q", sanitize(got), signature)
	}

	file := &File{
		Version:      le32(body, 0),
		Compressed:   compressed,
		DeclaredSize: le32(body, 0x0C),
		ActualSize:   len(body),
		Hash:         le32(body, hashOffset),
	}
	file.ExecutableName = utf16String(body[nameOffset : nameOffset+nameMaxBytes])

	chosen, ok := chooseLayout(body, file.Version)
	if !ok {
		return nil, fmt.Errorf("prefetch version %d has no field layout that reads as valid data", file.Version)
	}
	file.LayoutName = chosen.name
	file.RunCount = le32(body, fileInfoOffset+chosen.runCountOffset)
	file.RunTimes = readRunTimes(body, chosen)
	file.Volumes, file.LoadedFiles = readReferences(body, chosen)

	return file, nil
}

// HashFromName recovers the hash the file name encodes, e.g. 56DE4F9A from
// 7ZFM.EXE-56DE4F9A.pf. ok is false when the name does not carry one.
func HashFromName(name string) (uint32, bool) {
	base := strings.TrimSuffix(name, ".pf")
	base = strings.TrimSuffix(base, ".PF")
	dash := strings.LastIndex(base, "-")
	if dash < 0 || len(base)-dash-1 != 8 {
		return 0, false
	}
	var value uint32
	if _, err := fmt.Sscanf(base[dash+1:], "%X", &value); err != nil {
		return 0, false
	}
	return value, true
}

// SetNameHash records whether the record's hash agrees with the one in its file
// name. Kept separate from ParseBytes because the name is not in the bytes.
func (f *File) SetNameHash(fileName string) {
	if hash, ok := HashFromName(fileName); ok {
		f.HashMatchesName = hash == f.Hash
	}
}

// chooseLayout picks the field layout that reads as valid data.
//
// Two checks decide it, and both come from measuring real files rather than from the
// published tables:
//
//   - The first run-time slot has to be a plausible instant, and the slot *before*
//     it must not be. Together those separate version 30's two layouts: the first
//     check alone accepts a candidate that has landed in the middle of the array,
//     which silently shifts every timestamp by one position.
//   - The run count has to be at least the number of populated timestamp slots. A
//     program cannot have run fewer times than it has recorded runs. Across 250 real
//     files the correct offset violated this zero times while the neighbouring dword
//     violated it 136 times, so the check discriminates rather than merely passing.
func chooseLayout(body []byte, version uint32) (layout, bool) {
	candidates := layouts[version]
	if len(candidates) == 0 {
		// An unrecognised version is still worth attempting: the header is fixed and
		// a new Windows build is far more likely to reuse a known block layout than
		// to invent one. Ordered newest-first so a future version tries the modern
		// shape before the ancient one.
		for _, v := range []uint32{31, 30, 26, 23, 17} {
			candidates = append(candidates, layouts[v]...)
		}
	}

	for _, candidate := range candidates {
		if !fits(body, fileInfoOffset+candidate.lastRunOffset, candidate.lastRunSlots*8) ||
			!fits(body, fileInfoOffset+candidate.runCountOffset, 4) {
			continue
		}
		first := le64(body, fileInfoOffset+candidate.lastRunOffset)
		if first < filetimeMin || first > filetimeMax {
			continue
		}
		// Reject a candidate that has landed inside an array starting earlier. Only
		// checked past the fixed nine-dword block, whose contents are offsets and
		// counts rather than timestamps.
		if prev := candidate.lastRunOffset - 8; prev >= 0x24 {
			if v := le64(body, fileInfoOffset+prev); v >= filetimeMin && v <= filetimeMax {
				continue
			}
		}
		populated := 0
		for i := 0; i < candidate.lastRunSlots; i++ {
			if v := le64(body, fileInfoOffset+candidate.lastRunOffset+i*8); v >= filetimeMin && v <= filetimeMax {
				populated++
			}
		}
		if uint32(populated) > le32(body, fileInfoOffset+candidate.runCountOffset) {
			continue
		}
		return candidate, true
	}
	return layout{}, false
}

func readRunTimes(body []byte, chosen layout) []time.Time {
	times := make([]time.Time, 0, chosen.lastRunSlots)
	for i := 0; i < chosen.lastRunSlots; i++ {
		at := fileInfoOffset + chosen.lastRunOffset + i*8
		if !fits(body, at, 8) {
			break
		}
		value := le64(body, at)
		if value < filetimeMin || value > filetimeMax {
			// Unused slots are zero, and they are trailing: the array is
			// most-recent-first, so the first empty slot ends the list.
			break
		}
		times = append(times, filetimeToUTC(value))
	}
	return times
}

// readReferences reads the volume information block and the filename strings.
//
// Every offset here comes out of the file, so each one is bounds-checked before use
// and a block that does not fit is dropped rather than parsed. A .pf is an artifact
// an intruder can write.
func readReferences(body []byte, chosen layout) ([]Volume, []string) {
	fileNamesOffset := int(le32(body, fileInfoOffset+0x10))
	fileNamesSize := int(le32(body, fileInfoOffset+0x14))
	volumesOffset := int(le32(body, fileInfoOffset+0x18))
	volumesCount := int(le32(body, fileInfoOffset+0x1C))

	var loaded []string
	if fits(body, fileNamesOffset, fileNamesSize) {
		loaded = utf16StringList(body[fileNamesOffset : fileNamesOffset+fileNamesSize])
	}

	// maxVolumes bounds a count read from the file. A machine has single digits of
	// volumes; a four-billion claim is a misread or a hostile field.
	const maxVolumes = 64
	if volumesCount > maxVolumes {
		volumesCount = maxVolumes
	}

	volumes := make([]Volume, 0, volumesCount)
	for i := 0; i < volumesCount; i++ {
		entry := volumesOffset + i*chosen.volumeStride
		if !fits(body, entry, chosen.volumeStride) {
			break
		}

		// Offsets inside a volume entry are relative to the start of the volume
		// information block, not to the entry or to the file.
		pathOffset := volumesOffset + int(le32(body, entry+0x00))
		pathChars := int(le32(body, entry+0x04))
		volume := Volume{
			Created:   filetimeToUTC(le64(body, entry+0x08)),
			SerialHex: fmt.Sprintf("%08X", le32(body, entry+0x10)),
		}
		if fits(body, pathOffset, pathChars*2) {
			volume.DevicePath = utf16String(body[pathOffset : pathOffset+pathChars*2])
		}
		volume.FileRefCount = int(le32(body, entry+0x18)) / 8

		directoryOffset := volumesOffset + int(le32(body, entry+0x1C))
		directoryCount := int(le32(body, entry+0x20))
		volume.Directories = readDirectoryStrings(body, directoryOffset, directoryCount)

		volumes = append(volumes, volume)
	}
	return volumes, loaded
}

// readDirectoryStrings reads the length-prefixed UTF-16 directory list a volume
// entry points at: a uint16 character count, the characters, then a NUL.
func readDirectoryStrings(body []byte, at, count int) []string {
	// maxDirectories bounds a count read from the file, as with volumes. A traced run
	// touches hundreds of directories, not millions.
	const maxDirectories = 8192
	if count > maxDirectories {
		count = maxDirectories
	}

	directories := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if !fits(body, at, 2) {
			break
		}
		chars := int(binary.LittleEndian.Uint16(body[at : at+2]))
		if !fits(body, at+2, chars*2) {
			break
		}
		directories = append(directories, utf16String(body[at+2:at+2+chars*2]))
		at += 2 + chars*2 + 2 // the trailing NUL is not counted in chars
	}
	return directories
}

// LastRun is the most recent execution, or the zero time when the record holds none.
func (f *File) LastRun() time.Time {
	if len(f.RunTimes) == 0 {
		return time.Time{}
	}
	return f.RunTimes[0]
}

// DirectoryCount totals the directories across every volume.
func (f *File) DirectoryCount() int {
	total := 0
	for _, volume := range f.Volumes {
		total += len(volume.Directories)
	}
	return total
}

func fits(body []byte, at, length int) bool {
	return at >= 0 && length >= 0 && at+length <= len(body)
}

func le32(body []byte, at int) uint32 {
	if !fits(body, at, 4) {
		return 0
	}
	return binary.LittleEndian.Uint32(body[at : at+4])
}

func le64(body []byte, at int) uint64 {
	if !fits(body, at, 8) {
		return 0
	}
	return binary.LittleEndian.Uint64(body[at : at+8])
}

func filetimeToUTC(value uint64) time.Time {
	if value < filetimeMin || value > filetimeMax {
		return time.Time{}
	}
	return time.Unix(0, int64(value-filetimeEpochOffset)*100).UTC()
}

// utf16String decodes a NUL-terminated UTF-16LE string, stopping at the terminator.
func utf16String(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		unit := binary.LittleEndian.Uint16(b[i:])
		if unit == 0 {
			break
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units))
}

// utf16StringList splits a run of NUL-separated UTF-16LE strings.
func utf16StringList(b []byte) []string {
	var out []string
	start := 0
	for i := 0; i+1 < len(b); i += 2 {
		if binary.LittleEndian.Uint16(b[i:]) != 0 {
			continue
		}
		if i > start {
			out = append(out, utf16String(b[start:i]))
		}
		start = i + 2
	}
	if start+1 < len(b) {
		if s := utf16String(b[start:]); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// sanitize renders a bad signature safely for an error message: the bytes came from
// the file, so they may be control characters or invalid UTF-8.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			b.WriteByte('.')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
