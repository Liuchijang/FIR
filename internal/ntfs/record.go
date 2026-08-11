// Package ntfs holds the record-level primitives shared by the raw-volume
// reader in internal/acquisition and the parsers in internal/analyzers.
//
// Both sides used to carry their own copy: applyNTFSFixup/applyMFTFixup and two
// byte-identical attributeName functions. Fixup in particular rewrites an
// evidence record in place, so a bug fixed on one side and left on the other
// silently corrupts one half of a run's output.
//
// It imports nothing outside the standard library on purpose. acquisition
// otherwise depends on no internal package, and routing these three functions
// through internal/utils would have pulled internal/module and internal/artifact
// into a raw disk reader's build.
package ntfs

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// ApplyFixup undoes the NTFS update sequence array, rewriting record in place.
//
// A sectorSize of 0 or less means "derive it from the record": the two callers
// disagree on whether they know it. The raw-volume reader has the authoritative
// BytesPerSector from the volume boot record, while the parsers work from a
// collected $MFT with no volume data attached and have to infer it from the
// record length and the fixup count.
//
// The reader's copy used to reject a non-positive sectorSize instead. That
// branch was unreachable: GetNTFSVolumeData refuses a volume reporting zero
// bytes per sector, so no NTFSVolumeData carrying one ever exists.
func ApplyFixup(record []byte, sectorSize int) error {
	if len(record) < 8 {
		return fmt.Errorf("record too small")
	}

	usaOffset := int(binary.LittleEndian.Uint16(record[4:6]))
	usaCount := int(binary.LittleEndian.Uint16(record[6:8]))
	if usaOffset <= 0 || usaCount < 2 {
		return fmt.Errorf("invalid update sequence array")
	}
	usaEnd := usaOffset + usaCount*2
	if usaEnd > len(record) {
		return fmt.Errorf("update sequence array out of bounds")
	}

	if sectorSize <= 0 {
		sectorSize = 512
		if sectors := usaCount - 1; sectors > 0 && len(record)%sectors == 0 {
			sectorSize = len(record) / sectors
		}
	}

	updateSeq := record[usaOffset : usaOffset+2]
	replacements := record[usaOffset+2 : usaEnd]
	for i := 1; i < usaCount; i++ {
		sectorEnd := i*sectorSize - 2
		replOff := (i - 1) * 2
		if sectorEnd+2 > len(record) || replOff+2 > len(replacements) {
			return fmt.Errorf("fixup index out of bounds")
		}
		if record[sectorEnd] != updateSeq[0] || record[sectorEnd+1] != updateSeq[1] {
			return fmt.Errorf("update sequence mismatch")
		}
		record[sectorEnd] = replacements[replOff]
		record[sectorEnd+1] = replacements[replOff+1]
	}
	return nil
}

// AttributeName returns an attribute's name, or "" for an unnamed one.
func AttributeName(attr []byte) string {
	if len(attr) < 12 {
		return ""
	}
	nameLen := int(attr[9])
	nameOff := int(binary.LittleEndian.Uint16(attr[10:12]))
	if nameLen <= 0 || nameOff <= 0 || nameOff+nameLen*2 > len(attr) {
		return ""
	}
	return UTF16String(attr[nameOff : nameOff+nameLen*2])
}

// UTF16String decodes a UTF-16LE buffer up to the first NUL. It is a plain
// Windows string decode rather than anything NTFS-specific — the ShimCache and
// RecentDocs parsers read the same encoding out of registry blobs — and lives
// here only because this is the package both sides can already reach.
func UTF16String(data []byte) string {
	values := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		value := binary.LittleEndian.Uint16(data[i : i+2])
		if value == 0 {
			break
		}
		values = append(values, value)
	}
	return string(utf16.Decode(values))
}
