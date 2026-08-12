package analyzers

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Liuchijang/Tyto/internal/ntfs"
	"github.com/Velocidex/ordereddict"
	ese "www.velocidex.com/golang/go-ese/parser"
)

// SruDbIdMapTable is what makes the rest of SRUM readable. Every provider row
// identifies its subject by a small integer in AppId/UserId, and this table is
// the only place those integers are defined. Without it a run's SRUM output is a
// table of numbers.
const srumIDMapTable = "SruDbIdMapTable"

// IdType selects how IdBlob is encoded. 3 is a binary SID; everything else is a
// UTF-16LE application identity string of the form
// "!!winlogon.exe!1994/06/28:04:25:22!e2418!".
const srumIDTypeSID = 3

// srumIDMap resolves the AppId and UserId integers used across every provider
// table.
type srumIDMap map[int32]string

// loadSRUMIDMap reads the whole ID map. It is bounded by the number of distinct
// applications and accounts the machine has seen — tens of thousands of short
// strings, not a volume-sized artifact — so unlike the provider tables it is
// held resident, which is the point: the provider tables can then stream.
func loadSRUMIDMap(catalog *ese.Catalog) (srumIDMap, error) {
	ids := make(srumIDMap, 1024)
	err := catalog.DumpTable(srumIDMapTable, func(row *ordereddict.Dict) error {
		index, ok := srumInt32(row, "IdIndex")
		if !ok {
			return nil
		}
		blob, ok := srumBlob(row, "IdBlob")
		if !ok || len(blob) == 0 {
			// Rows with no IdBlob exist in the wild — the tagged column is simply
			// absent. Skipping keeps the raw AppId visible in the output instead
			// of inventing a name for it.
			return nil
		}

		idType, _ := srumUint8(row, "IdType")
		if idType == srumIDTypeSID {
			ids[index] = srumLabelSID(srumBinarySID(blob))
			return nil
		}
		ids[index] = strings.TrimRight(ntfs.UTF16String(blob), "\x00")
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", srumIDMapTable, err)
	}
	return ids, nil
}

// resolve returns the identity for an ID, or "" when the map does not define it.
func (m srumIDMap) resolve(id int32) string {
	if m == nil {
		return ""
	}
	return m[id]
}

// srumBinarySID renders a binary SID.
//
// The authority is big-endian across bytes 2..7 while the sub-authorities that
// follow are little-endian 32-bit words — mixing the two up produces a
// plausible-looking SID that belongs to nobody.
func srumBinarySID(sid []byte) string {
	if len(sid) < 8 {
		return ""
	}
	subCount := int(sid[1])
	authority := uint64(binary.BigEndian.Uint16(sid[2:4]))<<32 | uint64(binary.BigEndian.Uint32(sid[4:8]))

	var out strings.Builder
	fmt.Fprintf(&out, "S-%d-%d", sid[0], authority)
	for i := 0; i < subCount; i++ {
		start := 8 + i*4
		if start+4 > len(sid) {
			break
		}
		fmt.Fprintf(&out, "-%d", binary.LittleEndian.Uint32(sid[start:start+4]))
	}
	return out.String()
}

// srumBlob pulls a binary column out of a row. The ESE reader renders binary
// columns as a hex string, so the bytes have to be decoded back out before they
// can be read as UTF-16 or as a SID; a column that is already text is returned
// as its own bytes.
func srumBlob(row *ordereddict.Dict, name string) ([]byte, bool) {
	value, ok := row.Get(name)
	if !ok || value == nil {
		return nil, false
	}
	switch typed := value.(type) {
	case []byte:
		return typed, true
	case string:
		if decoded, err := hex.DecodeString(typed); err == nil {
			return decoded, true
		}
		return []byte(typed), true
	default:
		return nil, false
	}
}

func srumInt32(row *ordereddict.Dict, name string) (int32, bool) {
	value, ok := row.Get(name)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case int32:
		return typed, true
	case int64:
		return int32(typed), true
	case uint32:
		return int32(typed), true
	case int:
		return int32(typed), true
	default:
		return 0, false
	}
}

func srumUint8(row *ordereddict.Dict, name string) (uint8, bool) {
	value, ok := row.Get(name)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case uint8:
		return typed, true
	case int32:
		return uint8(typed), true
	case int64:
		return uint8(typed), true
	default:
		return 0, false
	}
}

func srumUint64(row *ordereddict.Dict, name string) (uint64, bool) {
	value, ok := row.Get(name)
	if !ok {
		return 0, false
	}
	switch typed := value.(type) {
	case uint64:
		return typed, true
	case int64:
		if typed < 0 {
			return 0, false
		}
		return uint64(typed), true
	case uint32:
		return uint64(typed), true
	case int32:
		if typed < 0 {
			return 0, false
		}
		return uint64(typed), true
	default:
		return 0, false
	}
}
