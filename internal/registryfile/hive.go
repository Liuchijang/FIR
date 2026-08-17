// Package registryfile reads a registry hive straight from its file, without
// asking Windows to mount it.
//
// It exists because the mounting APIs cannot open the hives Tyto collects.
// RegLoadAppKeyW rejects a collected SYSTEM with ERROR_BADDB — measured on a hive
// that verified byte-for-byte against its collection hash, carried both its
// transaction logs, and was structurally clean (format 1.5, sequence numbers
// equal) — while the NTUSER.DAT beside it loaded fine. An application hive may not
// contain symbolic links, and SYSTEM has one: CurrentControlSet. So that route was
// never going to work for the machine hives, and RegLoadKey, which would, needs
// SeRestorePrivilege and puts the subject's hive into the analyst's live registry.
//
// Reading the file is what the established ShimCache tooling does
// (AppCompatCacheParser parses the hive directly rather than mounting it), and it
// removes the whole class of problem: no elevation, no staging copies away from
// transaction logs, no mutation of the evidence, and the same code path on the
// subject machine and the investigator's.
//
// The package deliberately imports nothing outside the standard library, so a
// hive reader stays a hive reader.
package registryfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	// baseBlockSize is the header, and also the origin every cell offset is
	// measured from.
	baseBlockSize = 4096

	rootCellOffsetPos = 0x24

	// nameIsASCII marks a key or value name stored one byte per character rather
	// than as UTF-16.
	keyNameIsASCII   = 0x20
	valueNameIsASCII = 0x01

	// valueDataInline marks a value whose data is small enough to live in the
	// offset field itself.
	valueDataInline = 0x80000000

	// bigDataThreshold is the largest a value can be before it is split across
	// segments. AppCompatCache on a real host runs to hundreds of kilobytes, so
	// the split form is the normal case here, not an edge case.
	bigDataThreshold = 16344
)

// ErrNotFound is returned for a key or value the hive does not hold, so a caller
// can tell "absent" from "unreadable".
var ErrNotFound = errors.New("not found in hive")

// Hive is a read-only view of a hive file.
type Hive struct {
	data []byte
	root uint32
}

// Key is one key node inside a hive.
type Key struct {
	hive *Hive
	cell []byte
}

// Open reads a hive file.
//
// The whole file is read into memory. A hive is bounded by what the registry
// holds — the largest here is SOFTWARE at ~120 MB — unlike the volume-sized
// artifacts elsewhere in this tree that must be streamed. Walking cells by offset
// wants random access anyway.
func Open(path string) (*Hive, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return New(data)
}

// New reads a hive already in memory.
func New(data []byte) (*Hive, error) {
	if len(data) < baseBlockSize {
		return nil, fmt.Errorf("hive is %d bytes, shorter than its header", len(data))
	}
	if string(data[0:4]) != "regf" {
		return nil, fmt.Errorf("not a registry hive: signature %q", data[0:4])
	}

	hive := &Hive{
		data: data,
		root: binary.LittleEndian.Uint32(data[rootCellOffsetPos:]),
	}
	if _, err := hive.cell(hive.root); err != nil {
		return nil, fmt.Errorf("root cell: %w", err)
	}
	return hive, nil
}

// Root returns the hive's root key.
func (h *Hive) Root() (*Key, error) {
	return h.keyAt(h.root)
}

// OpenKey resolves a backslash-separated path below the root.
//
// Matching is case-insensitive, as the registry itself is. Symbolic links are not
// followed: SYSTEM's CurrentControlSet points at whichever ControlSet the machine
// last booted, which a reader of a collected hive resolves for itself by looking
// at Select\Current — following it here would mean reproducing that in a file
// parser that has no business knowing about it.
func (h *Hive) OpenKey(path string) (*Key, error) {
	root, err := h.Root()
	if err != nil {
		return nil, err
	}
	return root.OpenPath(path)
}

// OpenPath resolves a backslash-separated path below this key.
func (k *Key) OpenPath(path string) (*Key, error) {
	key := k
	for _, name := range strings.Split(path, `\`) {
		if name == "" {
			continue
		}
		next, err := key.Subkey(name)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		key = next
	}
	return key, nil
}

// cell returns the payload of the cell at offset, which is measured from the end
// of the base block and carries its own size as a signed prefix — negative for an
// allocated cell, positive for a free one.
func (h *Hive) cell(offset uint32) ([]byte, error) {
	if offset == 0xFFFFFFFF {
		return nil, ErrNotFound
	}
	start := int64(baseBlockSize) + int64(offset)
	if start < 0 || start+4 > int64(len(h.data)) {
		return nil, fmt.Errorf("cell offset %#x is outside the hive", offset)
	}

	size := int32(binary.LittleEndian.Uint32(h.data[start:]))
	if size < 0 {
		size = -size
	}
	if size < 4 || start+int64(size) > int64(len(h.data)) {
		return nil, fmt.Errorf("cell at %#x claims %d bytes", offset, size)
	}
	return h.data[start+4 : start+int64(size)], nil
}

func (h *Hive) keyAt(offset uint32) (*Key, error) {
	cell, err := h.cell(offset)
	if err != nil {
		return nil, err
	}
	if len(cell) < 76 || string(cell[0:2]) != "nk" {
		return nil, fmt.Errorf("cell at %#x is not a key node", offset)
	}
	return &Key{hive: h, cell: cell}, nil
}

// Name is the key's own name, not its path.
func (k *Key) Name() string {
	nameLen := int(binary.LittleEndian.Uint16(k.cell[72:]))
	if 76+nameLen > len(k.cell) {
		return ""
	}
	flags := binary.LittleEndian.Uint16(k.cell[2:])
	return decodeName(k.cell[76:76+nameLen], flags&keyNameIsASCII != 0)
}

// LastWrite is the key's last write time.
func (k *Key) LastWrite() time.Time {
	return filetime(binary.LittleEndian.Uint64(k.cell[4:]))
}

// SubkeyNames lists the immediate subkeys.
func (k *Key) SubkeyNames() ([]string, error) {
	offsets, err := k.subkeyOffsets()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(offsets))
	for _, offset := range offsets {
		sub, err := k.hive.keyAt(offset)
		if err != nil {
			continue
		}
		names = append(names, sub.Name())
	}
	return names, nil
}

// Subkey opens one immediate subkey by name, case-insensitively.
func (k *Key) Subkey(name string) (*Key, error) {
	offsets, err := k.subkeyOffsets()
	if err != nil {
		return nil, err
	}
	for _, offset := range offsets {
		sub, err := k.hive.keyAt(offset)
		if err != nil {
			continue
		}
		if strings.EqualFold(sub.Name(), name) {
			return sub, nil
		}
	}
	return nil, fmt.Errorf("subkey %q: %w", name, ErrNotFound)
}

// subkeyOffsets flattens the subkey list, whatever shape it takes.
//
// Four shapes exist and a hive mixes them freely: lf and lh are sorted lists with
// a name hash per entry, li is a plain list, and ri is a list *of lists* used once
// a key has more subkeys than one cell can index.
func (k *Key) subkeyOffsets() ([]uint32, error) {
	count := binary.LittleEndian.Uint32(k.cell[20:])
	if count == 0 {
		return nil, nil
	}
	return k.hive.subkeyList(binary.LittleEndian.Uint32(k.cell[28:]), 0)
}

// maxSubkeyListDepth bounds the ri recursion. Two levels is what the format
// needs; more means a cycle, and a hive from an untrusted source is exactly where
// one would appear.
const maxSubkeyListDepth = 8

func (h *Hive) subkeyList(offset uint32, depth int) ([]uint32, error) {
	if depth > maxSubkeyListDepth {
		return nil, fmt.Errorf("subkey list nested deeper than %d levels", maxSubkeyListDepth)
	}
	cell, err := h.cell(offset)
	if err != nil {
		return nil, err
	}
	if len(cell) < 4 {
		return nil, fmt.Errorf("subkey list at %#x is truncated", offset)
	}

	signature := string(cell[0:2])
	count := int(binary.LittleEndian.Uint16(cell[2:]))
	entries := cell[4:]

	var offsets []uint32
	switch signature {
	case "lf", "lh":
		for i := 0; i < count && (i+1)*8 <= len(entries); i++ {
			offsets = append(offsets, binary.LittleEndian.Uint32(entries[i*8:]))
		}
	case "li":
		for i := 0; i < count && (i+1)*4 <= len(entries); i++ {
			offsets = append(offsets, binary.LittleEndian.Uint32(entries[i*4:]))
		}
	case "ri":
		for i := 0; i < count && (i+1)*4 <= len(entries); i++ {
			nested, err := h.subkeyList(binary.LittleEndian.Uint32(entries[i*4:]), depth+1)
			if err != nil {
				continue
			}
			offsets = append(offsets, nested...)
		}
	default:
		return nil, fmt.Errorf("unknown subkey list signature %q at %#x", signature, offset)
	}
	return offsets, nil
}

// Registry value types, the REG_* constants, for callers deciding how to read a
// value's bytes.
const (
	TypeSZ       uint32 = 1
	TypeExpandSZ uint32 = 2
	TypeBinary   uint32 = 3
	TypeDWORD    uint32 = 4
	TypeMultiSZ  uint32 = 7
	TypeQWORD    uint32 = 11
)

// eachValue calls visit for every value in the key until it returns false.
//
// Both Value and ValueNames walk the same list, so the walk is written once —
// the vk record's name encoding flag is easy to get right in one place and easy to
// forget in the second.
func (k *Key) eachValue(visit func(name string, cell []byte) bool) error {
	count := binary.LittleEndian.Uint32(k.cell[36:])
	if count == 0 {
		return nil
	}
	list, err := k.hive.cell(binary.LittleEndian.Uint32(k.cell[40:]))
	if err != nil {
		return err
	}

	for i := 0; i < int(count) && (i+1)*4 <= len(list); i++ {
		cell, err := k.hive.cell(binary.LittleEndian.Uint32(list[i*4:]))
		if err != nil || len(cell) < 20 || string(cell[0:2]) != "vk" {
			continue
		}
		nameLen := int(binary.LittleEndian.Uint16(cell[2:]))
		if 20+nameLen > len(cell) {
			continue
		}
		flags := binary.LittleEndian.Uint16(cell[16:])
		// A nameless value is the key's default; callers ask for it as "".
		name := decodeName(cell[20:20+nameLen], flags&valueNameIsASCII != 0)
		if !visit(name, cell) {
			return nil
		}
	}
	return nil
}

// ValueNames lists the key's values.
func (k *Key) ValueNames() ([]string, error) {
	var names []string
	err := k.eachValue(func(name string, _ []byte) bool {
		names = append(names, name)
		return true
	})
	return names, err
}

// Value returns a value's raw bytes and its REG_* type.
func (k *Key) Value(name string) ([]byte, uint32, error) {
	var (
		data  []byte
		kind  uint32
		found bool
		inner error
	)
	err := k.eachValue(func(valueName string, cell []byte) bool {
		if !strings.EqualFold(valueName, name) {
			return true
		}
		found = true
		kind = binary.LittleEndian.Uint32(cell[12:])
		data, inner = k.hive.valueData(cell)
		return false
	})
	switch {
	case err != nil:
		return nil, 0, err
	case !found:
		return nil, 0, fmt.Errorf("value %q: %w", name, ErrNotFound)
	case inner != nil:
		return nil, kind, inner
	}
	return data, kind, nil
}

// BinaryValue returns a value's bytes, for callers that do not care about the type.
func (k *Key) BinaryValue(name string) ([]byte, error) {
	data, _, err := k.Value(name)
	return data, err
}

// StringValue reads a REG_SZ or REG_EXPAND_SZ.
//
// It refuses other types rather than rendering their bytes as text, matching what
// the mounted-registry API does: a caller that wants a number out of a string
// value asks for the number.
func (k *Key) StringValue(name string) (string, error) {
	data, kind, err := k.Value(name)
	if err != nil {
		return "", err
	}
	if kind != TypeSZ && kind != TypeExpandSZ {
		return "", fmt.Errorf("value %q is type %d, not a string", name, kind)
	}
	return trimUTF16(data), nil
}

// StringsValue reads a REG_MULTI_SZ.
func (k *Key) StringsValue(name string) ([]string, error) {
	data, kind, err := k.Value(name)
	if err != nil {
		return nil, err
	}
	if kind != TypeMultiSZ {
		return nil, fmt.Errorf("value %q is type %d, not a multi-string", name, kind)
	}

	var out []string
	for _, part := range strings.Split(decodeUTF16(data), "\x00") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out, nil
}

// IntegerValue reads a REG_DWORD or REG_QWORD.
func (k *Key) IntegerValue(name string) (uint64, error) {
	data, kind, err := k.Value(name)
	if err != nil {
		return 0, err
	}
	switch kind {
	case TypeDWORD:
		if len(data) < 4 {
			return 0, fmt.Errorf("value %q is a DWORD in %d bytes", name, len(data))
		}
		return uint64(binary.LittleEndian.Uint32(data)), nil
	case TypeQWORD:
		if len(data) < 8 {
			return 0, fmt.Errorf("value %q is a QWORD in %d bytes", name, len(data))
		}
		return binary.LittleEndian.Uint64(data), nil
	default:
		return 0, fmt.Errorf("value %q is type %d, not an integer", name, kind)
	}
}

func (h *Hive) valueData(vk []byte) ([]byte, error) {
	size := binary.LittleEndian.Uint32(vk[4:])
	offset := binary.LittleEndian.Uint32(vk[8:])

	// Up to four bytes live in the offset field itself rather than in a cell.
	if size&valueDataInline != 0 {
		length := int(size &^ valueDataInline)
		if length > 4 {
			length = 4
		}
		return append([]byte(nil), vk[8:8+length]...), nil
	}

	cell, err := h.cell(offset)
	if err != nil {
		return nil, err
	}
	if size <= bigDataThreshold {
		if int(size) > len(cell) {
			return append([]byte(nil), cell...), nil
		}
		return append([]byte(nil), cell[:size]...), nil
	}
	return h.bigData(cell, int(size))
}

// bigData reassembles a value stored across segments.
//
// Anything over 16344 bytes is split, and the vk points at a "db" record naming a
// list of segment cells instead of at the data. ShimCache is normally in this
// form, so a reader that stops at the threshold reads nothing on a real host.
func (h *Hive) bigData(cell []byte, size int) ([]byte, error) {
	if len(cell) < 8 || string(cell[0:2]) != "db" {
		return nil, fmt.Errorf("value claims %d bytes but is not stored as big data", size)
	}

	segments := int(binary.LittleEndian.Uint16(cell[2:]))
	list, err := h.cell(binary.LittleEndian.Uint32(cell[4:]))
	if err != nil {
		return nil, fmt.Errorf("big data segment list: %w", err)
	}

	out := make([]byte, 0, size)
	for i := 0; i < segments && (i+1)*4 <= len(list); i++ {
		segment, err := h.cell(binary.LittleEndian.Uint32(list[i*4:]))
		if err != nil {
			return nil, fmt.Errorf("big data segment %d: %w", i, err)
		}
		if len(segment) > bigDataThreshold {
			segment = segment[:bigDataThreshold]
		}
		out = append(out, segment...)
		if len(out) >= size {
			break
		}
	}
	if len(out) > size {
		out = out[:size]
	}
	return out, nil
}

// decodeName reads a key or value name, which the format stores either as one
// byte per character or as UTF-16.
func decodeName(raw []byte, isASCII bool) string {
	if isASCII {
		return string(raw)
	}
	return decodeUTF16(raw)
}

func decodeUTF16(raw []byte) string {
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(raw[i:]))
	}
	return string(utf16.Decode(units))
}

// trimUTF16 decodes a string value and drops the terminator, plus any padding
// after it. A REG_SZ is stored with a trailing NUL and the cell it sits in is
// rounded up, so the raw bytes routinely carry more than the string.
func trimUTF16(raw []byte) string {
	return strings.TrimRight(decodeUTF16(raw), "\x00")
}

// filetime converts a Windows FILETIME. A zero value means the field was never
// set and comes back as the zero Time so callers render it as no value at all.
func filetime(value uint64) time.Time {
	const windowsEpoch100ns = 116444736000000000
	if value < windowsEpoch100ns {
		return time.Time{}
	}
	return time.Unix(0, int64(value-windowsEpoch100ns)*100).UTC()
}
