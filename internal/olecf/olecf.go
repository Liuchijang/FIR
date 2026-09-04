// Package olecf reads an OLE Compound File — Microsoft's MS-CFB, the container
// behind .doc, .msi and, the reason this package exists, an
// automaticDestinations-ms jump list.
//
// A jump list is a compound file whose streams are one LNK per recent item plus
// a DestList stream holding the order, the timestamps and the path of each. So
// nothing about the artifact is reachable without reading the container first.
//
// stdlib only, deliberately, like internal/ntfs and internal/registryfile: this
// parses attacker-reachable bytes off a subject machine and has no business
// pulling a dependency into that path.
package olecf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unicode/utf16"
)

// Object types as MS-CFB names them. Only stream and root are load-bearing here;
// a jump list has no nested storages.
const (
	TypeUnallocated = 0
	TypeStorage     = 1
	TypeStream      = 2
	TypeRoot        = 5
)

const (
	headerSize   = 512
	dirEntrySize = 128

	freeSect   = 0xFFFFFFFF
	endOfChain = 0xFFFFFFFE
	fatSect    = 0xFFFFFFFD
	difatSect  = 0xFFFFFFFC

	headerDIFATCount = 109

	// maxFileSize bounds what this package will read into memory. A jump list is
	// bounded by design — the largest on a real host measured 635 KB — so the cap
	// is here to stop a hostile or corrupt file from being believed about its own
	// size, not to accommodate a real one.
	maxFileSize = 64 << 20
)

var signature = [8]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// ErrNotCompoundFile reports a file that is not MS-CFB at all. Callers separate
// it from a malformed compound file because a jump list directory can hold a
// file some other component wrote.
var ErrNotCompoundFile = errors.New("not an OLE compound file")

// Entry is one directory entry: a stream, a storage, or the root.
type Entry struct {
	Name     string
	Type     byte
	Created  uint64 // FILETIME, 0 when unset
	Modified uint64 // FILETIME, 0 when unset
	Size     uint64

	start uint32
}

// File is a parsed compound file. The whole file is held in memory because
// every stream in a jump list is read and the largest is under a megabyte.
type File struct {
	data []byte

	sectorSize     int
	miniSectorSize int
	miniCutoff     uint32

	fat        []uint32
	miniFAT    []uint32
	entries    []Entry
	miniStream []byte
}

// Open reads a compound file from disk.
func Open(path string) (*File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxFileSize {
		return nil, fmt.Errorf("compound file is %d bytes, over the %d byte limit", info.Size(), maxFileSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return New(data)
}

// New parses a compound file already in memory.
func New(data []byte) (*File, error) {
	if len(data) < headerSize {
		return nil, ErrNotCompoundFile
	}
	if [8]byte(data[:8]) != signature {
		return nil, ErrNotCompoundFile
	}

	f := &File{data: data}

	sectorShift := binary.LittleEndian.Uint16(data[0x1E:])
	miniShift := binary.LittleEndian.Uint16(data[0x20:])
	// Sanity bounds rather than an equality check on the two shifts MS-CFB
	// actually specifies (9 or 12, and 6): a real jump list is 9/6, and refusing
	// anything else would reject a valid container this reader could otherwise
	// handle. The bounds exist so the shift cannot produce a nonsense size.
	if sectorShift < 7 || sectorShift > 20 || miniShift < 2 || miniShift > sectorShift {
		return nil, fmt.Errorf("implausible sector shifts %d/%d", sectorShift, miniShift)
	}
	f.sectorSize = 1 << sectorShift
	f.miniSectorSize = 1 << miniShift
	f.miniCutoff = binary.LittleEndian.Uint32(data[0x38:])

	fatCount := binary.LittleEndian.Uint32(data[0x2C:])
	dirStart := binary.LittleEndian.Uint32(data[0x30:])
	miniFATStart := binary.LittleEndian.Uint32(data[0x3C:])
	difatStart := binary.LittleEndian.Uint32(data[0x44:])
	difatCount := binary.LittleEndian.Uint32(data[0x48:])

	if err := f.readFAT(fatCount, difatStart, difatCount); err != nil {
		return nil, err
	}
	if err := f.readDirectory(dirStart); err != nil {
		return nil, err
	}
	// The root entry's data run is the mini stream: every stream smaller than the
	// cutoff lives inside it, indexed by the mini FAT. In a jump list that is
	// almost every stream, so this is the common path and not an edge case.
	if root, ok := f.Root(); ok {
		stream, err := f.readChain(root.start, root.Size, false)
		if err != nil {
			return nil, fmt.Errorf("read mini stream: %w", err)
		}
		f.miniStream = stream
	}
	f.readMiniFAT(miniFATStart)

	return f, nil
}

// sector returns the bytes of one sector.
//
// Sector numbers are relative to the end of the header, so sector 0 begins at
// one sector size in — which is also where a 4096-byte-sector file's first
// sector starts, because its header is padded to a full sector.
//
// The last sector may be short, and refusing it is not a theoretical loss: a
// real jump list is not padded to a sector boundary, and a 635,534-byte one
// returned its DestList 142 bytes shy — the parse then walked entries until the
// stream ran out and reported the file as truncated. Callers that read fixed
// positions inside a sector, which is every allocation table, must bound
// themselves on what comes back.
func (f *File) sector(id uint32) ([]byte, bool) {
	if id >= fatSect {
		return nil, false
	}
	off := (int(id) + 1) * f.sectorSize
	if off < 0 || off >= len(f.data) {
		return nil, false
	}
	end := off + f.sectorSize
	if end > len(f.data) {
		end = len(f.data)
	}
	return f.data[off:end], true
}

// readFAT assembles the sector allocation table from the sector list held in the
// header plus, when the file is large enough to need one, the DIFAT chain.
func (f *File) readFAT(fatCount, difatStart, difatCount uint32) error {
	ids := make([]uint32, 0, headerDIFATCount)
	for i := 0; i < headerDIFATCount; i++ {
		ids = append(ids, binary.LittleEndian.Uint32(f.data[0x4C+i*4:]))
	}

	// Each DIFAT sector holds sector-size/4 - 1 FAT sector ids and ends with the
	// next DIFAT sector. difatCount bounds the walk so a cycle cannot spin.
	next := difatStart
	for i := uint32(0); i < difatCount && next < fatSect; i++ {
		sec, ok := f.sector(next)
		if !ok {
			return fmt.Errorf("DIFAT sector %d is outside the file", next)
		}
		if len(sec) < f.sectorSize {
			// A DIFAT sector ends with the pointer to the next one, so a short one
			// carries no continuation and nothing reliable to read.
			break
		}
		per := f.sectorSize/4 - 1
		for j := 0; j < per; j++ {
			ids = append(ids, binary.LittleEndian.Uint32(sec[j*4:]))
		}
		next = binary.LittleEndian.Uint32(sec[f.sectorSize-4:])
	}

	f.fat = make([]uint32, 0, int(fatCount)*(f.sectorSize/4))
	used := uint32(0)
	for _, id := range ids {
		if used >= fatCount {
			break
		}
		if id >= fatSect {
			continue
		}
		sec, ok := f.sector(id)
		if !ok {
			return fmt.Errorf("FAT sector %d is outside the file", id)
		}
		for j := 0; j+4 <= len(sec); j += 4 {
			f.fat = append(f.fat, binary.LittleEndian.Uint32(sec[j:]))
		}
		used++
	}
	if len(f.fat) == 0 {
		return errors.New("compound file has no FAT")
	}
	return nil
}

// readMiniFAT follows the mini FAT chain. A file with nothing in short storage
// has no mini FAT, which is not an error — the sector id is end-of-chain.
func (f *File) readMiniFAT(start uint32) {
	next := start
	for steps := 0; next < fatSect && steps <= len(f.fat); steps++ {
		sec, ok := f.sector(next)
		if !ok {
			return
		}
		for j := 0; j+4 <= len(sec); j += 4 {
			f.miniFAT = append(f.miniFAT, binary.LittleEndian.Uint32(sec[j:]))
		}
		next = f.fatNext(next)
	}
}

func (f *File) fatNext(id uint32) uint32 {
	if int(id) >= len(f.fat) {
		return endOfChain
	}
	return f.fat[id]
}

func (f *File) miniNext(id uint32) uint32 {
	if int(id) >= len(f.miniFAT) {
		return endOfChain
	}
	return f.miniFAT[id]
}

// readDirectory walks the directory chain and decodes every allocated entry.
func (f *File) readDirectory(start uint32) error {
	raw, err := f.readChain(start, 0, false)
	if err != nil {
		return fmt.Errorf("read directory: %w", err)
	}
	for off := 0; off+dirEntrySize <= len(raw); off += dirEntrySize {
		e := raw[off : off+dirEntrySize]
		typ := e[0x42]
		if typ == TypeUnallocated {
			continue
		}

		nameLen := int(binary.LittleEndian.Uint16(e[0x40:]))
		// The length counts the UTF-16 terminator; a value outside the 64-byte
		// name field means the entry is not one.
		if nameLen < 2 || nameLen > 64 {
			continue
		}
		f.entries = append(f.entries, Entry{
			Name:     utf16String(e[:nameLen-2]),
			Type:     typ,
			Created:  binary.LittleEndian.Uint64(e[0x64:]),
			Modified: binary.LittleEndian.Uint64(e[0x6C:]),
			start:    binary.LittleEndian.Uint32(e[0x74:]),
			Size:     binary.LittleEndian.Uint64(e[0x78:]),
		})
	}
	if len(f.entries) == 0 {
		return errors.New("compound file has no directory entries")
	}
	return nil
}

// readChain concatenates a data run. size of 0 means "to the end of the chain",
// which is what the directory itself needs since its length is not recorded.
func (f *File) readChain(start uint32, size uint64, mini bool) ([]byte, error) {
	if size > maxFileSize {
		return nil, fmt.Errorf("stream claims %d bytes, over the %d byte limit", size, maxFileSize)
	}

	unit := f.sectorSize
	limit := len(f.fat)
	if mini {
		unit = f.miniSectorSize
		limit = len(f.miniFAT)
	}

	var out []byte
	if size > 0 {
		out = make([]byte, 0, size)
	}

	// steps is bounded by the table length: a chain cannot legitimately visit more
	// sectors than the table has slots, and a corrupt file whose chain loops would
	// otherwise allocate until the process dies.
	next := start
	for steps := 0; next < fatSect && steps <= limit; steps++ {
		var chunk []byte
		if mini {
			off := int(next) * unit
			if off < 0 || off >= len(f.miniStream) {
				break
			}
			end := off + unit
			if end > len(f.miniStream) {
				end = len(f.miniStream)
			}
			chunk = f.miniStream[off:end]
			next = f.miniNext(next)
		} else {
			sec, ok := f.sector(next)
			if !ok {
				break
			}
			chunk = sec
			next = f.fatNext(next)
		}

		out = append(out, chunk...)
		if size > 0 && uint64(len(out)) >= size {
			break
		}
	}

	if size > 0 {
		if uint64(len(out)) < size {
			return out, fmt.Errorf("stream is %d bytes, %d were recorded", len(out), size)
		}
		out = out[:size]
	}
	return out, nil
}

// Root returns the root directory entry, whose data run is the mini stream.
func (f *File) Root() (Entry, bool) {
	for _, e := range f.entries {
		if e.Type == TypeRoot {
			return e, true
		}
	}
	return Entry{}, false
}

// Entries returns every allocated directory entry, in directory order.
func (f *File) Entries() []Entry {
	out := make([]Entry, len(f.entries))
	copy(out, f.entries)
	return out
}

// Streams returns the stream entries only, in directory order.
func (f *File) Streams() []Entry {
	var out []Entry
	for _, e := range f.entries {
		if e.Type == TypeStream {
			out = append(out, e)
		}
	}
	return out
}

// Read returns the bytes of one stream.
//
// Which table locates them is decided by the stream's own size against the
// header's cutoff, not by where the caller found the entry.
func (f *File) Read(e Entry) ([]byte, error) {
	if e.Size == 0 {
		return nil, nil
	}
	mini := e.Type != TypeRoot && e.Size < uint64(f.miniCutoff)
	return f.readChain(e.start, e.Size, mini)
}

// Stream reads a stream by name. Names are compared exactly: a jump list's
// numbered streams are lowercase hex and "DestList" is spelled that way.
func (f *File) Stream(name string) ([]byte, bool, error) {
	for _, e := range f.entries {
		if e.Type == TypeStream && e.Name == name {
			data, err := f.Read(e)
			return data, true, err
		}
	}
	return nil, false, nil
}

// utf16String decodes a little-endian UTF-16 name, stopping at the first NUL.
func utf16String(b []byte) string {
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
