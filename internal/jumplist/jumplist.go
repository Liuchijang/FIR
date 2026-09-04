// Package jumplist parses the two Windows jump list formats.
//
// Both live under %AppData%\Microsoft\Windows\Recent and both are a wrapper
// around LNK files:
//
//   - AutomaticDestinations\<AppID>.automaticDestinations-ms is an OLE compound
//     file (internal/olecf) holding one LNK stream per recent item plus a
//     DestList stream that carries the order, the path, the timestamp and which
//     machine the item was opened on.
//   - CustomDestinations\<AppID>.customDestinations-ms is LNK files concatenated
//     into footer-terminated chunks, one chunk per jump list category.
//
// Only the DestList half is decoded here. The LNK bodies are handed back as raw
// bytes: reading them needs a shell link parser, which is a larger job than this
// whole package and is deliberately not a prerequisite for getting a timeline of
// what was opened, when, and from where.
//
// stdlib only, like internal/olecf.
package jumplist

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/Liuchijang/Tyto/internal/olecf"
)

// destListStreamName is the one stream in the container that is not a LNK.
const destListStreamName = "DestList"

// Offsets inside a DestList entry. They are the same for every version except
// where noted; the path is what moved, and moving it is what broke every tool
// when Windows 10 shipped version 3.
const (
	offChecksum         = 0
	offVolumeDroid      = 8
	offFileDroid        = 24
	offVolumeBirthDroid = 40
	offFileBirthDroid   = 56
	offHostname         = 72
	offEntryNumber      = 88
	offAccessCount      = 96
	offLastModified     = 100
	offPinStatus        = 108

	// Version 1: a 16-bit character count, then the path.
	offV1PathSize = 112
	offV1Path     = 114

	// Version 3 and later.
	offInteractionCount = 116
	offV3PathSize       = 128
	offV3Path           = 130

	destListHeaderSize = 32
	hostnameSize       = 16
)

// maxPathChars bounds the declared length of an entry's path. A DestList path is
// a file system path or a shell folder reference; a value beyond this is a
// corrupt record, and believing it walks the parser off the end of the stream.
const maxPathChars = 4096

// Automatic is a parsed automaticDestinations-ms jump list.
type Automatic struct {
	AppID  string
	Header DestListHeader
	// Entries are in DestList order, which is most-recently-used first.
	Entries []Entry
	// OrphanStreams names LNK streams the DestList does not reference. They are
	// reported rather than parsed: a stream with no entry is either slack the
	// container has not reused or a DestList that lost a record.
	OrphanStreams []string
	Warnings      []string
}

// DestListHeader is the 32 bytes in front of the entries.
type DestListHeader struct {
	Version               uint32
	NumberOfEntries       uint32
	NumberOfPinnedEntries uint32
	LastEntryNumber       uint32
	LastRevisionNumber    uint32
}

// Entry is one DestList record: one item on the jump list.
type Entry struct {
	// MRUPosition is the entry's index in the DestList, which is the order the
	// list itself is in. It is not stored in the record.
	MRUPosition int

	Checksum         uint64
	VolumeDroid      GUID
	FileDroid        GUID
	VolumeBirthDroid GUID
	FileBirthDroid   GUID
	Hostname         string
	EntryNumber      uint32
	AccessCount      float32
	LastModified     uint64 // FILETIME
	PinStatus        int32
	InteractionCount int32
	Path             string

	// SpsSize is the length of the serialized property store trailing the
	// record, 0 when there is none. It is recorded because the four bytes that
	// hold it were long read as padding, and a non-zero value there desynchronises
	// any parser that assumes they are.
	SpsSize int

	// Lnk is the body of the stream this entry names, or nil when the container
	// has no such stream.
	Lnk []byte
}

// HasSps reports whether a serialized property store trails the record.
func (e Entry) HasSps() bool { return e.SpsSize > 0 }

// StreamName is the container stream holding this entry's LNK: the entry number
// in lowercase hex, with no padding.
func (e Entry) StreamName() string {
	return strconv.FormatUint(uint64(e.EntryNumber), 16)
}

// OpenAutomatic reads and parses an automaticDestinations-ms file.
func OpenAutomatic(path string) (*Automatic, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseAutomatic(data, AppIDFromFileName(path))
}

// ParseAutomatic parses an automaticDestinations-ms file already in memory.
//
// An empty jump list is not an error. 25 of 85 files on one real host held no
// entries at all — 18 with a zero-length DestList and 7 with no streams
// whatsoever — because the application had been launched but had opened nothing.
// Reporting that as a failure would make "this program touched no files" look
// like "this artifact could not be read".
func ParseAutomatic(data []byte, appID string) (*Automatic, error) {
	container, err := olecf.New(data)
	if err != nil {
		return nil, err
	}

	auto := &Automatic{AppID: appID}

	// Index the LNK streams by name so entries can be joined to them, and so
	// what is left over afterwards can be reported.
	lnks := make(map[string][]byte)
	unused := make(map[string]bool)
	for _, stream := range container.Streams() {
		if stream.Name == destListStreamName {
			continue
		}
		body, err := container.Read(stream)
		if err != nil {
			auto.Warnings = append(auto.Warnings, fmt.Sprintf("stream %s: %v", stream.Name, err))
			continue
		}
		key := strings.ToLower(stream.Name)
		lnks[key] = body
		unused[key] = true
	}

	destList, found, err := container.Stream(destListStreamName)
	if err != nil {
		return nil, fmt.Errorf("read DestList: %w", err)
	}
	if !found || len(destList) == 0 {
		for name := range unused {
			auto.OrphanStreams = append(auto.OrphanStreams, name)
		}
		return auto, nil
	}
	if len(destList) < destListHeaderSize {
		auto.Warnings = append(auto.Warnings,
			fmt.Sprintf("DestList is %d bytes, shorter than its %d byte header", len(destList), destListHeaderSize))
		return auto, nil
	}

	auto.Header = DestListHeader{
		Version:               binary.LittleEndian.Uint32(destList[0:]),
		NumberOfEntries:       binary.LittleEndian.Uint32(destList[4:]),
		NumberOfPinnedEntries: binary.LittleEndian.Uint32(destList[8:]),
		LastEntryNumber:       binary.LittleEndian.Uint32(destList[16:]),
		LastRevisionNumber:    binary.LittleEndian.Uint32(destList[24:]),
	}

	auto.Entries, auto.Warnings = appendEntries(auto.Warnings, destList, auto.Header.Version)

	// The count in the header against the count actually walked. This is the
	// check that would have caught the Windows 10 format change in every tool
	// that silently returned one entry out of hundreds.
	if got, want := uint32(len(auto.Entries)), auto.Header.NumberOfEntries; got != want {
		auto.Warnings = append(auto.Warnings,
			fmt.Sprintf("DestList header records %d entries, %d were readable", want, got))
	}

	for i := range auto.Entries {
		key := auto.Entries[i].StreamName()
		if body, ok := lnks[key]; ok {
			auto.Entries[i].Lnk = body
			delete(unused, key)
		}
	}
	for name := range unused {
		auto.OrphanStreams = append(auto.OrphanStreams, name)
	}

	return auto, nil
}

// appendEntries walks the variable-length entry records.
//
// The stride is the part worth being careful about. Through version 1 a record
// ends at its path; from version 3 the path is followed by a 32-bit length and
// then that many bytes of serialized property store. Those four bytes are zero
// on an ordinary desktop — all 2123 entries on the host this was measured
// against — so a parser that treats them as fixed padding passes every test it
// is likely to be given and then loses every record after the first entry that
// carries a property store.
func appendEntries(warnings []string, destList []byte, version uint32) ([]Entry, []string) {
	var entries []Entry

	for index, position := destListHeaderSize, 0; index < len(destList); position++ {
		pathOffset, sizeOffset := offV3Path, offV3PathSize
		if version <= 1 {
			pathOffset, sizeOffset = offV1Path, offV1PathSize
		}

		if index+pathOffset > len(destList) {
			warnings = append(warnings,
				fmt.Sprintf("entry %d is truncated: %d bytes left, %d needed for the record header", position, len(destList)-index, pathOffset))
			break
		}

		pathChars := int(binary.LittleEndian.Uint16(destList[index+sizeOffset:]))
		if pathChars > maxPathChars {
			warnings = append(warnings, fmt.Sprintf("entry %d declares a %d character path", position, pathChars))
			break
		}

		entrySize := pathOffset + pathChars*2
		if index+entrySize > len(destList) {
			warnings = append(warnings,
				fmt.Sprintf("entry %d claims %d bytes, %d remain", position, entrySize, len(destList)-index))
			break
		}

		record := destList[index : index+entrySize]
		stride := entrySize

		spsSize := 0
		if version > 1 {
			if index+entrySize+4 > len(destList) {
				warnings = append(warnings, fmt.Sprintf("entry %d has no room for its property store length", position))
				break
			}
			raw := int32(binary.LittleEndian.Uint32(destList[index+entrySize:]))
			if raw < 0 || index+entrySize+4+int(raw) > len(destList) {
				warnings = append(warnings, fmt.Sprintf("entry %d declares a %d byte property store", position, raw))
				break
			}
			spsSize = int(raw)
			stride = entrySize + 4 + spsSize
		}

		entries = append(entries, parseEntry(record, position, pathOffset, pathChars, spsSize))
		index += stride
	}

	return entries, warnings
}

// parseEntry decodes one record. Every field but the path sits at the same
// offset in all versions.
func parseEntry(record []byte, position, pathOffset, pathChars, spsSize int) Entry {
	entry := Entry{
		MRUPosition:      position,
		Checksum:         binary.LittleEndian.Uint64(record[offChecksum:]),
		VolumeDroid:      guidAt(record, offVolumeDroid),
		FileDroid:        guidAt(record, offFileDroid),
		VolumeBirthDroid: guidAt(record, offVolumeBirthDroid),
		FileBirthDroid:   guidAt(record, offFileBirthDroid),
		Hostname:         hostname(record[offHostname : offHostname+hostnameSize]),
		EntryNumber:      binary.LittleEndian.Uint32(record[offEntryNumber:]),
		AccessCount:      math.Float32frombits(binary.LittleEndian.Uint32(record[offAccessCount:])),
		LastModified:     binary.LittleEndian.Uint64(record[offLastModified:]),
		PinStatus:        int32(binary.LittleEndian.Uint32(record[offPinStatus:])),
		SpsSize:          spsSize,
	}
	if pathOffset == offV3Path {
		entry.InteractionCount = int32(binary.LittleEndian.Uint32(record[offInteractionCount:]))
	}
	entry.Path = utf16String(record[pathOffset : pathOffset+pathChars*2])
	return entry
}

// hostname reads the 16-byte name of the machine the item was opened on.
//
// The field holds either ASCII or UTF-16, and which one is decided by whether
// the second byte is a NUL — there is no flag saying so. Reading it as the wrong
// one turns a hostname into a single letter, and this field is the reason to
// look: on the host this was measured against, one entry out of 2123 named a
// different machine.
func hostname(field []byte) string {
	if len(field) > 1 && field[1] == 0 {
		return utf16String(field)
	}
	if i := bytes.IndexByte(field, 0); i >= 0 {
		field = field[:i]
	}
	return string(field)
}

// AppIDFromFileName returns the application id a jump list file is named after.
func AppIDFromFileName(path string) string {
	name := filepath.Base(path)
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	return strings.ToLower(name)
}

// utf16String decodes a little-endian UTF-16 string, stopping at the first NUL.
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
