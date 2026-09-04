package shelllink

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/Liuchijang/Tyto/internal/winguid"
)

// Shell item class types, masked as the format defines them: the low nibble
// varies with the item's flavour and the high nibble names the kind.
const (
	classRootFolder = 0x1F
	// classShellFolder is a known folder reached through a delegate item —
	// Downloads, Pictures, Documents. Skipping it does not lose a GUID, it loses a
	// whole path component: a link into Pictures came out as `My Computer\1.png`,
	// which reads as a file at the root of the namespace rather than as one two
	// levels down.
	classShellFolder = 0x2E
	classVolume      = 0x2F
	classFileEntry   = 0x30
	classFileMask    = 0x70
	// classURI is a link to an address rather than to a file. It is what a
	// browser leaves in the Recent folder, and without it such a link reports only
	// the identifier of the Internet shell folder it hangs under: 64 of 278 links
	// on one real host, every one of which had the address in its bytes.
	classURI = 0x61

	// fileEntryUnicode marks a file entry whose primary name is UTF-16 rather
	// than a single-byte string.
	fileEntryUnicode = 0x04
)

// beefFileEntryExtension is the extension block that carries a file entry's long
// name and its position in the MFT. Its presence is why a target's path can be
// recovered in full rather than as a run of 8.3 names.
const beefFileEntryExtension = 0xBEEF0004

// offsets inside a file entry shell item, counted from the start of the item
// including its own two-byte size, which is how the format documents them.
const (
	itemClassOffset       = 2
	itemFileSizeOffset    = 4
	itemAttributesOffset  = 12
	itemPrimaryNameOffset = 14
)

// Shell folder identifiers, so a path through one of these reads as a place
// rather than as a GUID. Anything else is reported as its GUID: a folder this
// does not know is still evidence of where the target was.
//
// The three delegate entries at the end were not taken from a list. They were
// derived from the artifacts themselves — each identifier was matched against
// the directory the same link's LinkInfo structure records, over 278 links, and
// each resolved to exactly one: 088e3905 appeared only under Downloads, 24ad3ad4
// only under Pictures, d3162b92 only under Documents.
var shellFolderNames = map[string]string{
	"20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
	"b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
	"59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users",
	"031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
	"f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
	"645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
	"1f4de370-d627-11d1-ba4f-00a0c91eedba": "Search Results",
	"679f85cb-0220-4080-b29b-5540cc05aab6": "Quick Access",
	"18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
	"374de290-123f-4565-9164-39c4925e467b": "Downloads",

	// Named from what hangs under it in the artifacts rather than from a list: on
	// one host every child of this identifier was an http address or an
	// application protocol — ms-settings:, ms-photos:, ms-screensketch: — which is
	// the Internet shell folder and nothing else.
	"871c5380-42a0-1069-a2ea-08002b30309d": "Internet",

	"088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
	"24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures",
	"d3162b92-9365-467a-956b-92703aca08af": "Documents",
}

// readTargetIDList walks the shell items naming the target.
//
// This is the only part of a link that describes a target which is not a file
// path at all — a control panel applet, a search, a URL a browser pinned — and
// it is also the only place the target's MFT position appears.
func (f *File) readTargetIDList(data []byte, at int) (int, error) {
	if at+2 > len(data) {
		return at, fmt.Errorf("target ID list runs past the end of the link")
	}
	size := int(binary.LittleEndian.Uint16(data[at:]))
	at += 2
	if at+size > len(data) {
		return at, fmt.Errorf("target ID list declares %d bytes, %d remain", size, len(data)-at)
	}

	f.parseIDList(data[at : at+size])
	return at + size, nil
}

func (f *File) parseIDList(list []byte) {
	var segments []string
	for offset := 0; offset+2 <= len(list); {
		itemSize := int(binary.LittleEndian.Uint16(list[offset:]))
		if itemSize == 0 {
			// The list ends at a zero-length item, which is the terminator and not
			// a malformed record.
			break
		}
		if itemSize < 3 || offset+itemSize > len(list) {
			f.Warnings = append(f.Warnings,
				fmt.Sprintf("shell item at %d declares %d bytes, %d remain", offset, itemSize, len(list)-offset))
			break
		}

		if segment := f.parseShellItem(list[offset : offset+itemSize]); segment != "" {
			segments = append(segments, segment)
		}
		offset += itemSize
	}

	f.TargetPath = joinSegments(segments)
}

// joinSegments assembles the path.
//
// A volume segment anchors it: everything before a drive root is shell namespace
// — "My Computer", "Desktop" — and prefixing a file system path with it produces
// "My Computer\D:\Hunt\...", which matches nothing and agrees with no other
// record of the same path. Where there is no volume item the segments are kept as
// they are, and the result is a namespace path rather than a file system one:
// that is what the link actually names, and LinkInfo's own path is the column to
// read beside it.
//
// A volume segment already ends in a separator, which is why the join cannot
// simply put one between every pair.
func joinSegments(segments []string) string {
	for i := len(segments) - 1; i >= 0; i-- {
		if isDriveRoot(segments[i]) || isAddress(segments[i]) {
			segments = segments[i:]
			break
		}
	}

	var b strings.Builder
	for _, segment := range segments {
		if b.Len() > 0 && !strings.HasSuffix(b.String(), `\`) {
			b.WriteString(`\`)
		}
		b.WriteString(segment)
	}
	return b.String()
}

// isAddress reports a URI segment. It anchors the path for the same reason a
// drive root does: the shell folder it hangs under names no part of the target.
func isAddress(segment string) bool {
	return strings.Contains(segment, "://")
}

// isDriveRoot reports a volume item's name: a drive letter, a colon and a
// separator.
func isDriveRoot(segment string) bool {
	return len(segment) == 3 && segment[1] == ':' && segment[2] == '\\'
}

// parseShellItem names one item, or returns "" for a kind this does not read.
func (f *File) parseShellItem(item []byte) string {
	class := item[itemClassOffset]
	switch {
	case class == classRootFolder, class == classShellFolder:
		// The identifier sits after the class byte and a sort-order byte.
		if len(item) < 4+16 {
			return ""
		}
		id := winguid.At(item, 4).String()
		if name, ok := shellFolderNames[id]; ok {
			return name
		}
		return "{" + id + "}"

	case class == classVolume:
		// A drive letter, stored with its trailing separator: "C:\".
		return trimNUL(string(item[3:]))

	case class == classURI:
		return uriOf(item)

	case class&classFileMask == classFileEntry:
		return f.parseFileEntry(item)
	}
	return ""
}

// uriOf reads the address out of a URI shell item.
//
// Two bytes of size, the class, a flags byte, then the length of an optional
// extra block, and the address as UTF-16 after it. Measured across the links on
// one host the extra length is zero and the address begins at byte 8; it is read
// from the field rather than assumed so a link that carries the block does not
// return the block instead of the address.
func uriOf(item []byte) string {
	const addressOffset = 8
	if len(item) < addressOffset {
		return ""
	}
	extra := int(binary.LittleEndian.Uint32(item[4:]))
	if extra < 0 || addressOffset+extra >= len(item) {
		return ""
	}
	return decodeUTF16(item[addressOffset+extra:])
}

// parseFileEntry reads one path component and, where the item carries it, the
// target's MFT position.
//
// The long name is preferred over the primary one: the primary is the 8.3 name
// on a volume that generates them, so a path built from it reads "PROGRA~1"
// where the target was "Program Files".
func (f *File) parseFileEntry(item []byte) string {
	if len(item) <= itemPrimaryNameOffset {
		return ""
	}

	// Each file entry clears what the one before it recorded, so only the last —
	// the target itself — can leave an MFT reference behind. Carrying the previous
	// value forward is not a small error: the item before the target is the
	// directory holding it, so a target with no reference of its own inherited the
	// folder's. Measured against JLECmd and the live file system, all 52 rows where
	// the two tools disagreed were this, and the number Tyto reported was the
	// parent directory's entry every time. Joining that to mft_parser lands on the
	// wrong object with nothing saying so.
	f.MFTEntryNumber, f.MFTSequenceNumber, f.HasMFTReference = 0, 0, false

	name := ""
	if item[itemClassOffset]&fileEntryUnicode != 0 {
		name = decodeUTF16(item[itemPrimaryNameOffset:])
	} else {
		name = trimNUL(string(item[itemPrimaryNameOffset:]))
	}

	// The last two bytes of the item are the offset of its first extension block,
	// which is how the block is found without having to know how long the name
	// before it was.
	extensionOffset := int(binary.LittleEndian.Uint16(item[len(item)-2:]))
	if extensionOffset < itemPrimaryNameOffset || extensionOffset+8 > len(item) {
		return name
	}
	block := item[extensionOffset:]
	if binary.LittleEndian.Uint32(block[4:]) != beefFileEntryExtension {
		return name
	}
	if longName := f.readFileEntryExtension(block); longName != "" {
		return longName
	}
	return name
}

// readFileEntryExtension reads a 0xBEEF0004 block: the MFT reference and the
// long name.
//
// The layout grows with the block's version, and the version is the only thing
// that says where the name starts — there is no offset to it. Version 3 is XP,
// 7 is Vista, 8 is Windows 7, 9 is Windows 8.1 and later.
func (f *File) readFileEntryExtension(block []byte) string {
	if len(block) < 18 {
		return ""
	}
	version := binary.LittleEndian.Uint16(block[2:])

	at := 18
	if version >= 7 {
		// A 16-byte run whose middle eight bytes are the target's file reference:
		// six bytes of MFT entry number and two of sequence number.
		if len(block) < 36 {
			return ""
		}
		reference := binary.LittleEndian.Uint64(block[20:])
		entry := reference & 0x0000FFFFFFFFFFFF
		if entry != 0 {
			f.MFTEntryNumber = entry
			f.MFTSequenceNumber = uint16(reference >> 48)
			f.HasMFTReference = true
		}
		at = 36
	}
	// Versions 8 and 9 each inserted four more bytes ahead of the name. Missing
	// them does not fail, it silently lands the decode on the padding after the
	// string: every one of the 219 links measured is version 9, and the long name
	// came back empty for all of them, so the path was built from 8.3 primary
	// names — "MICROS~1\AUTODG~1.XML" where the target was
	// "Microsoft\AutoD.giangnt34@msb.com.vn.xml".
	if version >= 9 {
		at += 4
	}
	if version >= 8 {
		at += 4
	}
	if version >= 3 {
		// A localized-name size the name is written after.
		at += 2
	}
	if at >= len(block) {
		return ""
	}
	return decodeUTF16(block[at:])
}

// summaryInformationFMTID is the property set PKEY_Title belongs to, in the byte
// order a GUID is stored in.
var summaryInformationFMTID = [16]byte{
	0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10,
	0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
}

const (
	propertyStoreVersion = 0x53505331 // "1PSP"
	pidTitle             = 2
	vtLPWSTR             = 0x001F
)

// readPropertyStoreBlock pulls PKEY_Title out of a serialized property store.
//
// Only the title is read, and only from the one property set that holds it. A
// custom destinations entry's title is the text the jump list menu showed —
// "Start Capture", "New Private Window" — which is the difference between
// knowing an application defined a task and knowing which task.
func (f *File) readPropertyStoreBlock(block []byte) {
	// The store follows the block's own 8-byte header.
	if len(block) < 8 {
		return
	}
	store := block[8:]

	for at := 0; at+8 <= len(store); {
		size := int(binary.LittleEndian.Uint32(store[at:]))
		if size < 8 {
			// A zero-length storage block terminates the store.
			return
		}
		if at+size > len(store) {
			f.Warnings = append(f.Warnings,
				fmt.Sprintf("property storage declares %d bytes, %d remain", size, len(store)-at))
			return
		}
		if binary.LittleEndian.Uint32(store[at+4:]) == propertyStoreVersion && at+28 <= len(store) {
			if [16]byte(store[at+8:at+24]) == summaryInformationFMTID {
				f.readIntegerNamedProperties(store[at+24 : at+size])
			}
		}
		at += size
	}
}

// readIntegerNamedProperties walks the properties of one storage block, looking
// for the title.
func (f *File) readIntegerNamedProperties(properties []byte) {
	for at := 0; at+13 <= len(properties); {
		size := int(binary.LittleEndian.Uint32(properties[at:]))
		if size < 13 || at+size > len(properties) {
			return
		}
		id := binary.LittleEndian.Uint32(properties[at+4:])
		// properties[at+8] is a reserved byte; the typed value starts after it.
		valueType := binary.LittleEndian.Uint16(properties[at+9:])

		if id == pidTitle && valueType == vtLPWSTR && at+17 <= len(properties) {
			// A VT_LPWSTR is a character count and then the string.
			chars := int(binary.LittleEndian.Uint32(properties[at+13:]))
			start := at + 17
			end := start + chars*2
			if chars > 0 && end <= len(properties) {
				f.Title = decodeUTF16(properties[start:end])
				return
			}
		}
		at += size
	}
}
