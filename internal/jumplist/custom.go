package jumplist

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

// lnkSignature is a shell link's first twenty bytes: the fixed header length
// 0x4C followed by the link class identifier. Nothing in a custom destinations
// file records where each embedded LNK starts or how long it is, so the only way
// to find them is to look for this.
var lnkSignature = []byte{
	0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
}

// footerSignature ends each category chunk.
var footerSignature = []byte{0xAB, 0xFB, 0xBF, 0xBA}

// minCategoryBytes is the size below which a chunk cannot hold a category header
// and a link. The first chunk of a real file is the 24-byte file header, which
// this drops.
const minCategoryBytes = 30

// maxCategoryHeaderType is the plausibility gate on a chunk's header.
//
// HeaderType decides whether a category name follows it, so it is a small
// enumeration: across 55 real files the value was 0 in 39 chunks and 2 in 11.
// The remaining five held 7209061, 7667825 and the like — a chunk whose start is
// not a header at all, because the footer that ended the chunk before it was
// data rather than a terminator. Their links still carve correctly; it is only
// the header fields that must not be reported as measurements.
const maxCategoryHeaderType = 0xFF

// Custom is a parsed customDestinations-ms jump list: the pinned and
// application-defined entries, as opposed to the recently-used ones.
type Custom struct {
	AppID      string
	Categories []Category
	Warnings   []string
}

// Category is one chunk: a jump list section such as an application's task list
// or the items a user pinned, holding one LNK per item.
type Category struct {
	// Offset is where the chunk begins in the file, so a finding can be pointed
	// back at the bytes it came from.
	Offset int

	// Rank orders the categories. JLECmd reads these four bytes as a float and
	// this reads them as the integer they are: across 58 category chunks on a
	// real host the field held 4, 1, 3 or 2 in 49 of them, and every one of the 58
	// read as the float 0.0 — the value JLECmd prints for the first is the
	// denormal 4e-45, which is the bit pattern 3 rendered in the wrong type.
	Rank       uint32
	HeaderType uint32
	Name       string
	Lnks       [][]byte

	// Terminated reports whether the chunk ended at a footer. A chunk that did
	// not is the tail of a file still being written.
	Terminated bool

	// HeaderParsed reports whether Rank, HeaderType and Name were read. They are
	// not read from an unterminated tail: that chunk begins wherever the file was
	// cut off, so its first twenty bytes need not be a category header at all. On
	// a real host the 27 .temp tails produced Rank values of 5373966 and 5373967 —
	// data being read as a header — while the finished chunks beside them held 1
	// to 4. The links carved out of the tail are unaffected and are the point of
	// reading it.
	HeaderParsed bool
}

// LnkCount totals the embedded links.
func (c *Custom) LnkCount() int {
	n := 0
	for _, category := range c.Categories {
		n += len(category.Lnks)
	}
	return n
}

// OpenCustom reads and parses a customDestinations-ms file.
func OpenCustom(path string) (*Custom, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCustom(data, AppIDFromFileName(path))
}

// ParseCustom parses a customDestinations-ms file already in memory.
//
// The file is split at every footer, not just the one at the end. 11 of the 28
// custom destination files on one real host carried two to four footers, and a
// parser that looks only at the tail gets the length of the last link in each
// chunk but the first wrong.
//
// A missing footer is a warning, not a rejection, and that is a deliberate
// departure from JLECmd — which throws "Invalid signature (footer missing)" when
// the last four bytes are not the footer. Windows writes these files by way of a
// .temp beside them, and on that same host the 27 leftover .temp files held 155
// embedded links against 120 in the 28 finished files. Refusing them discards
// more evidence than it protects.
func ParseCustom(data []byte, appID string) (*Custom, error) {
	custom := &Custom{AppID: appID}
	if len(data) == 0 {
		return nil, fmt.Errorf("file is empty")
	}

	chunks, tail := splitAtFooters(data)
	for _, chunk := range chunks {
		if len(chunk.body) <= minCategoryBytes {
			continue
		}
		custom.Categories = append(custom.Categories, parseCategory(chunk.body, chunk.offset, true))
	}

	if tail.body != nil {
		if bytes.Contains(tail.body, lnkSignature) {
			custom.Categories = append(custom.Categories, parseCategory(tail.body, tail.offset, false))
			custom.Warnings = append(custom.Warnings,
				fmt.Sprintf("%d bytes after the last footer held links; the file was still being written", len(tail.body)))
		} else if len(chunks) == 0 {
			return nil, fmt.Errorf("no footer and no embedded link found")
		}
	}

	return custom, nil
}

type chunk struct {
	offset int
	body   []byte
}

// splitAtFooters cuts the file into footer-terminated chunks, returning whatever
// followed the last footer separately.
func splitAtFooters(data []byte) ([]chunk, chunk) {
	var chunks []chunk
	start := 0
	for start < len(data) {
		i := bytes.Index(data[start:], footerSignature)
		if i < 0 {
			break
		}
		end := start + i + len(footerSignature)
		chunks = append(chunks, chunk{offset: start, body: data[start:end]})
		start = end
	}
	if start < len(data) {
		return chunks, chunk{offset: start, body: data[start:]}
	}
	return chunks, chunk{}
}

// headerTypeOf returns the chunk's header type, or a value above the plausible
// range when the chunk has no header to read.
func headerTypeOf(body []byte, terminated bool) uint32 {
	if !terminated || len(body) < 16 {
		return maxCategoryHeaderType + 1
	}
	return binary.LittleEndian.Uint32(body[12:])
}

// parseCategory reads a chunk's header and carves out its links.
func parseCategory(body []byte, offset int, terminated bool) Category {
	category := Category{Offset: offset, Terminated: terminated}

	if headerType := headerTypeOf(body, terminated); headerType <= maxCategoryHeaderType {
		category.HeaderParsed = true
		category.Rank = binary.LittleEndian.Uint32(body[4:])
		category.HeaderType = headerType
		// Only a type 0 header names its category — "Tasks", "Recent", or whatever
		// the application called the section.
		if category.HeaderType == 0 && len(body) >= 18 {
			nameChars := int(binary.LittleEndian.Uint16(body[16:]))
			if end := 18 + nameChars*2; nameChars > 0 && end <= len(body) {
				category.Name = utf16String(body[18:end])
			}
		}
	}

	// A link runs to the start of the next one, and the last runs to the footer,
	// or to the end of the chunk when there is not one.
	limit := len(body)
	if terminated {
		limit -= len(footerSignature)
	}

	var starts []int
	for at := 0; at < limit; {
		i := bytes.Index(body[at:limit], lnkSignature)
		if i < 0 {
			break
		}
		starts = append(starts, at+i)
		at += i + 1
	}

	for i, start := range starts {
		end := limit
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		if end > start {
			category.Lnks = append(category.Lnks, body[start:end])
		}
	}

	return category
}
