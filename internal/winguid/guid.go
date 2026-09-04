// Package winguid holds the Windows GUID as it appears inside a record, and the
// two things a DFIR reader wants out of one.
//
// It is shared rather than copied because both jump list DestList entries and a
// shell link's tracker block carry the same droid identifiers, and the version 1
// UUID arithmetic below is exactly the kind of thing that gets fixed on one side
// and left wrong on the other.
//
// stdlib only, like the parsers that use it.
package winguid

import (
	"encoding/binary"
	"fmt"
)

// GUID is a Windows GUID as it sits in a record: the first three fields are
// little-endian integers and the last eight bytes are in wire order.
type GUID [16]byte

// GregorianToFiletimeTicks is the distance between the two epochs a droid makes
// you cross: a version 1 UUID counts 100ns intervals from the start of the
// Gregorian calendar, 15 October 1582, and a FILETIME counts them from 1 January
// 1601. That is 6653 days, and converting to FILETIME rather than to a wall
// clock here means the value reaches the CSV through the same formatter as every
// other timestamp in the run. TestGregorianOffsetMatchesTheCalendar derives it.
const GregorianToFiletimeTicks = 6653 * 86400 * 10_000_000

func At(record []byte, offset int) GUID {
	var g GUID
	copy(g[:], record[offset:offset+16])
	return g
}

// IsZero reports the all-zero GUID, which is how an entry says it has no droid
// rather than by omitting the field.
func (g GUID) IsZero() bool {
	return g == GUID{}
}

func (g GUID) String() string {
	if g.IsZero() {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(g[0:]),
		binary.LittleEndian.Uint16(g[4:]),
		binary.LittleEndian.Uint16(g[6:]),
		g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15])
}

// MacAddress is the network card address a version 1 UUID is generated from,
// which sits in its last six bytes.
//
// It identifies the machine the item was opened on, and it survives the file
// being copied elsewhere — which is the whole reason the droid is worth
// carrying into the output.
//
// A node whose multicast bit is set is not a network card address and is not
// reported. RFC 4122 requires that bit on a node id generated at random, exactly
// so it can never be mistaken for an IEEE address, and Windows uses one when it
// has no adapter to read: 128 rows of one real run carried "ad:55:41:19:e4:e4",
// which named no machine and would have been chased as if it did. The locally
// administered bit is a different thing and is kept — a randomised Wi-Fi address
// or a virtual adapter is still the address that machine was using.
func (g GUID) MacAddress() string {
	if g.IsZero() || !g.isVersion1() {
		return ""
	}
	mac := g[10:16]
	if mac[0]&0x01 != 0 {
		return ""
	}
	var zero = true
	for _, b := range mac {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// CreatedFiletime is the timestamp embedded in a version 1 UUID, as a FILETIME.
//
// What it actually records is when the droid was generated, which is not the
// same thing as when the file was created — Eric Zimmerman's own testing found
// it tracking the machine's boot time. It is reported because it dates the
// droid, and callers must not present it as a file creation time.
//
// The version nibble is checked rather than masked away: a droid that is not a
// version 1 UUID has no timestamp in it, and forcing one out anyway produces a
// plausible-looking date from bytes that never encoded one.
func (g GUID) CreatedFiletime() (uint64, bool) {
	if g.IsZero() || !g.isVersion1() {
		return 0, false
	}
	timeHigh := binary.LittleEndian.Uint16(g[6:]) & 0x0FFF
	ticks := uint64(binary.LittleEndian.Uint32(g[0:])) |
		uint64(binary.LittleEndian.Uint16(g[4:]))<<32 |
		uint64(timeHigh)<<48
	if ticks < GregorianToFiletimeTicks {
		return 0, false
	}
	return ticks - GregorianToFiletimeTicks, true
}

func (g GUID) isVersion1() bool {
	return binary.LittleEndian.Uint16(g[6:])>>12 == 1
}
