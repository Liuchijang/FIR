package prefetch

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows 8 introduced a compressed Prefetch container and Windows 10 made it the
// norm: the file starts "MAM", a uint32 uncompressed size, then an Xpress Huffman
// stream. On a Windows 10 host 250 of 256 collected .pf files were compressed, so a
// reader that skips this step reads the container's magic as the record's version
// number and every field after it is noise.
//
// Decompression goes through ntdll rather than a Go implementation of Xpress
// Huffman. That is the same choice Eric Zimmerman's Prefetch library makes — his
// README's "you need at least Windows 8 for the decompression of Windows 10
// prefetch files to work" is that dependency showing through — and it costs nothing
// here: Tyto requires Windows 10 or later and already imports x/sys/windows
// unconditionally. The alternative is a few hundred lines of LZ77 plus Huffman
// decoding, which is a new place for a bug in a parser that reads attacker-supplied
// bytes.
var (
	ntdll                              = windows.NewLazySystemDLL("ntdll.dll")
	procRtlGetCompressionWorkSpaceSize = ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
	procRtlDecompressBufferEx          = ntdll.NewProc("RtlDecompressBufferEx")
)

// compressionFormatXpressHuff is COMPRESSION_FORMAT_XPRESS_HUFF.
const compressionFormatXpressHuff = 0x0004

// mamSignature opens a compressed container. The fourth byte is a format code; it
// is not validated because the only decoder available answers for all of them and
// RtlDecompressBufferEx reports its own disagreement.
const mamSignature = "MAM"

// mamHeaderSize is the signature plus the uncompressed size.
const mamHeaderSize = 8

// maxUncompressedSize bounds what a container may claim.
//
// The size comes from the file being parsed, so an absurd value is an allocation an
// attacker chose. A real .pf is tens to hundreds of kilobytes; 64 MiB is orders of
// magnitude of headroom and still refuses a 4 GiB claim.
const maxUncompressedSize = 64 << 20

// isCompressed reports whether raw is a MAM container.
func isCompressed(raw []byte) bool {
	return len(raw) >= mamHeaderSize && string(raw[:3]) == mamSignature
}

// decompress expands a MAM container, or returns raw unchanged when it is already a
// plain SCCA record.
func decompress(raw []byte) ([]byte, error) {
	if !isCompressed(raw) {
		return raw, nil
	}

	size := binary.LittleEndian.Uint32(raw[4:mamHeaderSize])
	if size == 0 {
		return nil, fmt.Errorf("compressed prefetch declares a zero uncompressed size")
	}
	if size > maxUncompressedSize {
		return nil, fmt.Errorf("compressed prefetch declares %d bytes uncompressed, over the %d limit", size, maxUncompressedSize)
	}
	payload := raw[mamHeaderSize:]
	if len(payload) == 0 {
		return nil, fmt.Errorf("compressed prefetch has a header but no payload")
	}

	var bufferWorkspace, fragmentWorkspace uint32
	status, _, _ := procRtlGetCompressionWorkSpaceSize.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafe.Pointer(&bufferWorkspace)),
		uintptr(unsafe.Pointer(&fragmentWorkspace)),
	)
	if status != 0 {
		return nil, fmt.Errorf("RtlGetCompressionWorkSpaceSize: NTSTATUS 0x%X", status)
	}

	out := make([]byte, size)
	workspace := make([]byte, bufferWorkspace)
	var finalSize uint32
	status, _, _ = procRtlDecompressBufferEx.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
		uintptr(unsafe.Pointer(&finalSize)),
		uintptr(unsafe.Pointer(&workspace[0])),
	)
	if status != 0 {
		return nil, fmt.Errorf("RtlDecompressBufferEx: NTSTATUS 0x%X", status)
	}
	// Trust the API's answer over the header's claim. A truncated file decompresses
	// to less than it advertised, and the trailing zeroes would otherwise be parsed
	// as structure.
	return out[:finalSize], nil
}
