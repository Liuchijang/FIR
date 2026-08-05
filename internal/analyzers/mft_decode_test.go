package analyzers

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

// filetime2020 is 2020-01-01T00:00:00Z expressed as a Windows FILETIME.
const filetime2020 = 132223104000000000

func utf16Bytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

type attrSpec struct {
	typ         uint32
	nonResident bool
	name        string
	content     []byte
	// nonResidentSizes, when nonResident is set, supplies allocated/real size at
	// attribute offsets 40 and 48.
	allocated, realSize uint64
}

func buildAttr(t *testing.T, spec attrSpec) []byte {
	t.Helper()

	nameBytes := utf16Bytes(spec.name)
	header := 24
	nameOff := header
	contentOff := nameOff + len(nameBytes)

	size := contentOff + len(spec.content)
	if spec.nonResident && size < 56 {
		size = 56
	}
	if pad := size % 8; pad != 0 {
		size += 8 - pad
	}

	attr := make([]byte, size)
	binary.LittleEndian.PutUint32(attr[0:4], spec.typ)
	binary.LittleEndian.PutUint32(attr[4:8], uint32(size))
	if spec.nonResident {
		attr[8] = 1
		binary.LittleEndian.PutUint64(attr[40:48], spec.allocated)
		binary.LittleEndian.PutUint64(attr[48:56], spec.realSize)
	}
	if len(nameBytes) > 0 {
		attr[9] = byte(len(nameBytes) / 2)
		binary.LittleEndian.PutUint16(attr[10:12], uint16(nameOff))
		copy(attr[nameOff:], nameBytes)
	}
	if !spec.nonResident {
		binary.LittleEndian.PutUint32(attr[16:20], uint32(len(spec.content)))
		binary.LittleEndian.PutUint16(attr[20:22], uint16(contentOff))
		copy(attr[contentOff:], spec.content)
	}
	return attr
}

func buildStandardInfo(created, modified, mftModified, accessed uint64) []byte {
	content := make([]byte, 48)
	binary.LittleEndian.PutUint64(content[0:8], created)
	binary.LittleEndian.PutUint64(content[8:16], modified)
	binary.LittleEndian.PutUint64(content[16:24], mftModified)
	binary.LittleEndian.PutUint64(content[24:32], accessed)
	return content
}

type fileNameSpec struct {
	parentRef      uint64
	parentSequence uint16
	name           string
	namespace      byte
	directory      bool
	allocated      uint64
	realSize       uint64
	times          uint64
}

func buildFileName(spec fileNameSpec) []byte {
	nameBytes := utf16Bytes(spec.name)
	content := make([]byte, 66+len(nameBytes))

	ref := spec.parentRef | uint64(spec.parentSequence)<<48
	binary.LittleEndian.PutUint64(content[0:8], ref)
	for _, off := range []int{8, 16, 24, 32} {
		binary.LittleEndian.PutUint64(content[off:off+8], spec.times)
	}
	binary.LittleEndian.PutUint64(content[40:48], spec.allocated)
	binary.LittleEndian.PutUint64(content[48:56], spec.realSize)
	if spec.directory {
		binary.LittleEndian.PutUint32(content[56:60], 0x10000000)
	}
	content[64] = byte(len(nameBytes) / 2)
	content[65] = spec.namespace
	copy(content[66:], nameBytes)
	return content
}

func buildRecord(t *testing.T, sequence, hardLinks uint16, flags uint16, attrs ...[]byte) []byte {
	t.Helper()

	const attrStart = 56
	record := make([]byte, mftRecordSize)
	copy(record[0:4], "FILE")
	binary.LittleEndian.PutUint16(record[16:18], sequence)
	binary.LittleEndian.PutUint16(record[18:20], hardLinks)
	binary.LittleEndian.PutUint16(record[20:22], attrStart)
	binary.LittleEndian.PutUint16(record[22:24], flags)

	off := attrStart
	for _, attr := range attrs {
		if off+len(attr) > len(record) {
			t.Fatalf("attributes exceed record size")
		}
		copy(record[off:], attr)
		off += len(attr)
	}
	binary.LittleEndian.PutUint32(record[off:off+4], 0xFFFFFFFF)
	return record
}

func TestParseReference(t *testing.T) {
	ref, seq := parseReference(0x0007_0000_0000_002A)
	if ref != 0x2A {
		t.Errorf("ref = %#x, want 0x2a", ref)
	}
	if seq != 7 {
		t.Errorf("sequence = %d, want 7", seq)
	}
}

func TestUTF16LEString(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"plain", utf16Bytes("notepad.exe"), "notepad.exe"},
		{"stops at NUL", append(utf16Bytes("abc"), 0, 0, 'X', 0), "abc"},
		{"non-BMP surrogate pair", utf16Bytes("a\U0001F600b"), "a\U0001F600b"},
		{"empty", nil, ""},
		{"odd trailing byte ignored", append(utf16Bytes("ab"), 0x41), "ab"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := utf16LEString(tc.data); got != tc.want {
				t.Errorf("utf16LEString() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNTFSFiletimeString(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
		want  string
	}{
		{"zero", 0, ""},
		{"below windows epoch", 1000, ""},
		{"exact epoch", ntfsWindowsEpochNs, "1970-01-01T00:00:00Z"},
		{"known date", filetime2020, "2020-01-01T00:00:00Z"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ntfsFiletimeString(tc.value); got != tc.want {
				t.Errorf("ntfsFiletimeString(%d) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestNamespaceLabelAndRank(t *testing.T) {
	labels := map[byte]string{0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32+DOS", 9: "Unknown(9)"}
	for ns, want := range labels {
		if got := namespaceLabel(ns); got != want {
			t.Errorf("namespaceLabel(%d) = %q, want %q", ns, got, want)
		}
	}
	// Win32+DOS outranks Win32, which outranks POSIX, which outranks bare DOS.
	if !(namespaceRank(3) > namespaceRank(1) && namespaceRank(1) > namespaceRank(0) && namespaceRank(0) > namespaceRank(2)) {
		t.Errorf("namespace ranking order broken: 3=%d 1=%d 0=%d 2=%d",
			namespaceRank(3), namespaceRank(1), namespaceRank(0), namespaceRank(2))
	}
	if namespaceRank(9) != 0 {
		t.Errorf("namespaceRank(9) = %d, want 0", namespaceRank(9))
	}
}

func TestFileExtension(t *testing.T) {
	tests := []struct {
		name        string
		isDirectory bool
		want        string
	}{
		{"notepad.EXE", false, ".exe"},
		{"archive.tar.gz", false, ".gz"},
		{"noext", false, ""},
		{"trailing.", false, ""},
		{"Windows", true, ""},
		{"dir.with.dots", true, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := fileExtension(tc.name, tc.isDirectory); got != tc.want {
				t.Errorf("fileExtension(%q, %v) = %q, want %q", tc.name, tc.isDirectory, got, tc.want)
			}
		})
	}
}

func TestResidentContent(t *testing.T) {
	attr := buildAttr(t, attrSpec{typ: attrTypeStandardInformation, content: []byte("hello")})
	content, ok := residentContent(attr)
	if !ok {
		t.Fatal("residentContent() ok = false, want true")
	}
	if string(content) != "hello" {
		t.Errorf("content = %q, want %q", content, "hello")
	}

	if _, ok := residentContent(buildAttr(t, attrSpec{typ: attrTypeData, nonResident: true})); ok {
		t.Error("residentContent() on a non-resident attribute should report false")
	}
	if _, ok := residentContent(make([]byte, 8)); ok {
		t.Error("residentContent() on a truncated attribute should report false")
	}
}

func TestAttributeName(t *testing.T) {
	named := buildAttr(t, attrSpec{typ: attrTypeData, name: "Zone.Identifier", content: []byte("x")})
	if got := attributeName(named); got != "Zone.Identifier" {
		t.Errorf("attributeName() = %q, want %q", got, "Zone.Identifier")
	}
	unnamed := buildAttr(t, attrSpec{typ: attrTypeData, content: []byte("x")})
	if got := attributeName(unnamed); got != "" {
		t.Errorf("attributeName() on unnamed attribute = %q, want empty", got)
	}
	if got := attributeName(make([]byte, 4)); got != "" {
		t.Errorf("attributeName() on truncated attribute = %q, want empty", got)
	}
}

func TestParseFileNameAttribute(t *testing.T) {
	content := buildFileName(fileNameSpec{
		parentRef:      5,
		parentSequence: 3,
		name:           "report.docx",
		namespace:      1,
		allocated:      4096,
		realSize:       3000,
		times:          filetime2020,
	})

	fn, ok := parseFileNameAttribute(content)
	if !ok {
		t.Fatal("parseFileNameAttribute() ok = false, want true")
	}
	if fn.ParentRef != 5 || fn.ParentSequence != 3 {
		t.Errorf("parent = (%d, %d), want (5, 3)", fn.ParentRef, fn.ParentSequence)
	}
	if fn.Name != "report.docx" {
		t.Errorf("Name = %q, want %q", fn.Name, "report.docx")
	}
	if fn.Namespace != 1 {
		t.Errorf("Namespace = %d, want 1", fn.Namespace)
	}
	if fn.Allocated != 4096 || fn.RealSize != 3000 {
		t.Errorf("sizes = (%d, %d), want (4096, 3000)", fn.Allocated, fn.RealSize)
	}
	if fn.Directory {
		t.Error("Directory = true, want false")
	}
	if fn.Created != "2020-01-01T00:00:00Z" {
		t.Errorf("Created = %q, want 2020-01-01T00:00:00Z", fn.Created)
	}

	if _, ok := parseFileNameAttribute(make([]byte, 65)); ok {
		t.Error("parseFileNameAttribute() on short content should report false")
	}

	// A name length that runs past the buffer must be rejected, not read out of bounds.
	truncated := buildFileName(fileNameSpec{name: "abc", namespace: 1})
	truncated[64] = 200
	if _, ok := parseFileNameAttribute(truncated); ok {
		t.Error("parseFileNameAttribute() with overlong name length should report false")
	}
}

func TestParseMFTRecordResidentFile(t *testing.T) {
	record := buildRecord(t, 4, 1, 0x0001,
		buildAttr(t, attrSpec{
			typ:     attrTypeStandardInformation,
			content: buildStandardInfo(filetime2020, filetime2020, filetime2020, filetime2020),
		}),
		buildAttr(t, attrSpec{
			typ: attrTypeFileName,
			content: buildFileName(fileNameSpec{
				parentRef: 5, parentSequence: 5, name: "notes.txt", namespace: 1, times: filetime2020,
			}),
		}),
		buildAttr(t, attrSpec{typ: attrTypeData, content: []byte("body-bytes")}),
	)

	row, ok, err := parseMFTRecord(record, 42)
	if err != nil {
		t.Fatalf("parseMFTRecord() error = %v", err)
	}
	if !ok {
		t.Fatal("parseMFTRecord() ok = false, want true")
	}

	if row.RecordNumber != 42 || row.Sequence != 4 || row.HardLinkCount != 1 {
		t.Errorf("header = (%d, %d, %d), want (42, 4, 1)", row.RecordNumber, row.Sequence, row.HardLinkCount)
	}
	if !row.InUse || row.IsDirectory {
		t.Errorf("InUse = %v, IsDirectory = %v, want true/false", row.InUse, row.IsDirectory)
	}
	if row.Name != "notes.txt" || row.Extension != ".txt" {
		t.Errorf("Name/Extension = %q/%q, want notes.txt/.txt", row.Name, row.Extension)
	}
	if row.NameNamespace != "Win32" {
		t.Errorf("NameNamespace = %q, want Win32", row.NameNamespace)
	}
	if row.ParentRef != 5 || row.ParentSequence != 5 {
		t.Errorf("parent = (%d, %d), want (5, 5)", row.ParentRef, row.ParentSequence)
	}
	if !row.ResidentData || !row.UnnamedDataStream || row.HasAlternateData {
		t.Errorf("data flags = resident %v, unnamed %v, alternate %v; want true/true/false",
			row.ResidentData, row.UnnamedDataStream, row.HasAlternateData)
	}
	if row.RealSize != int64(len("body-bytes")) || row.Allocated != int64(len("body-bytes")) {
		t.Errorf("sizes = (%d, %d), want (%d, %d)", row.Allocated, row.RealSize, len("body-bytes"), len("body-bytes"))
	}
	if row.SICreated != "2020-01-01T00:00:00Z" || row.FNCreated != "2020-01-01T00:00:00Z" {
		t.Errorf("timestamps = SI %q, FN %q", row.SICreated, row.FNCreated)
	}
}

func TestParseMFTRecordNonResidentWithADSAndShortName(t *testing.T) {
	record := buildRecord(t, 1, 2, 0x0003,
		buildAttr(t, attrSpec{
			typ: attrTypeFileName,
			content: buildFileName(fileNameSpec{
				parentRef: 5, name: "LongDirectoryName", namespace: 1, directory: true,
			}),
		}),
		buildAttr(t, attrSpec{
			typ: attrTypeFileName,
			content: buildFileName(fileNameSpec{
				parentRef: 5, name: "LONGDI~1", namespace: 2, directory: true,
			}),
		}),
		buildAttr(t, attrSpec{typ: attrTypeData, nonResident: true, allocated: 8192, realSize: 5000}),
		buildAttr(t, attrSpec{typ: attrTypeData, name: "Zone.Identifier", content: []byte("z")}),
	)

	row, ok, err := parseMFTRecord(record, 7)
	if err != nil {
		t.Fatalf("parseMFTRecord() error = %v", err)
	}
	if !ok {
		t.Fatal("parseMFTRecord() ok = false, want true")
	}

	if row.Name != "LongDirectoryName" {
		t.Errorf("Name = %q, want the Win32 name LongDirectoryName", row.Name)
	}
	if row.ShortName != "LONGDI~1" {
		t.Errorf("ShortName = %q, want LONGDI~1", row.ShortName)
	}
	if !row.IsDirectory {
		t.Error("IsDirectory = false, want true")
	}
	if row.Extension != "" {
		t.Errorf("Extension = %q, want empty for a directory", row.Extension)
	}
	if !row.HasAlternateData {
		t.Error("HasAlternateData = false, want true")
	}
	if row.Allocated != 8192 || row.RealSize != 5000 {
		t.Errorf("sizes = (%d, %d), want (8192, 5000)", row.Allocated, row.RealSize)
	}
	if row.ResidentData {
		t.Error("ResidentData = true, want false for a non-resident $DATA")
	}
}

func TestParseMFTRecordRejectsNonFileSignature(t *testing.T) {
	record := make([]byte, mftRecordSize)
	copy(record[0:4], "BAAD")
	if _, ok, err := parseMFTRecord(record, 1); ok || err != nil {
		t.Errorf("parseMFTRecord(BAAD) = ok %v, err %v; want false, nil", ok, err)
	}
	if _, ok, err := parseMFTRecord(make([]byte, 8), 1); ok || err != nil {
		t.Errorf("parseMFTRecord(short) = ok %v, err %v; want false, nil", ok, err)
	}
}

func TestParseMFTRecordRejectsBadAttributeLength(t *testing.T) {
	record := buildRecord(t, 1, 1, 0x0001,
		buildAttr(t, attrSpec{typ: attrTypeData, content: []byte("x")}),
	)
	// Zero-length attribute would loop forever; oversized would read past the record.
	binary.LittleEndian.PutUint32(record[60:64], 0)
	if _, _, err := parseMFTRecord(record, 3); err == nil {
		t.Error("parseMFTRecord() with zero attribute length should return an error")
	}

	binary.LittleEndian.PutUint32(record[60:64], uint32(mftRecordSize+64))
	if _, _, err := parseMFTRecord(record, 3); err == nil {
		t.Error("parseMFTRecord() with oversized attribute length should return an error")
	}
}

func TestParseMFTRecordUnnamedRecordFallsBackToRecordNumber(t *testing.T) {
	record := buildRecord(t, 1, 1, 0x0001,
		buildAttr(t, attrSpec{typ: attrTypeData, content: []byte("x")}),
	)
	row, ok, err := parseMFTRecord(record, 99)
	if err != nil || !ok {
		t.Fatalf("parseMFTRecord() = ok %v, err %v", ok, err)
	}
	if row.Name != "record_99" {
		t.Errorf("Name = %q, want record_99", row.Name)
	}
}

func TestSelectBestFileNames(t *testing.T) {
	win32 := fileNameAttribute{Name: "LongName.txt", Namespace: 1}
	dos := fileNameAttribute{Name: "LONGNA~1.TXT", Namespace: 2}

	best, short, ok := selectBestFileNames([]fileNameAttribute{dos, win32})
	if !ok {
		t.Fatal("selectBestFileNames() ok = false, want true")
	}
	if best.Name != win32.Name {
		t.Errorf("best = %q, want %q", best.Name, win32.Name)
	}
	if short.Name != dos.Name {
		t.Errorf("short = %q, want %q", short.Name, dos.Name)
	}

	if _, _, ok := selectBestFileNames(nil); ok {
		t.Error("selectBestFileNames(nil) ok = true, want false")
	}
}

func TestResolveMFTPath(t *testing.T) {
	records := map[mftKey]mftRecordRow{
		{Drive: "C", Record: 5}:  {RecordNumber: 5, Name: "."},
		{Drive: "C", Record: 10}: {RecordNumber: 10, Name: "Windows", ParentRef: 5},
		{Drive: "C", Record: 11}: {RecordNumber: 11, Name: "System32", ParentRef: 10},
		{Drive: "C", Record: 12}: {RecordNumber: 12, Name: "cmd.exe", ParentRef: 11},
	}

	cache := map[mftKey]string{}
	if got := resolveMFTPath(records, cache, "C", 12); got != `\Windows\System32\cmd.exe` {
		t.Errorf("resolveMFTPath() = %q, want \\Windows\\System32\\cmd.exe", got)
	}
	if got := resolveMFTPath(records, cache, "C", 5); got != `\` {
		t.Errorf("resolveMFTPath(root) = %q, want \\", got)
	}
	if got := resolveMFTPath(records, cache, "C", 404); got != `\record_404` {
		t.Errorf("resolveMFTPath(missing) = %q, want \\record_404", got)
	}
	// Record numbers are only unique per volume, so a different drive must not hit
	// the cache populated above.
	if got := resolveMFTPath(records, cache, "D", 12); got != `\record_12` {
		t.Errorf("resolveMFTPath(other drive) = %q, want \\record_12", got)
	}
}

// A corrupt $MFT can contain a cyclic parent chain; resolving it must terminate
// rather than recurse until the stack overflows.
func TestResolveMFTPathCyclicParentChain(t *testing.T) {
	records := map[mftKey]mftRecordRow{
		{Drive: "C", Record: 20}: {RecordNumber: 20, Name: "a", ParentRef: 21},
		{Drive: "C", Record: 21}: {RecordNumber: 21, Name: "b", ParentRef: 20},
	}

	done := make(chan string, 1)
	go func() { done <- resolveMFTPath(records, map[mftKey]string{}, "C", 20) }()

	select {
	case got := <-done:
		if got == "" {
			t.Error("resolveMFTPath() returned an empty path")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resolveMFTPath() did not terminate on a cyclic parent chain")
	}
}
