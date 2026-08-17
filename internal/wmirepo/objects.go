// Package wmirepo carves WMI event-subscription persistence out of a collected
// OBJECTS.DATA.
//
// It reads the object store as bytes and does not walk the repository's real
// structure. That is deliberate, and it is the approach David Pany's
// PyWMIPersistenceFinder established and woanware/wmi-parser reimplemented: a
// structural reader needs the MAPPING*.MAP page tables to translate logical page
// numbers, INDEX.BTR to find objects by a hashed name, and the full class
// definition chain to interpret an instance's packed properties — thousands of
// lines, two hash algorithms across Windows versions, and a wrong MAPPING file
// silently yields a stale transaction.
//
// Scanning buys two things that pay for the imprecision. It needs only
// OBJECTS.DATA, and it finds records in pages the repository has already released,
// so a subscription an intruder deleted is still recoverable — which a live CIM
// query can never show.
//
// What it costs: a carve cannot prove a record is live rather than freed, and it
// reports what the bytes say rather than what WMI would answer. Treat the output
// as leads to confirm, not as an authoritative instance list.
//
// Stdlib-only, like internal/registryfile and internal/ntfs.
package wmirepo

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Result is everything one OBJECTS.DATA yielded.
type Result struct {
	Bindings  []Binding
	Filters   []Filter
	Consumers []Consumer
	// BytesScanned is what the caller asked for and what was actually read, so a
	// truncated or short file is visible in the output rather than looking like a
	// host with no subscriptions.
	BytesScanned int64
}

// Binding is a __FilterToConsumerBinding: the record that actually arms a
// subscription by naming one consumer and one filter.
//
// This is the primary finding. A filter alone fires nothing and a consumer alone
// runs nothing; the binding is the persistence.
type Binding struct {
	ConsumerType string
	ConsumerName string
	FilterName   string
	// Paired is false when only one side of the reference pair was found, which
	// happens in a partially overwritten record. Reported rather than dropped: half
	// a binding is still evidence that one existed.
	Paired bool
	Offset int64
}

// Filter is an __EventFilter instance: the WQL query that decides when a
// subscription fires.
type Filter struct {
	Namespace     string
	Name          string
	Query         string
	QueryLanguage string
	Offset        int64
}

// Consumer is an *EventConsumer instance — the action a subscription takes.
//
// Payload is the consumer's own strings in the order the record stores them,
// unlabelled on purpose. Which string is the command line, the script body or the
// template depends on the consumer subclass and on the property order in that
// machine's class definition, and this reader does not parse class definitions.
// Guessing a label would misattribute the most important cell in the row, so the
// strings are handed over as found.
type Consumer struct {
	Type    string
	Name    string
	Payload []string
	Offset  int64
}

// chunkSize and overlap bound the read.
//
// OBJECTS.DATA is tens to hundreds of megabytes and this runs on a live
// investigation host, so the file is streamed rather than read whole. The overlap
// has to exceed the longest record this cares about: a binding's two reference
// strings plus a filter's query, which is comfortably under 64 KiB even with a
// pathological WQL query.
const (
	chunkSize = 8 << 20
	overlap   = 64 << 10
)

var (
	// A binding stores its two references as readable object paths. The consumer
	// reference comes first because the repository lays a record's strings out in
	// property order and Consumer sorts before Filter.
	//
	// The name pattern is [^"]* rather than the [\w\s]* the C# reference
	// implementation uses. That difference matters in exactly the case this exists
	// for: \w\s excludes the dots, dashes and braces that appear in a name chosen
	// to blend into a system's own, so the narrow form drops the subscriptions most
	// worth finding.
	bindingPairRe = regexp.MustCompile(`(?s)([A-Za-z0-9_]{1,64}EventConsumer)\.Name="([^"]{0,400})"[\x00-\x20]{0,64}__EventFilter\.Name="([^"]{0,400})"`)

	// The unpaired forms, for records where only one reference survived.
	consumerRefRe = regexp.MustCompile(`([A-Za-z0-9_]{1,64}EventConsumer)\.Name="([^"]{0,400})"`)
	filterRefRe   = regexp.MustCompile(`__EventFilter\.Name="([^"]{0,400})"`)

	// Instance records begin with the class name as a NUL-terminated string. The
	// class *definitions* start the same way, which is why every hit is validated
	// against the strings that follow rather than accepted on the name alone.
	filterClassRe   = regexp.MustCompile(`__EventFilter\x00`)
	consumerClassRe = regexp.MustCompile(`([A-Za-z0-9_]{1,64}EventConsumer)\x00`)
)

// Scan carves subscriptions out of the OBJECTS.DATA at path.
func Scan(path string) (Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return Result{}, fmt.Errorf("open WMI object store: %w", err)
	}
	defer file.Close()

	return ScanReader(file)
}

// ScanReader is Scan over an already-open store, so a test can drive a synthetic
// one without touching the filesystem.
func ScanReader(r io.Reader) (Result, error) {
	var (
		result Result
		buf    = make([]byte, chunkSize+overlap)
		// Chunks overlap, so the same record is seen twice. Dedupe on absolute
		// offset rather than on content: two identical subscriptions in different
		// pages are two findings, and one of them may be the deleted copy.
		seenBinding  = map[int64]bool{}
		seenFilter   = map[int64]bool{}
		seenConsumer = map[int64]bool{}
		carry        int
		base         int64
	)

	for {
		n, err := io.ReadFull(r, buf[carry:])
		filled := carry + n
		if filled == 0 {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			if err != nil {
				return result, fmt.Errorf("read WMI object store: %w", err)
			}
			break
		}

		window := buf[:filled]
		scanWindow(window, base, &result, seenBinding, seenFilter, seenConsumer)
		result.BytesScanned = base + int64(filled)

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return result, fmt.Errorf("read WMI object store: %w", err)
		}

		// Carry the tail forward so a record straddling the boundary is matched on
		// the next pass. base advances by only the consumed part.
		keep := overlap
		if filled < keep {
			keep = filled
		}
		copy(buf, window[filled-keep:])
		carry = keep
		base += int64(filled - keep)
	}

	sortResult(&result)
	result.Consumers = keepBoundConsumers(result.Consumers, result.Bindings)
	return result, nil
}

// keepBoundConsumers drops every carved consumer record that no binding refers to.
//
// Carving consumer instances on their own does not work well enough to ship: a
// clean Windows 10 host produced 26 candidates for one real consumer, because the
// class name appears in provider registrations, in class definitions, in localised
// amendment blocks, and beside binary that reads as short strings. The binding
// references, by contrast, are exact — they are stored as readable object paths and
// carry both the consumer's subclass and its name.
//
// So the binding list is used as the filter: a candidate survives only if some
// binding names it. That costs the unbound consumers, which is the right trade
// because a consumer no binding points at never fires. It does not cost the deleted
// ones — a deleted subscription's binding record is carved the same way a live one
// is, which is the whole reason for reading the file instead of asking WMI.
func keepBoundConsumers(candidates []Consumer, bindings []Binding) []Consumer {
	if len(candidates) == 0 || len(bindings) == 0 {
		return nil
	}

	wanted := make(map[string]bool, len(bindings))
	for _, b := range bindings {
		if b.ConsumerName != "" {
			wanted[strings.ToLower(b.ConsumerName)] = true
		}
	}
	if len(wanted) == 0 {
		return nil
	}

	kept := candidates[:0]
	for _, c := range candidates {
		if wanted[strings.ToLower(c.Name)] {
			kept = append(kept, c)
			continue
		}
		// The name can also sit in the payload rather than being picked as the name,
		// because property order varies by subclass.
		for _, field := range c.Payload {
			if wanted[strings.ToLower(field)] {
				kept = append(kept, c)
				break
			}
		}
	}
	return kept
}

func scanWindow(window []byte, base int64, result *Result, seenBinding, seenFilter, seenConsumer map[int64]bool) {
	// Bindings first, recording the byte span each paired match covered.
	//
	// The unpaired sweeps below then skip anything falling inside one of those
	// spans. Suppressing by *span* rather than by capture-group offset is the point:
	// keying on the group offsets reported each already-paired binding a second time
	// as a filter-only half, because the pair regex's third group starts at the
	// filter's name while the filter regex starts at the class name before it.
	var paired []span
	for _, m := range bindingPairRe.FindAllSubmatchIndex(window, -1) {
		at := base + int64(m[0])
		paired = append(paired, span{m[0], m[1]})
		if seenBinding[at] {
			continue
		}
		seenBinding[at] = true
		result.Bindings = append(result.Bindings, Binding{
			ConsumerType: string(window[m[2]:m[3]]),
			ConsumerName: string(window[m[4]:m[5]]),
			FilterName:   string(window[m[6]:m[7]]),
			Paired:       true,
			Offset:       at,
		})
	}

	for _, m := range consumerRefRe.FindAllSubmatchIndex(window, -1) {
		if within(paired, m[0]) {
			continue
		}
		at := base + int64(m[0])
		if seenBinding[at] {
			continue
		}
		seenBinding[at] = true
		result.Bindings = append(result.Bindings, Binding{
			ConsumerType: string(window[m[2]:m[3]]),
			ConsumerName: string(window[m[4]:m[5]]),
			Offset:       at,
		})
	}

	for _, m := range filterRefRe.FindAllSubmatchIndex(window, -1) {
		if within(paired, m[0]) {
			continue
		}
		at := base + int64(m[0])
		if seenBinding[at] {
			continue
		}
		seenBinding[at] = true
		result.Bindings = append(result.Bindings, Binding{
			FilterName: string(window[m[2]:m[3]]),
			Offset:     at,
		})
	}

	for _, m := range filterClassRe.FindAllIndex(window, -1) {
		at := base + int64(m[0])
		if seenFilter[at] {
			continue
		}
		filter, ok := readFilter(window, m[1])
		if !ok {
			continue
		}
		seenFilter[at] = true
		filter.Offset = at
		result.Filters = append(result.Filters, filter)
	}

	for _, m := range consumerClassRe.FindAllSubmatchIndex(window, -1) {
		at := base + int64(m[0])
		if seenConsumer[at] {
			continue
		}
		consumer, ok := readConsumer(string(window[m[2]:m[3]]), window, m[1])
		if !ok {
			continue
		}
		seenConsumer[at] = true
		consumer.Offset = at
		result.Consumers = append(result.Consumers, consumer)
	}
}

// span is a matched byte range within the current window.
type span struct{ start, end int }

func within(spans []span, at int) bool {
	for _, s := range spans {
		if at >= s.start && at < s.end {
			return true
		}
	}
	return false
}

// maxRecordStrings bounds how far past a class name the reader will walk. An
// instance's strings sit together; running further only collects the next record's.
const maxRecordStrings = 12

// classCheckFields is how many of a record's leading strings decide whether the hit
// is a class definition rather than an instance of that class.
//
// Scoped to the front deliberately. Checking all of maxRecordStrings rejected the
// one real __EventFilter instance on a clean Windows 10 host: reading twelve
// strings ran past the end of the instance into the *next* record's property table,
// found its type keywords, and concluded the instance was a definition. A
// definition declares its types immediately, so the front is where the answer is.
const classCheckFields = 4

// minRecordField is the shortest string treated as a record value.
//
// Binary regions are full of single printable bytes separated by NULs, and reading
// them as values produced consumer rows named "C" with a payload of ["F","F","4"].
// A one-character CIM string property is possible in theory; a run of them is
// always the object store's binary, so the reader stops at the first one.
const minRecordField = 2

// maxRecordSkip bounds how far past a class name readStrings will look for the start
// of the string heap, so a class name followed by nothing but binary cannot drag the
// reader into the next record's strings. The fixed property block ahead of the heap
// is a SID and a few flags — tens of bytes, not hundreds.
const maxRecordSkip = 256

// readFilter interprets the strings after an __EventFilter class name.
//
// The order on a real host is EventNamespace, Name, Query, QueryLanguage — the
// string-typed properties in the order the class declares them. Rather than trust
// position alone, the query and the language are recognised by shape, because a
// filter whose namespace or name happens to be absent would otherwise shift every
// remaining field by one and mislabel the query.
func readFilter(window []byte, from int) (Filter, bool) {
	fields := readStrings(window, from, maxRecordStrings)
	if len(fields) == 0 || isClassDefinition(fields) {
		return Filter{}, false
	}

	var filter Filter
	for _, field := range fields {
		switch {
		case filter.Query == "" && looksLikeQuery(field):
			filter.Query = field
		case filter.QueryLanguage == "" && isQueryLanguage(field):
			filter.QueryLanguage = field
		case filter.Namespace == "" && looksLikeNamespace(field):
			filter.Namespace = field
		case filter.Name == "" && isPlausibleName(field):
			filter.Name = field
		}
	}

	// A query is what makes the record a filter worth reporting. Without one this
	// is a class definition, a reference, or a record too damaged to read.
	if filter.Query == "" {
		return Filter{}, false
	}
	return filter, true
}

// readConsumer interprets the strings after an *EventConsumer class name.
func readConsumer(class string, window []byte, from int) (Consumer, bool) {
	fields := readStrings(window, from, maxRecordStrings)
	if len(fields) == 0 || isClassDefinition(fields) {
		return Consumer{}, false
	}

	// A provider registration names the consumer class inside an object path. It is
	// not an instance of the consumer, and reporting it as one puts a row per
	// consumer class on every clean machine.
	if strings.Contains(fields[0], `__Win32Provider.Name=`) || strings.Contains(fields[0], `\\.\`) {
		return Consumer{}, false
	}

	consumer := Consumer{Type: class}
	for _, field := range fields {
		if consumer.Name == "" && isPlausibleName(field) {
			consumer.Name = field
			continue
		}
		consumer.Payload = append(consumer.Payload, field)
	}
	if consumer.Name == "" && len(consumer.Payload) == 0 {
		return Consumer{}, false
	}
	return consumer, true
}

// readStrings reads a record's string heap: up to limit consecutive
// NUL-terminated printable strings.
//
// The asymmetry in how binary is treated is the whole of this function, and it
// comes from the record layout on a real host:
//
//	__EventFilter\0 │ 10 00 00 00 01 02 .. 20 02 00 00 │ root\cimv2\0\0 SCM Event Log Filter\0\0 ..
//	                └─ CreatorSID, a length-prefixed uint8[16] ─┘
//
// So binary *before* the first string is the record's fixed property block and is
// skipped, while binary *after* it means the heap has ended and everything past it
// belongs to the next record. Stopping at the first non-printable byte instead —
// which is what a fixture without a property block lets you get away with — found
// zero filters on a Windows 10 host that plainly had one.
func readStrings(window []byte, from, limit int) []string {
	var out []string
	i := from
	for len(out) < limit && i < len(window) && i-from < maxRecordSkip {
		for i < len(window) && window[i] == 0 {
			i++
		}
		if i >= len(window) {
			break
		}
		end := bytes.IndexByte(window[i:], 0)
		if end < 0 {
			break
		}
		field := window[i : i+end]
		i += end
		if len(field) < minRecordField || !isPrintableASCII(field) {
			if len(out) > 0 {
				break
			}
			continue
		}
		out = append(out, string(field))
	}
	return out
}

func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// cimTypeKeywords are the strings a class definition's property table is built
// from. Two or more of them following a class name means the hit is the definition
// rather than an instance of it.
var cimTypeKeywords = map[string]bool{
	"string": true, "boolean": true, "datetime": true, "object": true,
	"uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"sint8": true, "sint16": true, "sint32": true, "sint64": true,
	"real32": true, "real64": true, "char16": true,
	"NOT_NULL": true, "not_null": true, "CIMTYPE": true, "Association": true,
	"abstract": true, "AMENDMENT": true, "LOCALE": true, "Key": true, "key": true,
}

func isClassDefinition(fields []string) bool {
	if len(fields) > classCheckFields {
		fields = fields[:classCheckFields]
	}
	for _, field := range fields {
		if cimTypeKeywords[field] || strings.HasPrefix(field, "ref:") {
			return true
		}
	}
	return false
}

func looksLikeQuery(s string) bool {
	if len(s) < 10 {
		return false
	}
	lower := strings.ToLower(s)
	return strings.Contains(lower, "select ") || strings.Contains(lower, " from ") ||
		strings.HasPrefix(lower, "__instance") || strings.Contains(lower, " isa ")
}

func isQueryLanguage(s string) bool {
	return strings.EqualFold(s, "WQL") || strings.EqualFold(s, "SQL")
}

// looksLikeNamespace matches the WMI namespace form, e.g. root\cimv2 or
// ROOT\Subscription. Deliberately narrow: a false positive here steals the Name
// field.
func looksLikeNamespace(s string) bool {
	if len(s) < 4 || strings.Contains(s, " ") || strings.Contains(s, `"`) {
		return false
	}
	lower := strings.ToLower(s)
	return lower == "root" || strings.HasPrefix(lower, `root\`)
}

// isPlausibleName rejects the fields that are structurally something else. It is
// permissive about the name's own characters on purpose — an operator-hostile name
// full of punctuation is exactly what this has to keep.
func isPlausibleName(s string) bool {
	if s == "" || len(s) > 400 {
		return false
	}
	if cimTypeKeywords[s] || strings.HasPrefix(s, "ref:") {
		return false
	}
	if looksLikeQuery(s) || isQueryLanguage(s) || looksLikeNamespace(s) {
		return false
	}
	// A reference, not a name.
	return !strings.Contains(s, `.Name="`)
}

// sortResult puts the output in file order so two runs over the same store produce
// identical CSVs. Chunk overlap means matches are not otherwise appended in a
// stable order.
func sortResult(result *Result) {
	sort.SliceStable(result.Bindings, func(i, j int) bool {
		return result.Bindings[i].Offset < result.Bindings[j].Offset
	})
	sort.SliceStable(result.Filters, func(i, j int) bool {
		return result.Filters[i].Offset < result.Filters[j].Offset
	})
	sort.SliceStable(result.Consumers, func(i, j int) bool {
		return result.Consumers[i].Offset < result.Consumers[j].Offset
	})
}

// QueryFor returns the query of the filter a binding names, and whether one was
// found. A binding whose filter record is gone is still reported; the empty query
// says the filter did not survive, which is itself worth seeing.
func (r Result) QueryFor(filterName string) (string, bool) {
	if filterName == "" {
		return "", false
	}
	for _, filter := range r.Filters {
		if strings.EqualFold(filter.Name, filterName) {
			return filter.Query, true
		}
	}
	return "", false
}
