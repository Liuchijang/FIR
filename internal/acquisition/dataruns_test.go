package acquisition

import "testing"

// run builds one data-run entry: header nibbles are (offSize<<4)|lenSize.
func run(lenBytes, offBytes []byte) []byte {
	header := byte(len(offBytes)<<4 | len(lenBytes))
	out := []byte{header}
	out = append(out, lenBytes...)
	return append(out, offBytes...)
}

func TestParseDataRunsSingleRun(t *testing.T) {
	runs, err := parseDataRuns(append(run([]byte{0x20}, []byte{0x10}), 0))
	if err != nil {
		t.Fatalf("parseDataRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(runs))
	}
	if runs[0].Length != 0x20 {
		t.Errorf("Length = %d, want 32", runs[0].Length)
	}
	if runs[0].LCN != 0x10 {
		t.Errorf("LCN = %d, want 16", runs[0].LCN)
	}
	if runs[0].Sparse {
		t.Error("Sparse = true, want false")
	}
}

// NTFS stores the run length unsigned; only the LCN offset is signed. A 200-cluster
// fragment encodes as the single byte 0xC8, and sign-extending it yields -56, which
// callers treat as end-of-runs and silently stop copying mid-file.
func TestParseDataRunsLengthIsUnsigned(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes []byte
		want  int64
	}{
		{"high bit set in one byte", []byte{0xC8}, 200},
		{"max single byte", []byte{0xFF}, 255},
		{"high bit set in two bytes", []byte{0x00, 0x80}, 0x8000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runs, err := parseDataRuns(append(run(tc.bytes, []byte{0x10}), 0))
			if err != nil {
				t.Fatalf("parseDataRuns() error = %v", err)
			}
			if len(runs) != 1 {
				t.Fatalf("got %d runs, want 1", len(runs))
			}
			if runs[0].Length != tc.want {
				t.Errorf("Length = %d, want %d", runs[0].Length, tc.want)
			}
		})
	}
}

// The LCN offset must stay signed so fragments can point backwards on disk.
func TestParseDataRunsOffsetStaysSigned(t *testing.T) {
	data := append(run([]byte{0x08}, []byte{0x00, 0x02}), run([]byte{0x08}, []byte{0xF0, 0xFF})...)
	runs, err := parseDataRuns(append(data, 0))
	if err != nil {
		t.Fatalf("parseDataRuns() error = %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("got %d runs, want 2", len(runs))
	}
	if runs[0].LCN != 0x200 {
		t.Errorf("first LCN = %d, want 512", runs[0].LCN)
	}
	if runs[1].LCN != 0x200-0x10 {
		t.Errorf("second LCN = %d, want %d (backward jump)", runs[1].LCN, 0x200-0x10)
	}
}

func TestParseDataRunsSparse(t *testing.T) {
	runs, err := parseDataRuns(append(run([]byte{0x10}, nil), 0))
	if err != nil {
		t.Fatalf("parseDataRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(runs))
	}
	if !runs[0].Sparse {
		t.Error("Sparse = false, want true")
	}
	if runs[0].Length != 0x10 {
		t.Errorf("Length = %d, want 16", runs[0].Length)
	}
}

func TestParseDataRunsRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"zero length field", []byte{0x10, 0x00}},
		{"truncated length field", []byte{0x22, 0x01}},
		{"length field wider than int64", append(run([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, []byte{0x10}), 0)},
		{"offset field wider than int64", append(run([]byte{0x10}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}), 0)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseDataRuns(tc.data); err == nil {
				t.Errorf("parseDataRuns(%#v) error = nil, want an error", tc.data)
			}
		})
	}
}

func TestParseDataRunsStopsAtTerminator(t *testing.T) {
	data := append(run([]byte{0x08}, []byte{0x10}), 0x00)
	data = append(data, run([]byte{0x08}, []byte{0x20})...)
	runs, err := parseDataRuns(data)
	if err != nil {
		t.Fatalf("parseDataRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Errorf("got %d runs, want 1 (parsing must stop at the terminator)", len(runs))
	}
}
