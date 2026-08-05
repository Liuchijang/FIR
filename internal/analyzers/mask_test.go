package analyzers

import "testing"

func TestMaskString(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"no bits set", usnReasonString(0), ""},
		{"single bit", usnReasonString(0x00000001), "DATA_OVERWRITE"},
		{"high bit", usnReasonString(0x80000000), "CLOSE"},
		{"multiple bits keep table order", usnReasonString(0x00000200 | 0x00000001), "DATA_OVERWRITE|FILE_DELETE"},
		{"unknown bits ignored", usnReasonString(0x00000008), ""},
		{"file attributes empty", fileAttributesString(0), ""},
		{"source info empty", usnSourceInfoString(0), ""},
		{"uint16 table", securityDescriptorControlString(0), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("got %q, want %q", tc.got, tc.want)
			}
		})
	}
}
