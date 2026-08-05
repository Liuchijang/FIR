package analyzers

import "testing"

// Amcache stores FileId/DriverId as four pad characters followed by the 40-hex-char
// SHA-1. Only the pad may be removed: stripping every leading zero also eats the
// hash's own leading zeros, which silently yields a wrong hash for ~1 entry in 16.
func TestNormalizeAmcacheSHA1(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "padded hash",
			value: "0000B6C0A1D5E4F3928374655647382910AB2C3D",
			want:  "b6c0a1d5e4f3928374655647382910ab2c3d",
		},
		{
			name:  "hash whose first digit is zero keeps it",
			value: "00000A1B2C3D4E5F60718293A4B5C6D7E8F90123",
			want:  "0a1b2c3d4e5f60718293a4b5c6d7e8f90123",
		},
		{
			name:  "hash with several leading zeros keeps them all",
			value: "0000000A1B2C3D4E5F60718293A4B5C6D7E8F901",
			want:  "000a1b2c3d4e5f60718293a4b5c6d7e8f901",
		},
		{
			name:  "already unpadded hash is left alone",
			value: "b6c0a1d5e4f3928374655647382910ab2c3d4e5f",
			want:  "b6c0a1d5e4f3928374655647382910ab2c3d4e5f",
		},
		{
			name:  "surrounding whitespace trimmed",
			value: "  0000B6C0A1D5E4F3928374655647382910AB2C3D  ",
			want:  "b6c0a1d5e4f3928374655647382910ab2c3d",
		},
		{name: "empty", value: "", want: ""},
		{name: "all zeros", value: "0000000000000000000000000000000000000000", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeAmcacheSHA1(tc.value); got != tc.want {
				t.Errorf("normalizeAmcacheSHA1(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}
