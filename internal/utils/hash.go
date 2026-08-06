package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashFile reads the whole file. Collectors that hash a freshly written
// artifact (the $MFT, the memory dump) move those bytes a second time here.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for hashing: %w", err)
	}
	defer f.Close()

	return HashReader(f)
}

func HashReader(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hash computation: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
