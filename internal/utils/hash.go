package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashFile reads the whole file, so it is the wrong tool for an artifact this
// process just wrote — hash those on the way out instead. What is left is the
// memory image, whose bytes winpmem writes from a child process we never see.
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
