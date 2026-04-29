package utils

import (
	"io"
	"sync/atomic"
	"time"
)

var diskIOLimitBps atomic.Int64

func SetDiskIOLimit(bytesPerSecond int64) {
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}
	diskIOLimitBps.Store(bytesPerSecond)
}

func diskLimitedReader(r io.Reader) io.Reader {
	if diskIOLimitBps.Load() <= 0 {
		return r
	}
	return &limitedReader{reader: r}
}

type limitedReader struct {
	reader io.Reader
}

func (r *limitedReader) Read(p []byte) (int, error) {
	start := time.Now()
	n, err := r.reader.Read(p)
	limit := diskIOLimitBps.Load()
	if n > 0 && limit > 0 {
		expected := time.Duration(int64(time.Second) * int64(n) / limit)
		if remaining := expected - time.Since(start); remaining > 0 {
			time.Sleep(remaining)
		}
	}
	return n, err
}
