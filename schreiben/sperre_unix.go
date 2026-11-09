//go:build !windows

package schreiben

import (
	"os"
	"syscall"
)

func dateiSperren(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func dateiEntsperren(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
