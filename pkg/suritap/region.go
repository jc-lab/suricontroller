//go:build linux

package suritap

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Region layout: see tap/suritap/src/region.rs.
const (
	regionHeader = 4096
	minRing      = 64 << 10
	maxRing      = 1 << 30
	ctlC2S       = 1024
	ctlS2C       = 2048
)

var pid = os.Getpid()

type region struct {
	fd       int
	mem      []byte
	c2s, s2c ring
}

func validRing(n int) bool { return n >= minRing && n <= maxRing && n&(n-1) == 0 }

// newRegion creates a sealed memfd with both rings and maps it.
func newRegion(c2sSize, s2cSize int) (*region, error) {
	if !validRing(c2sSize) || !validRing(s2cSize) {
		return nil, fmt.Errorf("suritap: ring sizes must be powers of two in [%d, %d]", minRing, maxRing)
	}
	size := regionHeader + c2sSize + s2cSize
	fd, err := unix.MemfdCreate("suritap", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("suritap: memfd_create: %w", err)
	}
	fail := func(err error) (*region, error) {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		return fail(fmt.Errorf("suritap: ftruncate: %w", err))
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); err != nil {
		return fail(fmt.Errorf("suritap: seal: %w", err))
	}
	mem, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return fail(fmt.Errorf("suritap: mmap: %w", err))
	}
	le := binary.LittleEndian
	le.PutUint32(mem[0:], magic)
	le.PutUint16(mem[4:], 1)
	le.PutUint16(mem[6:], regionHeader)
	le.PutUint64(mem[16:], uint64(size))
	le.PutUint64(mem[24:], regionHeader)
	le.PutUint64(mem[32:], uint64(c2sSize))
	le.PutUint64(mem[40:], uint64(regionHeader+c2sSize))
	le.PutUint64(mem[48:], uint64(s2cSize))
	return &region{
		fd:  fd,
		mem: mem,
		c2s: ring{ctl: mem[ctlC2S : ctlC2S+ctlSize], data: mem[regionHeader : regionHeader+c2sSize], size: uint64(c2sSize)},
		s2c: ring{ctl: mem[ctlS2C : ctlS2C+ctlSize], data: mem[regionHeader+c2sSize : size], size: uint64(s2cSize)},
	}, nil
}

func (r *region) close() {
	if r.mem != nil {
		_ = unix.Munmap(r.mem)
		r.mem = nil
	}
	if r.fd >= 0 {
		unix.Close(r.fd)
		r.fd = -1
	}
}
