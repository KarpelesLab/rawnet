package rawnet

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// With raw packet quite often data needs to be prefixed, however that means a
// lot of bytes needs to be copied over and this is generally a bad idea in
// term of performances. We can avoid that by not concatenating data but
// instead pass all the data to be written in an array of buffers.
//
// The code below comes from: https://github.com/google/vectorio

// Writev calls writev() syscall, but first convert a [][]byte to []sycall.Iovec, return number of bytes written and an error
func Writev(f *os.File, in [][]byte) (nw int, err error) {
	iovec := make([]syscall.Iovec, len(in))
	for i, slice := range in {
		iovec[i] = syscall.Iovec{&slice[0], uint64(len(slice))}
	}

	// using f.Fd() makes SetDeadline() not working. Is it something we
	// care about? What does SyscallConn().Write() cost in terms of perfs?
	//nw, err = WritevRaw(uintptr(f.Fd()), iovec)

	c, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	err = c.Write(func(fd uintptr) (done bool) {
		nw, err = WritevRaw(fd, iovec)
		return true
	})

	return
}

// WritevRaw calls writev() syscall like Writev, but expects a slice of syscall.Iovec
func WritevRaw(fd uintptr, iovec []syscall.Iovec) (nw int, err error) {
	nwRaw, _, errno := syscall.Syscall(syscall.SYS_WRITEV, fd, uintptr(unsafe.Pointer(&iovec[0])), uintptr(len(iovec)))
	nw = int(nwRaw)
	if errno != 0 {
		err = fmt.Errorf("writev failed with error: %w", syscall.Errno(errno))
	}
	return
}
