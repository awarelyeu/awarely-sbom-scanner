package main

import (
	"os"
	"syscall"
	"unsafe"
)

func stdinTerminal() bool {
	var state syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&state)))
	return err == 0
}
