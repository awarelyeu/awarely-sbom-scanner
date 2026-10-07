package main

import (
	"os"
	"syscall"
	"unsafe"
)

func stdinTerminal() bool { return fileTerminal(os.Stdin) }

func fileTerminal(file *os.File) bool {
	var state syscall.Termios
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), syscall.TIOCGETA, uintptr(unsafe.Pointer(&state)))
	return err == 0
}
