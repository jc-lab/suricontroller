//go:build !linux

package engine

import "syscall"

func sysProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

func signalGroup(pid int, sig syscall.Signal) error {
	return syscall.Kill(-pid, sig)
}
