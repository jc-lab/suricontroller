package engine

import "syscall"

// sysProcAttr puts Suricata in its own process group and kills it if the
// agent dies.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}

func signalGroup(pid int, sig syscall.Signal) error {
	return syscall.Kill(-pid, sig)
}
