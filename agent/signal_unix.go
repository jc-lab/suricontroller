package agent

import "syscall"

// sighup asks Suricata to reopen its log files.
var sighup = syscall.SIGHUP
